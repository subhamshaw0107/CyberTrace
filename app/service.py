"""
app/service.py
================

Application layer shared by the CLI (ps26237.py) and the web UI (app/web.py).

A *workspace* directory holds everything for one deployment:
    config.json              {"ledger": "sim" | "fabric"}
    identities/<id>.json     public keys + passphrase-encrypted secret keys
    ledger_sim.pkl           the simulated ledger (only for ledger = "sim")

Secret keys at rest are encrypted with AES-256-GCM under a key derived from
the recipient's passphrase with scrypt (N=2^15, r=8, p=1). This is software
protection for a prototype; see docs/DEPLOYMENT.md for hardware-token/HSM
guidance.

Security rule enforced here: a decrypted, watermarked document is released
ONLY after its signed decryption record has been committed to the ledger.
If the commit fails, decryption output is discarded and an error is raised.
"""

from __future__ import annotations
import base64
import json
import os
import pickle
import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from crypto.pqc import MLKEM, MLDSA, DSAKeyPair, BACKEND
from crypto.document_crypto import EncryptedPackage, encrypt_for_recipients
from crypto.decryption_session import perform_decryption_session
from watermark.document_formats import detect_format, embed_document, extract_candidates, EXTENSIONS, UnsupportedFormat
from forensics.trace_leak import attribute_watermark, AttributionReport

PACKAGE_FORMAT = "ps26237-package-v1"
NODE_IDS = ["sender-org-node", "independent-auditor-node", "security-dept-node", "offsite-backup-node"]
ID_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$")


class ServiceError(Exception):
    pass


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _unb64(s: str) -> bytes:
    return base64.b64decode(s)


def _kdf(passphrase: str, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=32, n=2 ** 15, r=8, p=1).derive(passphrase.encode())


@dataclass
class DecryptOutcome:
    filename: str
    data: bytes
    format: str
    record: dict
    committed_on: list
    ledger_ref: str


@dataclass
class TraceOutcome:
    report: AttributionReport
    source: str                        # "image" or "page N"
    candidates_tried: list = field(default_factory=list)

    @property
    def confirmed(self) -> bool:
        return self.report.final_verdict.startswith("CONFIRMED")

    def to_dict(self) -> dict:
        r = self.report
        lk = r.ledger_lookup
        return {
            "verdict": r.final_verdict,
            "confirmed": self.confirmed,
            "source": self.source,
            "extracted_watermark_id": r.watermark_extracted_hex,
            "extraction": r.extraction,
            "match_distance_bits": r.match_distance_bits,
            "ledger": {"found": lk.found, "verified": lk.verified, "quorum_achieved": lk.quorum_achieved,
                       "quorum_needed": lk.quorum_needed, "agreeing_nodes": lk.node_ids_matched},
            "signature_valid": r.signature_valid,
            "record": {k: v for k, v in (lk.record or {}).items() if not k.startswith("_")},
            "candidates_tried": self.candidates_tried,
        }


def resolve_workspace_dir(preferred: str | None = None) -> str:
    """Resolves workspace directory with automatic fallback to /tmp for serverless/read-only hosts."""
    if preferred:
        return preferred
    env_home = os.environ.get("PS26237_HOME")
    if env_home:
        return env_home
    is_serverless = bool(os.environ.get("VERCEL") or os.environ.get("NETLIFY") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME") or os.environ.get("LAMBDA_TASK_ROOT") or os.environ.get("RENDER") or os.environ.get("PORT"))
    if is_serverless:
        return "/tmp/ps26237_workspace"
    return "ps26237_workspace"


class Workspace:
    _lock = threading.RLock()

    def __init__(self, root: str | os.PathLike | None = None, ledger: str | None = None):
        target = resolve_workspace_dir(str(root) if root else None)
        try:
            self.root = Path(target)
            self.root.mkdir(parents=True, exist_ok=True)
            (self.root / "identities").mkdir(exist_ok=True)
        except OSError:
            self.root = Path("/tmp/ps26237_workspace")
            self.root.mkdir(parents=True, exist_ok=True)
            (self.root / "identities").mkdir(exist_ok=True)

        cfg_path = self.root / "config.json"
        cfg = json.loads(cfg_path.read_text()) if cfg_path.exists() else {"ledger": "sim"}
        if ledger:
            cfg["ledger"] = ledger
        if cfg["ledger"] not in ("sim", "fabric"):
            raise ServiceError("ledger must be 'sim' or 'fabric'")
        cfg_path.write_text(json.dumps(cfg, indent=1))
        self.config = cfg
        self._ledger = None

    def seed_demo_identities_if_empty(self) -> list[str]:
        """Seeds alice, bob, carol with passphrase 'password123' if no identities exist."""
        import hashlib
        with self._lock:
            existing = self.list_identities()
            if existing:
                return []
            demo_map = {
                "alice": ("Alice (Sender)", "sender@cybertrace.local", "Sender"),
                "bob": ("Bob (Receiver)", "receiver@cybertrace.local", "Receiver"),
                "carol": ("Carol (Receiver)", "carol@cybertrace.local", "Receiver"),
            }
            for name, (disp_name, email, role) in demo_map.items():
                try:
                    seed = hashlib.sha256(f"ps26237-demo-seed-v1-{name}".encode()).digest()
                    self.create_identity(name, "password123", seed=seed, name=disp_name, email=email, role=role)
                    created.append(name)
                except Exception:
                    pass
            return created

    # ------------------------------------------------------------------ ledger
    @property
    def ledger_backend(self) -> str:
        return self.config["ledger"]

    def ledger(self):
        if self._ledger is None:
            if self.ledger_backend == "fabric":
                from ledger.fabric_ledger import FabricLedgerNetwork
                self._ledger = FabricLedgerNetwork()
            else:
                from ledger.ledger_network import LedgerNetwork
                p = self.root / "ledger_sim.pkl"
                self._ledger = pickle.loads(p.read_bytes()) if p.exists() else LedgerNetwork(NODE_IDS, quorum=3)
        return self._ledger

    def _save_ledger(self):
        if self.ledger_backend == "sim" and self._ledger is not None:
            tmp = self.root / "ledger_sim.pkl.tmp"
            tmp.write_bytes(pickle.dumps(self._ledger))
            tmp.replace(self.root / "ledger_sim.pkl")

    def ledger_status(self) -> dict:
        with self._lock:
            led = self.ledger()
            integ = led.verify_network_integrity()
            return {"backend": self.ledger_backend, "nodes": list(led.nodes), "quorum": led.quorum,
                    "records": len(led.all_watermark_ids()), "integrity": integ}

    def get_ledger_events(self) -> dict:
        """
        Read-only extraction and verification of all ledger blocks.
        Never exposes private keys, passphrases, or secret credentials.
        Returns real summary statistics, event records, and network integrity.
        """
        import time
        with self._lock:
            led = self.ledger()
            backend = self.ledger_backend
            integ = led.verify_network_integrity()
            events = []

            # Check if using the multi-node LedgerNetwork simulation
            if hasattr(led, "nodes") and isinstance(led.nodes, dict) and len(led.nodes) > 0 and hasattr(list(led.nodes.values())[0], "chain"):
                ref_node = list(led.nodes.values())[0]
                total_nodes = len(led.nodes)
                quorum_needed = led.quorum

                for i, block in enumerate(ref_node.chain):
                    is_genesis = (i == 0 or block.record.get("type") == "GENESIS")
                    rec = block.record or {}

                    # Count cross-node consensus
                    agreeing_nodes = []
                    for nid, n in led.nodes.items():
                        if i < len(n.chain):
                            if is_genesis and n.chain[0].record.get("type") == "GENESIS":
                                agreeing_nodes.append(nid)
                            elif not is_genesis and n.chain[i].record.get("watermark_id") == rec.get("watermark_id"):
                                agreeing_nodes.append(nid)

                    quorum_achieved = len(agreeing_nodes)
                    quorum_ok = (quorum_achieved >= quorum_needed)

                    # Chain integrity verification
                    hash_ok = (block.compute_hash() == block.block_hash)
                    prev_ok = True if i == 0 else (block.prev_hash == ref_node.chain[i - 1].block_hash)
                    chain_integrity = "VALID" if (hash_ok and prev_ok) else "TAMPERED"

                    # Verify recipient ML-DSA-65 signature on the record
                    sig_status = "N/A"
                    if not is_genesis:
                        sig_hex = rec.get("_signature_hex")
                        pk_hex = rec.get("_signer_public_key_hex")
                        if sig_hex and pk_hex:
                            try:
                                from crypto.pqc import MLDSA
                                from crypto.decryption_session import DecryptionRecord
                                canon = DecryptionRecord(
                                    watermark_id=rec["watermark_id"],
                                    recipient_id=rec["recipient_id"],
                                    document_id=rec["document_id"],
                                    session_id=rec["session_id"],
                                    document_hash=rec["document_hash"],
                                    unix_timestamp=rec["unix_timestamp"],
                                    human_timestamp=rec["human_timestamp"],
                                ).canonical_bytes()
                                is_sig_valid = MLDSA.verify(canon, bytes.fromhex(sig_hex), bytes.fromhex(pk_hex))
                                sig_status = "VALID" if is_sig_valid else "INVALID"
                            except Exception:
                                sig_status = "INVALID"
                    else:
                        sig_status = "VALID"

                    event_type = "GENESIS" if is_genesis else rec.get("type", "DECRYPTION_PROVENANCE")
                    doc_id = "-" if is_genesis else rec.get("document_id", "-")
                    actor = "SYSTEM" if is_genesis else rec.get("recipient_id", "-")
                    
                    # Compute precise real local and UTC timestamps
                    ts = float(rec.get("unix_timestamp") or block.timestamp or time.time())
                    local_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
                    utc_time = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(ts))
                    next_hash = ref_node.chain[i + 1].block_hash if (i + 1 < len(ref_node.chain)) else None

                    events.append({
                        "event_id": f"EVT-{i:04d}",
                        "index": block.index,
                        "event_type": event_type,
                        "document_id": doc_id,
                        "actor": actor,
                        "recipient_id": actor,
                        "timestamp": ts,
                        "local_timestamp": local_time,
                        "utc_timestamp": utc_time,
                        "human_timestamp": local_time,
                        "watermark_id": rec.get("watermark_id", "-") if not is_genesis else "-",
                        "session_id": rec.get("session_id", "-") if not is_genesis else "-",
                        "document_hash": rec.get("document_hash", "-") if not is_genesis else "-",
                        "block_hash": block.block_hash,
                        "prev_hash": block.prev_hash,
                        "next_hash": next_hash,
                        "node_id": block.node_id,
                        "status": "COMMITTED" if quorum_ok else "UNCONFIRMED",
                        "signature_status": sig_status,
                        "signature_algorithm": "ML-DSA-65 (NIST FIPS 204)" if not is_genesis else "Node ML-DSA Key",
                        "integrity_status": chain_integrity,
                        "quorum_achieved": quorum_achieved,
                        "quorum_needed": quorum_needed,
                        "agreeing_nodes": agreeing_nodes,
                        "total_nodes": total_nodes,
                        "signer_public_key_hex": rec.get("_signer_public_key_hex", "") if not is_genesis else "",
                        "signature_hex": rec.get("_signature_hex", "") if not is_genesis else block.node_signature,
                    })
            else:
                # Fabric network backend
                wm_ids = led.all_watermark_ids() if hasattr(led, "all_watermark_ids") else []
                total_nodes = len(getattr(led, "nodes", {})) or 4
                quorum_needed = getattr(led, "quorum", 3)
                for idx, wm in enumerate(wm_ids, 1):
                    res = led.lookup_by_watermark(wm)
                    rec = res.record or {}
                    sig_status = "VALID" if res.verified else ("INVALID" if res.found else "UNKNOWN")
                    ts = float(rec.get("unix_timestamp") or time.time())
                    local_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
                    utc_time = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(ts))

                    events.append({
                        "event_id": f"EVT-{idx:04d}",
                        "index": idx,
                        "event_type": "DECRYPTION_PROVENANCE",
                        "document_id": rec.get("document_id", "-"),
                        "actor": rec.get("recipient_id", "-"),
                        "recipient_id": rec.get("recipient_id", "-"),
                        "timestamp": ts,
                        "local_timestamp": local_time,
                        "utc_timestamp": utc_time,
                        "human_timestamp": local_time,
                        "watermark_id": wm,
                        "session_id": rec.get("session_id", "-"),
                        "document_hash": rec.get("document_hash", "-"),
                        "block_hash": wm,
                        "prev_hash": "-",
                        "next_hash": None,
                        "node_id": "fabric-network",
                        "status": "COMMITTED" if res.quorum_achieved >= quorum_needed else "UNCONFIRMED",
                        "signature_status": sig_status,
                        "signature_algorithm": "ML-DSA-65 (NIST FIPS 204)",
                        "integrity_status": "VALID" if res.verified else "UNVERIFIED",
                        "quorum_achieved": res.quorum_achieved,
                        "quorum_needed": quorum_needed,
                        "agreeing_nodes": res.node_ids_matched,
                        "total_nodes": total_nodes,
                        "signer_public_key_hex": rec.get("_signer_public_key_hex", ""),
                        "signature_hex": rec.get("_signature_hex", ""),
                    })

            # Real overview metrics
            non_genesis = [e for e in events if e["event_type"] != "GENESIS"]
            doc_set = set(e["document_id"] for e in non_genesis if e["document_id"] != "-")
            rec_set = set(e["recipient_id"] for e in non_genesis if e["recipient_id"] != "-")
            wm_set = set(e["watermark_id"] for e in non_genesis if e["watermark_id"] != "-")
            committed_count = sum(1 for e in events if e["status"] == "COMMITTED")

            stats = {
                "total_records": len(events),
                "total_provenance_records": len(non_genesis),
                "unique_documents": len(doc_set),
                "unique_recipients": len(rec_set),
                "decryption_events": len(non_genesis),
                "watermark_events": len(wm_set),
                "committed_events": committed_count,
                "backend": backend,
                "quorum_needed": getattr(led, "quorum", 3),
                "total_nodes": len(getattr(led, "nodes", {})),
                "network_consistent": integ.get("network_consistent", True),
                "tampered_nodes": integ.get("tampered_nodes", []),
            }

            return {
                "stats": stats,
                "events": events,
                "integrity": integ,
            }

    def get_document_timeline(self, document_id: str, matched_watermark_id: str | None = None, forensic_summary: dict | None = None) -> dict:
        """
        Feature #21: Incident Timeline for Forensics Page.
        Retrieves real chronological events for a specific document_id.
        Never fabricates fake events or modifies the ledger.
        """
        if not document_id or document_id.strip() == "-" or not document_id.strip():
            return {
                "document_id": document_id or "",
                "total_events": 0,
                "events": [],
                "incident_point": None,
                "matched_watermark_id": matched_watermark_id,
            }

        doc_id = document_id.strip()
        all_data = self.get_ledger_events()
        raw_events = all_data.get("events", [])

        # Filter strictly by document_id (ignoring genesis "-")
        filtered = [
            dict(ev) for ev in raw_events 
            if ev.get("document_id") and ev.get("document_id") == doc_id
        ]

        # Sort chronologically by actual timestamp (oldest first)
        filtered.sort(key=lambda x: float(x.get("timestamp") or 0))

        incident_event = None
        cleaned_events = []

        norm_matched_wm = (matched_watermark_id or "").strip().lower()

        for ev in filtered:
            ev_copy = dict(ev)
            actor = ev_copy.get("actor") or ev_copy.get("recipient_id") or "UNKNOWN"
            ev_copy["recipient"] = actor
            ev_copy["actor"] = actor

            # Check if this event corresponds to the watermark identified in the leak
            wm = (ev_copy.get("watermark_id") or "").strip().lower()
            if norm_matched_wm and wm and wm != "-" and (wm == norm_matched_wm):
                ev_copy["is_incident_point"] = True
                incident_event = ev_copy
            else:
                ev_copy["is_incident_point"] = False

            # Expose only safe fields (never private keys, passphrases, AES keys, tokens)
            safe_event = {
                "event_id": ev_copy.get("event_id"),
                "index": ev_copy.get("index"),
                "event_type": ev_copy.get("event_type", "DECRYPTION_PROVENANCE"),
                "document_id": ev_copy.get("document_id"),
                "recipient": ev_copy.get("recipient"),
                "actor": ev_copy.get("actor"),
                "timestamp": ev_copy.get("timestamp"),
                "local_timestamp": ev_copy.get("local_timestamp"),
                "utc_timestamp": ev_copy.get("utc_timestamp"),
                "human_timestamp": ev_copy.get("human_timestamp"),
                "watermark_id": ev_copy.get("watermark_id"),
                "session_id": ev_copy.get("session_id"),
                "document_hash": ev_copy.get("document_hash"),
                "block_hash": ev_copy.get("block_hash"),
                "prev_hash": ev_copy.get("prev_hash"),
                "status": ev_copy.get("status", "COMMITTED"),
                "signature_status": ev_copy.get("signature_status", "VALID"),
                "signature_algorithm": ev_copy.get("signature_algorithm", "ML-DSA-65 (NIST FIPS 204)"),
                "integrity_status": ev_copy.get("integrity_status", "VALID"),
                "quorum_achieved": ev_copy.get("quorum_achieved"),
                "quorum_needed": ev_copy.get("quorum_needed"),
                "agreeing_nodes": ev_copy.get("agreeing_nodes", []),
                "total_nodes": ev_copy.get("total_nodes", 4),
                "is_incident_point": ev_copy.get("is_incident_point", False),
            }
            cleaned_events.append(safe_event)

        # If forensic_summary is provided (e.g. from /trace after analyzing the leaked file),
        # include the forensic analysis event at the end of the timeline
        if forensic_summary:
            f_ts = float(forensic_summary.get("timestamp") or time.time())
            local_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(f_ts))
            utc_time = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(f_ts))
            prev_h = cleaned_events[-1]["block_hash"] if cleaned_events else "-"
            f_evt = {
                "event_id": f"EVT-TRACE-{int(f_ts)}",
                "index": len(cleaned_events) + 1,
                "event_type": "FORENSIC_ANALYSIS",
                "document_id": doc_id,
                "recipient": forensic_summary.get("attributed_recipient", "-"),
                "actor": "Forensics Engine",
                "timestamp": f_ts,
                "local_timestamp": local_time,
                "utc_timestamp": utc_time,
                "human_timestamp": local_time,
                "watermark_id": forensic_summary.get("watermark_id", "-"),
                "session_id": "-",
                "document_hash": forensic_summary.get("document_hash", "-"),
                "block_hash": "-",
                "prev_hash": prev_h,
                "status": "COMPLETED",
                "signature_status": "VALID" if forensic_summary.get("signature_valid") else ("INVALID" if forensic_summary.get("signature_valid") is False else "N/A"),
                "signature_algorithm": "ML-DSA-65 (NIST FIPS 204)",
                "integrity_status": "VALID",
                "quorum_achieved": forensic_summary.get("quorum_achieved", 4),
                "quorum_needed": forensic_summary.get("quorum_needed", 3),
                "agreeing_nodes": forensic_summary.get("agreeing_nodes", []),
                "total_nodes": 4,
                "is_incident_point": False,
                "verdict": forensic_summary.get("verdict", ""),
                "confirmed": forensic_summary.get("confirmed", False),
                "confidence": forensic_summary.get("confidence", 1.0),
            }
            cleaned_events.append(f_evt)

        return {
            "document_id": doc_id,
            "total_events": len(cleaned_events),
            "events": cleaned_events,
            "incident_point": incident_event,
            "matched_watermark_id": matched_watermark_id,
        }

    # -------------------------------------------------------------- identities
    def _identity_path(self, rid: str) -> Path:
        if not ID_RE.match(rid):
            raise ServiceError(f"invalid identity '{rid}' (letters, digits, . _ -)")
        return self.root / "identities" / f"{rid}.json"

    def create_identity(self, rid: str, passphrase: str, seed: bytes | None = None, name: str | None = None, email: str | None = None, role: str | None = None) -> dict:
        path = self._identity_path(rid)
        if path.exists():
            raise ServiceError(f"identity '{rid}' already exists")
        for actual_id in self.list_identities():
            if actual_id.lower() == rid.lower():
                raise ServiceError(f"identity '{rid}' already exists")
        if len(passphrase) < 8:
            raise ServiceError("passphrase must be at least 8 characters")

        target_email = (email or f"{rid}@cybertrace.local").strip().lower()
        existing_with_email = self.get_identity_by_email(target_email)
        if existing_with_email and existing_with_email.get("id", "").lower() != rid.lower():
            raise ServiceError(f"email '{target_email}' is already registered to identity '{existing_with_email.get('id')}'")
        kem, dsa = MLKEM.keygen(seed=seed), MLDSA.keygen(seed=seed)
        if seed:
            import hashlib
            salt = hashlib.sha256(b"salt:" + rid.encode()).digest()[:16]
            nonce = hashlib.sha256(b"nonce:" + rid.encode()).digest()[:12]
        else:
            salt, nonce = os.urandom(16), os.urandom(12)
        secret = json.dumps({"kem_secret_key": _b64(kem.secret_key), "dsa_secret_key": _b64(dsa.secret_key)}).encode()
        ct = AESGCM(_kdf(passphrase, salt)).encrypt(nonce, secret, rid.encode())
        ident = {
            "id": rid,
            "name": name or rid.capitalize(),
            "email": (email or f"{rid}@cybertrace.local").strip().lower(),
            "role": role or "Receiver",
            "algorithms": {"kem": MLKEM.algorithm, "signature": MLDSA.algorithm, "backend": BACKEND},
            "kem_public_key": _b64(kem.public_key),
            "dsa_public_key": _b64(dsa.public_key),
            "secret_keys": {"kdf": "scrypt-n32768-r8-p1", "cipher": "AES-256-GCM",
                            "salt": _b64(salt), "nonce": _b64(nonce), "ciphertext": _b64(ct)},
        }
        with self._lock:
            if self.ledger_backend == "fabric":
                self.ledger().register_recipient_key(rid, dsa.public_key)
            path.write_text(json.dumps(ident, indent=1))
        return self.public_identity(rid)

    def _load_identity(self, rid: str) -> dict:
        path = self._identity_path(rid)
        if not path.exists():
            for actual_id in self.list_identities():
                if actual_id.lower() == rid.lower():
                    return json.loads(self._identity_path(actual_id).read_text())
            raise ServiceError(f"unknown identity '{rid}'")
        return json.loads(path.read_text())

    def get_identity(self, rid: str) -> dict | None:
        try:
            return self._load_identity(rid)
        except Exception:
            return None

    def get_identity_by_email(self, email: str) -> dict | None:
        email_clean = (email or "").strip().lower()
        if not email_clean:
            return None
        for rid in self.list_identities():
            ident = self.get_identity(rid)
            if ident and ident.get("email", "").strip().lower() == email_clean:
                return ident
        return None

    def public_identity(self, rid: str) -> dict:
        i = self._load_identity(rid)
        return {"id": i["id"], "name": i.get("name", i["id"]), "email": i.get("email", f"{i['id']}@cybertrace.local"),
                "role": i.get("role", "Receiver"), "algorithms": i["algorithms"],
                "kem_public_key_bytes": len(_unb64(i["kem_public_key"])),
                "dsa_public_key_bytes": len(_unb64(i["dsa_public_key"]))}

    def list_identities(self) -> list[str]:
        return sorted(p.stem for p in (self.root / "identities").glob("*.json"))

    def _unlock(self, rid: str, passphrase: str) -> tuple[bytes, DSAKeyPair]:
        i = self._load_identity(rid)
        s = i["secret_keys"]
        try:
            secret = AESGCM(_kdf(passphrase, _unb64(s["salt"]))).decrypt(_unb64(s["nonce"]), _unb64(s["ciphertext"]), rid.encode())
        except Exception:
            raise ServiceError("wrong passphrase") from None
        sk = json.loads(secret)
        return _unb64(sk["kem_secret_key"]), DSAKeyPair(public_key=_unb64(i["dsa_public_key"]),
                                                         secret_key=_unb64(sk["dsa_secret_key"]))

    def signing_directory(self) -> dict:
        return {rid: _unb64(self._load_identity(rid)["dsa_public_key"]) for rid in self.list_identities()}

    # ---------------------------------------------------------------- sender
    def encrypt(self, data: bytes, filename: str, recipients: list[str], document_id: str | None = None) -> bytes:
        detect_format(data)  # reject unsupported formats before distribution
        if not recipients:
            raise ServiceError("at least one recipient required")
        keys = {r: _unb64(self._load_identity(r)["kem_public_key"]) for r in recipients}
        document_id = document_id or f"DOC-{uuid.uuid4().hex[:12].upper()}"
        pkg = encrypt_for_recipients(document_id, data, keys)
        return json.dumps({"format": PACKAGE_FORMAT, "filename": os.path.basename(filename),
                           "crypto_backend": BACKEND,
                           "package": json.loads(pkg.to_json())}).encode()

    @staticmethod
    def package_info(package_bytes: bytes) -> dict:
        outer = json.loads(package_bytes)
        if outer.get("format") != PACKAGE_FORMAT:
            raise ServiceError("not a PS26237 package")
        p = outer["package"]
        return {"document_id": p["document_id"], "filename": outer["filename"], "recipients": sorted(p["key_wraps"]),
                "ciphertext_bytes": len(_unb64(p["ciphertext"]))}

    # ------------------------------------------------------------- recipient
    def decrypt(self, package_bytes: bytes, rid: str, passphrase: str) -> DecryptOutcome:
        try:
            outer = json.loads(package_bytes)
        except ValueError:
            raise ServiceError("not a PS26237 package") from None
        if outer.get("format") != PACKAGE_FORMAT:
            raise ServiceError("not a PS26237 package")
        pkg_backend = outer.get("crypto_backend")
        if pkg_backend and pkg_backend != BACKEND:
            raise ServiceError(
                f"Cryptographic backend mismatch: this package was encrypted using '{pkg_backend}', "
                f"but this server is running '{BACKEND}'. Please encrypt and decrypt within the same environment."
            )
        pkg = EncryptedPackage.from_json(json.dumps(outer["package"]))
        kem_sk, dsa_kp = self._unlock(rid, passphrase)
        try:
            session = perform_decryption_session(pkg, rid, kem_sk, dsa_kp, raw_image_array=None)
        except PermissionError as e:
            raise ServiceError(str(e)) from None
        except Exception as ex:
            raise ServiceError(f"decryption failed: {ex} (wrong key or corrupted package)") from None

        watermarked, fmt = embed_document(session.plaintext_bytes, bytes.fromhex(session.record.watermark_id))

        record = session.record.to_dict()
        record["_signature_hex"] = session.signature_hex
        record["_signer_public_key_hex"] = session.signer_public_key_hex
        with self._lock:
            commit = self.ledger().commit_record(record)
            if not commit.committed:
                raise ServiceError("ledger commit failed -- document NOT released")
            self._save_ledger()

        stem = os.path.splitext(outer["filename"])[0]
        return DecryptOutcome(
            filename=f"{stem}.{rid}{EXTENSIONS[fmt]}", data=watermarked, format=fmt,
            record={k: v for k, v in record.items() if not k.startswith("_")},
            committed_on=commit.node_ids_committed, ledger_ref=commit.block_hash,
        )

    # ------------------------------------------------------------- forensics
    def trace(self, leaked: bytes) -> TraceOutcome:
        candidates = extract_candidates(leaked)
        with self._lock:
            led = self.ledger()
            directory = self.signing_directory()
            tried, first = [], None
            for c in candidates:
                rep = attribute_watermark(c.watermark_id, led, directory,
                                          {"confidence": c.confidence, **c.info})
                tried.append({"source": c.source, "watermark_id": c.watermark_id.hex(),
                              "confidence": round(c.confidence, 3), "verdict": rep.final_verdict.split(" --")[0]})
                outcome = TraceOutcome(rep, c.source, tried)
                if outcome.confirmed:
                    return outcome
                first = first or outcome
            return first
