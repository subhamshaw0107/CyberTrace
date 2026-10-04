"""
ledger/fabric_ledger.py
=========================

Client for the real Hyperledger Fabric provenance network in ledger/fabric/
(1 orderer + 4 organisation peers in separate containers, 3-of-4
endorsement policy). Same public interface as LedgerNetwork
(commit_record / lookup_by_watermark / verify_network_integrity), so
forensics/trace_leak.py works with either.

Talks to Fabric through the `peer` CLI inside the ps26237-cli container
(`docker exec`). Start the network first: `bash ledger/fabric/network.sh up`.

What is enforced by Fabric itself, not by this client:
  - every endorsing peer's chaincode verifies the recipient's ML-DSA-65
    signature and the write-once registered key before endorsing;
  - a write is only valid if 3 of the 4 organisations endorsed it;
  - records can never be overwritten or deleted by the chaincode.

What this client adds on top, for reads: it queries every organisation's
peer separately and only trusts a record that 3 of 4 return identically,
so one compromised peer that lies about a record is detected and outvoted.
"""

from __future__ import annotations
import base64
import json
import re
import subprocess
from dataclasses import dataclass

from crypto.pqc import MLDSA
from crypto.decryption_session import DecryptionRecord
from ledger.forensics_result import ForensicLookupResult
from ledger.ledger_network import CommitResult

CLI_CONTAINER = "ps26237-cli"

# Fabric org -> node name used elsewhere in the project
ORG_NODES = {
    "sender": "sender-org-node",
    "auditor": "independent-auditor-node",
    "security": "security-dept-node",
    "backup": "offsite-backup-node",
}


class FabricError(RuntimeError):
    pass


@dataclass
class InvokeResult:
    ok: bool
    tx_id: str
    valid_at_peers: list
    output: str


def _cli(args: list[str], ctor: dict | None = None, timeout: int = 120) -> subprocess.CompletedProcess:
    cmd = ["docker", "exec", "-i", CLI_CONTAINER, "bash", "/work/scripts/cli.sh", *args]
    return subprocess.run(cmd, input=json.dumps(ctor) if ctor else "", capture_output=True,
                          text=True, encoding="utf-8", timeout=timeout)


def _record_from_dict(d: dict) -> DecryptionRecord:
    return DecryptionRecord(
        watermark_id=d["watermark_id"], recipient_id=d["recipient_id"], document_id=d["document_id"],
        session_id=d["session_id"], document_hash=d["document_hash"],
        unix_timestamp=d["unix_timestamp"], human_timestamp=d["human_timestamp"],
    )


class FabricLedgerNetwork:
    def __init__(self, orgs: list[str] | None = None, quorum: int = 3):
        self.orgs = orgs or list(ORG_NODES)
        self.quorum = quorum
        self.nodes = {ORG_NODES[o]: o for o in self.orgs}  # node name -> org (len() used by callers)
        if not self.is_running():
            raise FabricError("Fabric network not running. Start it with: bash ledger/fabric/network.sh up")

    @staticmethod
    def is_running() -> bool:
        try:
            r = subprocess.run(["docker", "inspect", "-f", "{{.State.Running}}", CLI_CONTAINER],
                               capture_output=True, text=True, timeout=20)
            return r.stdout.strip() == "true"
        except (OSError, subprocess.TimeoutExpired):
            return False

    # ---- writes -----------------------------------------------------------

    def invoke(self, fn: str, args: list[str], submitter: str = "sender", endorsers: list[str] | None = None) -> InvokeResult:
        endorsers = endorsers or self.orgs
        r = _cli(["invoke", submitter, ",".join(endorsers)], {"Args": [fn, *args]})
        out = r.stdout + r.stderr
        m = re.search(r"txid \[([0-9a-f]+)\]", out)
        valid = re.findall(r"committed with status \(VALID\) at peer0\.(\w+)\.", out)
        return InvokeResult(ok=(r.returncode == 0 and bool(valid)), tx_id=m.group(1) if m else "",
                            valid_at_peers=valid, output=out)

    def register_recipient_key(self, recipient_id: str, public_key: bytes) -> InvokeResult:
        res = self.invoke("RegisterRecipientKey", [recipient_id, public_key.hex()])
        if not res.ok:
            raise FabricError(f"key registration failed for {recipient_id}:\n{res.output[-2000:]}")
        return res

    def commit_record(self, record: dict) -> CommitResult:
        """record = DecryptionRecord.to_dict() + _signature_hex + _signer_public_key_hex."""
        canonical = _record_from_dict(record).canonical_bytes()
        res = self.invoke("CommitRecord", [json.dumps(record), base64.b64encode(canonical).decode()])
        return CommitResult(
            committed=res.ok,
            quorum_needed=self.quorum,
            quorum_achieved=len(res.valid_at_peers),
            block_index=-1,              # Fabric block numbers aren't exposed by the peer CLI invoke output
            block_hash=res.tx_id,        # Fabric transaction ID
            node_ids_committed=[ORG_NODES[o] for o in res.valid_at_peers],
        )

    # ---- reads ------------------------------------------------------------

    def query_peer(self, org: str, fn: str, args: list[str]) -> str | None:
        r = _cli(["query", org], {"Args": [fn, *args]})
        if r.returncode != 0:
            return None
        return r.stdout.strip()

    def lookup_by_watermark(self, watermark_id_hex: str) -> ForensicLookupResult:
        stored: dict[str, dict] = {}
        for org in self.orgs:
            raw = self.query_peer(org, "GetByWatermark", [watermark_id_hex])
            if raw:
                stored[org] = json.loads(raw)

        if not stored:
            return ForensicLookupResult(found=False, verified=False, quorum_needed=self.quorum,
                                        quorum_achieved=0, record=None, signature_checks={}, node_ids_matched=[])

        groups: dict[str, list[str]] = {}
        for org, st in stored.items():
            groups.setdefault(json.dumps(st["record"], sort_keys=True), []).append(org)
        best = max(groups, key=lambda k: len(groups[k]))
        agreeing = groups[best]
        record = json.loads(best)

        # Independently re-verify, per agreeing peer, the recipient's ML-DSA-65
        # signature over the canonical bytes that peer stored.
        sig_checks = {}
        for org in agreeing:
            st = stored[org]
            canonical = base64.b64decode(st["canonical_b64"])
            sig_checks[ORG_NODES[org]] = (
                canonical == _record_from_dict(st["record"]).canonical_bytes()
                and MLDSA.verify(canonical, bytes.fromhex(st["record"]["_signature_hex"]),
                                 bytes.fromhex(st["record"]["_signer_public_key_hex"]))
            )

        return ForensicLookupResult(
            found=True,
            verified=len(agreeing) >= self.quorum and all(sig_checks.values()),
            quorum_needed=self.quorum,
            quorum_achieved=len(agreeing),
            record=record,
            signature_checks=sig_checks,
            node_ids_matched=[ORG_NODES[o] for o in agreeing],
        )

    def all_watermark_ids(self) -> list[str]:
        ids = set()
        for org in self.orgs:
            raw = self.query_peer(org, "ListWatermarks", [])
            if raw:
                ids.update(json.loads(raw))
        return sorted(ids)

    def history_count(self, org: str, watermark_id_hex: str) -> int:
        raw = self.query_peer(org, "GetHistoryCount", [watermark_id_hex])
        return int(raw) if raw else -1

    def verify_network_integrity(self) -> dict:
        """Compares every record as reported by each organisation's peer.
        A peer disagreeing with the 3-of-4 majority on any record is flagged."""
        views: dict[str, dict] = {}
        report = {"nodes": {}, "network_consistent": True, "tampered_nodes": [], "record_mismatches": []}
        for org in self.orgs:
            raw = self.query_peer(org, "ListWatermarks", [])
            if raw is None:
                report["nodes"][ORG_NODES[org]] = {"reachable": False}
                continue
            ids = json.loads(raw)
            views[org] = {wm: json.loads(self.query_peer(org, "GetByWatermark", [wm]) or "null") for wm in ids}
            report["nodes"][ORG_NODES[org]] = {"reachable": True, "records": len(ids)}

        all_ids = sorted({wm for v in views.values() for wm in v})
        bad = set(o for o in self.orgs if o not in views)
        for wm in all_ids:
            versions: dict[str, list[str]] = {}
            for org, v in views.items():
                rec = v.get(wm)
                versions.setdefault(json.dumps(rec["record"] if rec else None, sort_keys=True), []).append(org)
            if len(versions) > 1:
                majority = max(versions, key=lambda k: len(versions[k]))
                dissent = [o for k, os_ in versions.items() if k != majority for o in os_]
                bad.update(dissent)
                report["record_mismatches"].append({"watermark_id": wm, "dissenting_nodes": [ORG_NODES[o] for o in dissent]})
        report["tampered_nodes"] = sorted(ORG_NODES[o] for o in bad)
        report["network_consistent"] = not bad
        return report
