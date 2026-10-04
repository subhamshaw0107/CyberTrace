"""
forensics/trace_leak.py
=========================

The "given a leaked copy, identify the recipient" pipeline:
    1. Extract the (possibly degraded) watermark from the leaked image.
    2. Look it up against the ledger network (requires quorum agreement).
    3. Cryptographically verify the recipient's ML-DSA signature over
       the decryption record.
    4. Produce a final, human-readable, cryptographically verifiable
       attribution report.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional

from watermark.dct_watermark import extract_watermark_detailed, bit_error_rate
from ledger.ledger_network import LedgerNetwork
from ledger.forensics_result import ForensicLookupResult
from crypto.pqc import MLDSA


@dataclass
class AttributionReport:
    watermark_extracted_hex: str
    ledger_lookup: ForensicLookupResult
    signature_valid: Optional[bool]
    final_verdict: str
    match_distance_bits: Optional[int] = None   # Hamming distance extracted -> matched ledger ID (0 = exact)
    extraction: dict = field(default_factory=dict)

    def pretty_print(self) -> str:
        lines = []
        lines.append("=" * 70)
        lines.append("FORENSIC ATTRIBUTION REPORT")
        lines.append("=" * 70)
        lines.append(f"Extracted watermark ID : {self.watermark_extracted_hex}")
        if self.extraction:
            e = self.extraction
            lines.append(f"Extraction             : {e.get('method')}, sync confidence {e.get('confidence', 0):.2f}, "
                         f"rotation {e.get('angle', 0):+.2f} deg, scale x{e.get('scale', 1):.3f}")
        if self.match_distance_bits is not None:
            lines.append(f"Ledger ID match        : {'exact' if self.match_distance_bits == 0 else f'{self.match_distance_bits} of 128 bits differ (<= {MAX_MATCH_DISTANCE_BITS} accepted)'}")
        lines.append(f"Ledger match found     : {self.ledger_lookup.found}")
        lines.append(f"Quorum achieved        : {self.ledger_lookup.quorum_achieved}/{self.ledger_lookup.quorum_needed}")
        if self.ledger_lookup.record:
            r = self.ledger_lookup.record
            lines.append(f"Recipient identified   : {r.get('recipient_id')}")
            lines.append(f"Document ID            : {r.get('document_id')}")
            lines.append(f"Decryption timestamp   : {r.get('human_timestamp')}")
            lines.append(f"Session ID             : {r.get('session_id')}")
        lines.append(f"Signature verified      : {self.signature_valid}")
        lines.append("-" * 70)
        lines.append(f"VERDICT: {self.final_verdict}")
        lines.append("=" * 70)
        return "\n".join(lines)


# A leaked copy's recovered ID may have a few flipped bits. It is matched to the
# nearest ledger ID if within this many bits. For a random 128-bit ID, the chance
# of landing within 16 bits of a given ID is sum_{k<=16} C(128,k) / 2^128 ~ 3.2e-19,
# so even with 10^6 ledger records a false match is ~3.2e-13.
MAX_MATCH_DISTANCE_BITS = 16


def _nearest_ledger_id(watermark_bytes: bytes, ledger_network) -> tuple[Optional[str], Optional[int]]:
    if not hasattr(ledger_network, "all_watermark_ids"):
        return None, None
    best, best_d, runner_up = None, 10 ** 9, 10 ** 9
    for wm_hex in ledger_network.all_watermark_ids():
        d = round(bit_error_rate(watermark_bytes, bytes.fromhex(wm_hex)) * 128)
        if d < best_d:
            best, best_d, runner_up = wm_hex, d, best_d
        elif d < runner_up:
            runner_up = d
    if best is not None and best_d <= MAX_MATCH_DISTANCE_BITS and runner_up > MAX_MATCH_DISTANCE_BITS:
        return best, best_d
    return None, None


def trace_leaked_document(
    leaked_image_array,
    ledger_network: LedgerNetwork,
    recipient_signing_public_keys: dict,
) -> AttributionReport:
    """Extracts the watermark from a leaked image and attributes it (see attribute_watermark)."""
    watermark_bytes, info = extract_watermark_detailed(leaked_image_array)
    return attribute_watermark(watermark_bytes, ledger_network, recipient_signing_public_keys, info)


def attribute_watermark(
    watermark_bytes: bytes,
    ledger_network,
    recipient_signing_public_keys: dict,
    extraction_info: Optional[dict] = None,
) -> AttributionReport:
    """
    watermark_bytes    : 16-byte ID recovered from a leaked copy
    ledger_network     : LedgerNetwork or FabricLedgerNetwork holding committed decryption records
    recipient_signing_public_keys : known-good public keys per recipient (e.g. from an
                                     organizational PKI/directory), used to verify the
                                     recipient's own signature over the decryption record
                                     independent of what the ledger nodes stored.
    """
    watermark_hex = watermark_bytes.hex()

    lookup = ledger_network.lookup_by_watermark(watermark_hex)
    distance = 0 if lookup.found else None
    if not lookup.found:
        near, d = _nearest_ledger_id(watermark_bytes, ledger_network)
        if near is not None:
            lookup = ledger_network.lookup_by_watermark(near)
            distance = d
    signature_valid = None
    if lookup.found and lookup.record:
        recipient_id = lookup.record.get("recipient_id")
        stored_sig_hex = lookup.record.get("_signature_hex")  # embedded at commit time
        stored_pub_hex = lookup.record.get("_signer_public_key_hex")
        if stored_sig_hex and stored_pub_hex:
            from crypto.decryption_session import DecryptionRecord
            rec_for_verify = DecryptionRecord(
                watermark_id=lookup.record["watermark_id"],
                recipient_id=lookup.record["recipient_id"],
                document_id=lookup.record["document_id"],
                session_id=lookup.record["session_id"],
                document_hash=lookup.record["document_hash"],
                unix_timestamp=lookup.record["unix_timestamp"],
                human_timestamp=lookup.record["human_timestamp"],
            )
            sig = bytes.fromhex(stored_sig_hex)
            pub = bytes.fromhex(stored_pub_hex)
            signature_valid = MLDSA.verify(rec_for_verify.canonical_bytes(), sig, pub)

            # Cross-check against the independently-known public key directory,
            # to guard against a ledger entry claiming a signature that doesn't
            # actually belong to the recipient's real, out-of-band-verified key.
            if recipient_id in recipient_signing_public_keys:
                directory_pub = recipient_signing_public_keys[recipient_id]
                if directory_pub != pub:
                    signature_valid = False

    if not lookup.found:
        verdict = "NO MATCH -- this watermark is not present in the ledger. Document may not be from this system, or watermark was destroyed by heavy processing."
    elif not lookup.verified:
        verdict = f"INCONCLUSIVE -- match found but quorum/signature check failed ({lookup.quorum_achieved}/{lookup.quorum_needed}). Possible ledger tampering detected; do not rely on this result."
    elif signature_valid:
        verdict = f"CONFIRMED -- recipient '{lookup.record.get('recipient_id')}' is cryptographically proven to have decrypted this exact document in session {lookup.record.get('session_id')}. Non-repudiable."
    else:
        verdict = "SIGNATURE MISMATCH -- ledger record found but the recipient's cryptographic signature does not verify. Do not attribute without further investigation."

    return AttributionReport(
        watermark_extracted_hex=watermark_hex,
        ledger_lookup=lookup,
        signature_valid=signature_valid,
        final_verdict=verdict,
        match_distance_bits=distance,
        extraction=extraction_info or {},
    )
