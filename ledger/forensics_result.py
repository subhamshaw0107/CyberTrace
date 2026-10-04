"""
ledger/forensics_result.py
=============================
Result type for a cross-node forensic ledger lookup.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ForensicLookupResult:
    found: bool                       # was ANY node holding this watermark found at all
    verified: bool                    # did a quorum agree AND all signatures check out
    quorum_needed: int
    quorum_achieved: int
    record: Optional[dict]
    signature_checks: dict            # node_id -> bool
    node_ids_matched: list

    def summary(self) -> str:
        if not self.found:
            return "NOT FOUND: no ledger node has any record of this watermark."
        if not self.verified:
            return (f"FOUND BUT UNVERIFIED: only {self.quorum_achieved}/{self.quorum_needed} "
                    f"nodes agree -- insufficient quorum or signature failure. Possible tampering.")
        r = self.record
        return (f"VERIFIED: recipient='{r.get('recipient_id')}' decrypted document "
                f"'{r.get('document_id')}' at {r.get('human_timestamp')} "
                f"(session {r.get('session_id')}). "
                f"Confirmed by {self.quorum_achieved}/{len(self.signature_checks) or self.quorum_needed} "
                f"ledger nodes, all signatures valid.")
