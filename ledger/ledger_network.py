"""
ledger/ledger_network.py
===========================

Ties together N independent LedgerNode instances into a permissioned
network with quorum-commit semantics, and provides the tamper-detection
/ forensic-lookup API used by the rest of the system.
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Optional

from ledger.ledger_node import LedgerNode, Block
from crypto.pqc import MLDSA


@dataclass
class CommitResult:
    committed: bool
    quorum_needed: int
    quorum_achieved: int
    block_index: int
    block_hash: str
    node_ids_committed: list


class LedgerNetwork:
    """
    A permissioned network of `num_nodes` ledger participants (e.g. one
    run by the sender's org, one by a neutral auditor/compliance body,
    one by IT security, one offsite backup node -- all air-gapped, all
    on the same secure network segment but administratively separate).

    A record is only durably committed once `quorum` nodes have
    independently validated and appended it with their OWN signature.
    """

    def __init__(self, node_ids: list[str], quorum: int | None = None):
        self.nodes: dict[str, LedgerNode] = {nid: LedgerNode(nid) for nid in node_ids}
        self.quorum = quorum if quorum is not None else (len(node_ids) // 2 + 1)
        if self.quorum > len(node_ids):
            raise ValueError("quorum cannot exceed number of nodes")

    def commit_record(self, record: dict) -> CommitResult:
        """
        Proposes `record` to every node. Each node independently builds
        its own block (with its own prev_hash, own signature). We
        require `quorum` nodes to successfully append a block whose
        RECORD content matches exactly (byte-for-byte) before we call
        this record 'committed'. This models a permissioned-BFT-style
        commit: an attacker controlling fewer than quorum nodes cannot
        insert, alter, or suppress a record because the honest quorum's
        agreement on the record content, and each node's own hash chain,
        will disagree with the attacker's version.
        """
        proposals: dict[str, Block] = {}
        for node_id, node in self.nodes.items():
            block = node.propose_block(record)
            proposals[node_id] = block

        committed_nodes = []
        for node_id, node in self.nodes.items():
            block = proposals[node_id]
            if node.accept_block(block):
                committed_nodes.append(node_id)

        achieved = len(committed_nodes)
        committed = achieved >= self.quorum

        ref_node = self.nodes[committed_nodes[0]] if committed_nodes else None
        ref_block = ref_node.chain[-1] if ref_node else None

        return CommitResult(
            committed=committed,
            quorum_needed=self.quorum,
            quorum_achieved=achieved,
            block_index=ref_block.index if ref_block else -1,
            block_hash=ref_block.block_hash if ref_block else "",
            node_ids_committed=committed_nodes,
        )

    def verify_network_integrity(self) -> dict:
        """Checks every node's own chain integrity AND cross-checks that
        a quorum of nodes agree on every record. Returns a report usable
        for a 'ledger health' dashboard."""
        report = {"nodes": {}, "network_consistent": True, "tampered_nodes": []}
        for node_id, node in self.nodes.items():
            ok = node.verify_own_chain()
            report["nodes"][node_id] = {
                "chain_length": len(node.chain),
                "self_consistent": ok,
            }
            if not ok:
                report["tampered_nodes"].append(node_id)
                report["network_consistent"] = False

        # cross-node agreement check on record content by index
        chain_lengths = [len(n.chain) for n in self.nodes.values()]
        min_len = min(chain_lengths) if chain_lengths else 0
        mismatches = []
        for idx in range(min_len):
            if idx == 0:
                continue  # genesis blocks legitimately differ (each embeds its own node_id)
            # Note: block hashes legitimately differ across nodes because
            # each node has its own node_id / chain-specific prev_hash
            # lineage; what MUST agree across a quorum is the RECORD
            # payload itself at each index.
            records_at_idx = {nid: n.chain[idx].record for nid, n in self.nodes.items() if idx < len(n.chain)}
            unique_records = set(str(sorted(r.items())) for r in records_at_idx.values())
            if len(unique_records) > 1:
                mismatches.append(idx)
        report["record_mismatches_at_indices"] = mismatches
        if mismatches:
            report["network_consistent"] = False
        return report

    def simulate_rogue_admin_tamper(self, node_id: str, block_index: int, malicious_record: dict):
        """
        DEMO/TEST FUNCTION: simulates a single compromised administrator
        directly editing one node's local ledger file (bypassing the
        proper commit protocol) to erase or alter a decryption record.
        Used to prove the 'no single admin can alter records undetected'
        requirement -- call verify_network_integrity() afterward to see
        it get caught.
        """
        node = self.nodes[node_id]
        node.chain[block_index].record = malicious_record
        # NOTE: we deliberately do NOT recompute block_hash/signature here,
        # exactly as a real attacker directly editing a database row would
        # NOT be able to also forge the other honest nodes' independent
        # attestations of the original content.

    def all_watermark_ids(self) -> list[str]:
        """Every watermark ID held by at least one node (for nearest-ID forensic matching;
        any match is still re-checked by the quorum lookup)."""
        ids = set()
        for node in self.nodes.values():
            for block in node.chain[1:]:
                wm = block.record.get("watermark_id")
                if isinstance(wm, str):
                    ids.add(wm)
        return sorted(ids)

    def lookup_by_watermark(self, watermark_id_hex: str) -> "ForensicLookupResult":
        """
        Cross-node forensic lookup: queries every node for a block whose
        record.watermark_id matches, and only returns a VERIFIED result
        if a quorum of nodes independently hold the identical record,
        each correctly signed by that node's own key.
        """
        from ledger.forensics_result import ForensicLookupResult  # local import avoids circulars

        matches: dict[str, Block] = {}
        for node_id, node in self.nodes.items():
            block = node.get_record_by_watermark(watermark_id_hex)
            if block is not None:
                matches[node_id] = block

        if not matches:
            return ForensicLookupResult(found=False, verified=False, quorum_needed=self.quorum,
                                         quorum_achieved=0, record=None, signature_checks={}, node_ids_matched=[])

        # group by identical record content
        groups: dict[str, list[str]] = {}
        for node_id, block in matches.items():
            key = str(sorted(block.record.items()))
            groups.setdefault(key, []).append(node_id)

        best_key = max(groups, key=lambda k: len(groups[k]))
        best_node_ids = groups[best_key]
        achieved = len(best_node_ids)
        verified = achieved >= self.quorum

        # verify each agreeing node's own signature over its block hash
        sig_checks = {}
        for node_id in best_node_ids:
            node = self.nodes[node_id]
            block = matches[node_id]
            sig = bytes.fromhex(block.node_signature)
            sig_checks[node_id] = MLDSA.verify(bytes.fromhex(block.block_hash), sig, node.keypair.public_key)

        record = matches[best_node_ids[0]].record

        return ForensicLookupResult(
            found=True,
            verified=verified and all(sig_checks.values()),
            quorum_needed=self.quorum,
            quorum_achieved=achieved,
            record=record,
            signature_checks=sig_checks,
            node_ids_matched=best_node_ids,
        )
