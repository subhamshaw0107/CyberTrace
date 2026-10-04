"""
ledger/ledger_node.py
=======================

Offline, tamper-evident, multi-node ledger for decryption-attribution
records -- the "no single administrator or compromised account can
retroactively alter or erase the record" requirement.

DESIGN
------
Rather than a single hash-chained log file (which one compromised
admin CAN silently rewrite if they control that one file), this
implements N independent ledger nodes, each an independent append-only
hash chain, that:

    1. Each maintain their OWN copy of the chain (simulating separate
       machines/processes in a permissioned network -- e.g. one node
       per: sender org, recipient org, a neutral auditor, a backup site).
    2. A write is only considered COMMITTED when a QUORUM of nodes
       (default 3-of-4, configurable) have accepted and cross-signed it.
    3. Every node signs every block it appends with its own node
       signing key (ML-DSA-shaped, see crypto/pqc.py), so commitment
       is itself an unforgeable, multi-party attested event -- not
       just "the file says so".
    4. At verification/lookup time, a record is only trusted if it is
       IDENTICAL and correctly chained across at least a quorum of
       nodes. A single node being compromised/rolled-back/deleted
       is detected (chain hash mismatch against the honest majority)
       and does NOT let an attacker rewrite history, because they
       would need to compromise a quorum simultaneously and in a
       mutually consistent way.

This is a simplified BFT-style permissioned ledger -- not a full
consensus protocol implementation (no view-changes, leader election,
etc.), but it demonstrates the core property the problem statement
asks for: NO SINGLE ADMIN CAN UNILATERALLY ALTER OR ERASE A RECORD,
because doing so breaks that node's chain-hash agreement with the
other nodes, which is detectable.

REAL DEPLOYMENT NOTE: swap this for Hyperledger Fabric / Corda running
on an air-gapped network of real separate machines; the block/record
schema and quorum-commit logic here maps directly onto Fabric
endorsement policies (quorum = endorsement policy, e.g. "3 of 4 orgs
must endorse").
"""

from __future__ import annotations
import hashlib
import json
import time
import copy
from dataclasses import dataclass, field, asdict
from typing import Optional

from crypto.pqc import MLDSA, DSAKeyPair


def _hash_json(obj: dict) -> str:
    canonical = json.dumps(obj, sort_keys=True, separators=(",", ":"))
    return hashlib.sha3_256(canonical.encode()).hexdigest()


@dataclass
class Block:
    index: int
    timestamp: float
    record: dict                # the decryption-attribution record (payload)
    prev_hash: str
    node_id: str
    node_signature: str = ""    # hex-encoded ML-DSA signature by this node over the block hash
    block_hash: str = field(default="")

    def compute_hash(self) -> str:
        payload = {
            "index": self.index,
            "timestamp": self.timestamp,
            "record": self.record,
            "prev_hash": self.prev_hash,
            "node_id": self.node_id,
        }
        return _hash_json(payload)


class LedgerNode:
    """A single independent ledger participant with its own chain and
    its own ML-DSA node signing keypair."""

    def __init__(self, node_id: str):
        self.node_id = node_id
        self.keypair: DSAKeyPair = MLDSA.keygen()
        self.chain: list[Block] = []
        self._append_genesis()

    def _append_genesis(self):
        genesis = Block(
            index=0,
            timestamp=time.time(),
            record={"type": "GENESIS", "node_id": self.node_id},
            prev_hash="0" * 64,
            node_id=self.node_id,
        )
        genesis.block_hash = genesis.compute_hash()
        genesis.node_signature = MLDSA.sign(bytes.fromhex(genesis.block_hash), self.keypair.secret_key).hex()
        self.chain.append(genesis)

    def propose_block(self, record: dict) -> Block:
        """Creates a candidate block (not yet committed) for this node."""
        prev = self.chain[-1]
        block = Block(
            index=prev.index + 1,
            timestamp=time.time(),
            record=record,
            prev_hash=prev.block_hash,
            node_id=self.node_id,
        )
        block.block_hash = block.compute_hash()
        block.node_signature = MLDSA.sign(bytes.fromhex(block.block_hash), self.keypair.secret_key).hex()
        return block

    def accept_block(self, block: Block) -> bool:
        """Validates and appends a block proposed for this node's chain
        (used when the node accepts a block matching the quorum-agreed
        content, with its own signature over it)."""
        prev = self.chain[-1]
        if block.prev_hash != prev.block_hash:
            return False
        if block.compute_hash() != block.block_hash:
            return False
        self.chain.append(block)
        return True

    def verify_own_chain(self) -> bool:
        """Detects local tampering: recomputes every hash and signature
        in this node's own chain."""
        for i, block in enumerate(self.chain):
            if block.compute_hash() != block.block_hash:
                return False
            if i > 0 and block.prev_hash != self.chain[i - 1].block_hash:
                return False
            sig = bytes.fromhex(block.node_signature)
            if not MLDSA.verify(bytes.fromhex(block.block_hash), sig, self.keypair.public_key):
                return False
        return True

    def get_record_by_watermark(self, watermark_id_hex: str) -> Optional[Block]:
        for block in self.chain:
            if block.record.get("watermark_id") == watermark_id_hex:
                return block
        return None
