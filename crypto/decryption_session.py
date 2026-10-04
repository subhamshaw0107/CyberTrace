"""
crypto/decryption_session.py
===============================

Ties together: decrypting a document -> generating a watermark ->
signing a decryption record with the recipient's OWN ML-DSA private
key -> committing to the ledger. This is the "non-repudiation" core
of the system: the recipient cannot later deny having decrypted the
file, because the signature can only have been produced by their
private key, and the record lives on a quorum-committed ledger they
don't solely control.
"""

from __future__ import annotations
import os
import time
import hashlib
import json
from dataclasses import dataclass

from crypto.pqc import MLDSA, DSAKeyPair
from crypto.document_crypto import EncryptedPackage, decrypt_for_recipient
from watermark.dct_watermark import generate_watermark_id, embed_watermark


@dataclass
class DecryptionRecord:
    """The payload that gets signed by the recipient and committed to
    the ledger -- the cryptographically-bound proof of 'who decrypted
    what, when, producing which watermark'."""
    watermark_id: str          # hex
    recipient_id: str
    document_id: str
    session_id: str
    document_hash: str         # SHA3-256 of the ORIGINAL plaintext (proves which doc)
    unix_timestamp: float
    human_timestamp: str

    def canonical_bytes(self) -> bytes:
        payload = {
            "watermark_id": self.watermark_id,
            "recipient_id": self.recipient_id,
            "document_id": self.document_id,
            "session_id": self.session_id,
            "document_hash": self.document_hash,
            "unix_timestamp": self.unix_timestamp,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()

    def to_dict(self) -> dict:
        return {
            "watermark_id": self.watermark_id,
            "recipient_id": self.recipient_id,
            "document_id": self.document_id,
            "session_id": self.session_id,
            "document_hash": self.document_hash,
            "unix_timestamp": self.unix_timestamp,
            "human_timestamp": self.human_timestamp,
        }


@dataclass
class DecryptionSessionResult:
    plaintext_bytes: bytes             # raw decrypted bytes (pre-watermark)
    watermarked_array: object          # numpy array, the visually-identical watermarked image
    record: DecryptionRecord
    signature_hex: str
    signer_public_key_hex: str


def perform_decryption_session(
    package: EncryptedPackage,
    recipient_id: str,
    recipient_kem_secret_key: bytes,
    recipient_dsa_keypair: DSAKeyPair,
    raw_image_array=None,
) -> DecryptionSessionResult:
    """
    Full recipient-side flow for ONE decryption event:
      1. Decrypt the shared ciphertext using the recipient's own KEM secret key.
      2. Generate a fresh, session-unique watermark ID.
      3. Embed it invisibly into the decrypted image (visually identical output).
      4. Build a DecryptionRecord binding {watermark, recipient, doc, time}.
      5. Sign the record with the recipient's OWN ML-DSA secret key.
    Returns everything needed to (a) hand the recipient their watermarked
    copy and (b) commit the signed record to the ledger.
    """
    plaintext = decrypt_for_recipient(package, recipient_id, recipient_kem_secret_key)
    document_hash = hashlib.sha3_256(plaintext).hexdigest()

    session_nonce = os.urandom(16)
    session_id = session_nonce.hex()
    watermark_id = generate_watermark_id(recipient_id, package.document_id, session_nonce)

    if raw_image_array is not None:
        watermarked_array, _ = embed_watermark(raw_image_array, watermark_id)
    else:
        watermarked_array = None

    now = time.time()
    record = DecryptionRecord(
        watermark_id=watermark_id.hex(),
        recipient_id=recipient_id,
        document_id=package.document_id,
        session_id=session_id,
        document_hash=document_hash,
        unix_timestamp=now,
        human_timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
    )

    signature = MLDSA.sign(record.canonical_bytes(), recipient_dsa_keypair.secret_key)

    return DecryptionSessionResult(
        plaintext_bytes=plaintext,
        watermarked_array=watermarked_array,
        record=record,
        signature_hex=signature.hex(),
        signer_public_key_hex=recipient_dsa_keypair.public_key.hex(),
    )
