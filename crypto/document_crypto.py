"""
crypto/document_crypto.py
==========================

Broadcast-encrypt / individually-decrypt document layer.

Model:
    1. Sender generates one random Document Encryption Key (DEK) and
       encrypts the document ONCE with AES-256-GCM under the DEK.
    2. For EACH recipient, the sender wraps (encapsulates) the SAME DEK
       using that recipient's ML-KEM public key. This produces one
       per-recipient KEM ciphertext ("key wrap") -- small, one per
       recipient -- while the (large) document ciphertext is shared.
    3. Each recipient decapsulates their own key wrap with their own
       ML-KEM secret key to recover the DEK, then AES-GCM-decrypts the
       (identical, shared) document ciphertext.

This matches the problem statement precisely: "sender encrypts a file
once and each recipient decrypts it independently using their own
credentials."
"""

from __future__ import annotations
import os
import json
import base64
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from crypto.pqc import MLKEM


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


def _derive_aes_key(shared_secret: bytes, context: bytes) -> bytes:
    """HKDF-SHA256 derivation of a 256-bit AES key from the KEM shared
    secret, domain-separated by context (e.g. document id)."""
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=context)
    return hkdf.derive(shared_secret)


@dataclass
class EncryptedPackage:
    """The single distributed artifact: one ciphertext blob + one KEM
    key-wrap per recipient. This whole object is what gets broadcast."""
    document_id: str
    nonce: str                      # base64 AES-GCM nonce (shared)
    ciphertext: str                 # base64 AES-GCM ciphertext (shared, IDENTICAL for all recipients)
    key_wraps: dict = field(default_factory=dict)   # recipient_id -> base64 KEM ciphertext

    def to_json(self) -> str:
        return json.dumps({
            "document_id": self.document_id,
            "nonce": self.nonce,
            "ciphertext": self.ciphertext,
            "key_wraps": self.key_wraps,
        })

    @staticmethod
    def from_json(s: str) -> "EncryptedPackage":
        d = json.loads(s)
        return EncryptedPackage(**d)


def encrypt_for_recipients(document_id: str, plaintext: bytes, recipient_public_keys: dict) -> EncryptedPackage:
    """
    recipient_public_keys: dict of recipient_id -> ML-KEM public_key bytes

    Encrypts `plaintext` ONCE. Returns one EncryptedPackage whose
    `ciphertext` field is byte-for-byte identical regardless of how many
    recipients there are -- only `key_wraps` grows per recipient.
    """
    dek = os.urandom(32)  # Document Encryption Key, random per document
    nonce = os.urandom(12)

    aesgcm = AESGCM(dek)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=document_id.encode())

    key_wraps = {}
    for recipient_id, pub_key in recipient_public_keys.items():
        kem_ciphertext, shared_secret = MLKEM.encapsulate(pub_key)
        # wrap the DEK itself under a key derived from the KEM shared secret
        wrap_key = _derive_aes_key(shared_secret, context=document_id.encode())
        wrap_nonce = os.urandom(12)
        wrapped_dek = AESGCM(wrap_key).encrypt(wrap_nonce, dek, associated_data=recipient_id.encode())
        key_wraps[recipient_id] = _b64(kem_ciphertext) + "|" + _b64(wrap_nonce) + "|" + _b64(wrapped_dek)

    return EncryptedPackage(
        document_id=document_id,
        nonce=_b64(nonce),
        ciphertext=_b64(ciphertext),
        key_wraps=key_wraps,
    )


def decrypt_for_recipient(package: EncryptedPackage, recipient_id: str, recipient_secret_key: bytes) -> bytes:
    """Recipient-side decryption: recover DEK via their own KEM secret key,
    then AES-GCM-decrypt the (shared) document ciphertext."""
    if recipient_id not in package.key_wraps:
        raise PermissionError(f"'{recipient_id}' is not an authorized recipient of document '{package.document_id}'")

    kem_ct_b64, wrap_nonce_b64, wrapped_dek_b64 = package.key_wraps[recipient_id].split("|")
    kem_ciphertext = _unb64(kem_ct_b64)
    wrap_nonce = _unb64(wrap_nonce_b64)
    wrapped_dek = _unb64(wrapped_dek_b64)

    shared_secret = MLKEM.decapsulate(kem_ciphertext, recipient_secret_key)
    wrap_key = _derive_aes_key(shared_secret, context=package.document_id.encode())
    dek = AESGCM(wrap_key).decrypt(wrap_nonce, wrapped_dek, associated_data=recipient_id.encode())

    nonce = _unb64(package.nonce)
    ciphertext = _unb64(package.ciphertext)
    plaintext = AESGCM(dek).decrypt(nonce, ciphertext, associated_data=package.document_id.encode())
    return plaintext
