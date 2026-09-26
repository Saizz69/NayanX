"""
Symmetric Document Encryption Engine using AES-256-GCM.

Standards:
- NIST SP 800-38D (Galois/Counter Mode)
- RFC 5869 (HMAC-based Extract-and-Expand Key Derivation Function - HKDF)

Cryptographic Blueprint:
1. Document Encryption:
   - A fresh cryptographically secure random 256-bit Document Key (K_doc) is generated for each document.
   - A unique 96-bit (12-byte) initialization vector (IV / Nonce) is generated.
   - The document is encrypted with AES-256-GCM, yielding ciphertext and a 128-bit authentication tag.
2. Recipient Key Encapsulation & Wrapping:
   - For each recipient, ML-KEM-768 produces a 32-byte shared secret (SS).
   - HKDF-SHA256 derives a 256-bit Key-Wrapping Key (KWK) from SS.
   - K_doc is wrapped with KWK using AES-256-GCM with a dedicated nonce and tag.
   - This ensures post-quantum multi-recipient encryption without re-encrypting the bulk PDF!
"""

from __future__ import annotations
import os
from typing import Tuple, Dict, Any
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from app.core.pqc import b64_encode, b64_decode


def generate_document_key() -> bytes:
    """Generate a high-entropy 256-bit AES key for bulk document encryption."""
    return AESGCM.generate_key(bit_length=256)


def derive_key_wrapping_key(shared_secret: bytes, salt: bytes = b"forensic-doc-pqc-salt-v1") -> bytes:
    """
    Derives a 256-bit AES-GCM key from the ML-KEM-768 shared secret using HKDF-SHA256.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"ML-KEM-768-AES256-GCM-KeyWrap",
    )
    return hkdf.derive(shared_secret)


def wrap_document_key(doc_key: bytes, shared_secret: bytes) -> Dict[str, str]:
    """
    Wraps the 256-bit document key using AES-256-GCM with the KEM-derived key.
    Returns base64-encoded wrapped_key, wrap_nonce, and wrap_tag.
    """
    kwk = derive_key_wrapping_key(shared_secret)
    aesgcm = AESGCM(kwk)
    nonce = os.urandom(12)
    # Encrypt doc_key (32 bytes). AESGCM.encrypt appends 16-byte tag to the ciphertext
    ct_with_tag = aesgcm.encrypt(nonce, doc_key, None)
    wrapped_key = ct_with_tag[:-16]
    tag = ct_with_tag[-16:]

    return {
        "wrapped_key": b64_encode(wrapped_key),
        "wrap_nonce": b64_encode(nonce),
        "wrap_tag": b64_encode(tag),
    }


def unwrap_document_key(wrapped_info: Dict[str, str], shared_secret: bytes) -> bytes:
    """
    Unwraps the 256-bit document key using the KEM-derived key.
    """
    kwk = derive_key_wrapping_key(shared_secret)
    aesgcm = AESGCM(kwk)
    nonce = b64_decode(wrapped_info["wrap_nonce"])
    wrapped_key = b64_decode(wrapped_info["wrapped_key"])
    tag = b64_decode(wrapped_info["wrap_tag"])

    ct_with_tag = wrapped_key + tag
    return aesgcm.decrypt(nonce, ct_with_tag, None)


def encrypt_document_bytes(document_bytes: bytes, doc_key: bytes) -> Dict[str, str]:
    """
    Encrypts arbitrary document bytes using AES-256-GCM.
    Returns:
        dict containing base64 ciphertext, nonce, tag, and sha256 plaintext hash.
    """
    digest = hashes.Hash(hashes.SHA256())
    digest.update(document_bytes)
    doc_hash_hex = digest.finalize().hex()

    aesgcm = AESGCM(doc_key)
    nonce = os.urandom(12)
    ct_with_tag = aesgcm.encrypt(nonce, document_bytes, None)
    ciphertext = ct_with_tag[:-16]
    tag = ct_with_tag[-16:]

    return {
        "ciphertext": b64_encode(ciphertext),
        "nonce": b64_encode(nonce),
        "tag": b64_encode(tag),
        "document_hash": doc_hash_hex,
        "byte_length": str(len(document_bytes)),
    }


def decrypt_document_bytes(
    ciphertext_b64: str, nonce_b64: str, tag_b64: str, doc_key: bytes
) -> bytes:
    """
    Decrypts and authenticates ciphertext using AES-256-GCM.
    Raises InvalidTag exception if ciphertext or tag was altered.
    """
    aesgcm = AESGCM(doc_key)
    nonce = b64_decode(nonce_b64)
    ciphertext = b64_decode(ciphertext_b64)
    tag = b64_decode(tag_b64)
    ct_with_tag = ciphertext + tag
    return aesgcm.decrypt(nonce, ct_with_tag, None)
