"""
Pydantic Schemas for Cryptographic Attribution Service.
"""

from __future__ import annotations
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class EngineStatusResponse(BaseModel):
    engine: str
    fips_203_kem: str
    fips_204_dsa: str
    native_oqs_active: bool
    security_level: str
    vault_status: str
    ledger_entries_count: int


class EnrollRequest(BaseModel):
    name: str = Field(..., description="Human-readable name of the recipient (e.g. 'Alice Chen')")
    recipient_id: Optional[str] = Field(None, description="Optional custom ID. Auto-generated if omitted.")
    role: Optional[str] = Field("Special Analyst", description="Role or classification clearance level")


class RecipientPublicRecord(BaseModel):
    recipient_id: str
    name: str
    role: str
    kem_pubkey_id: str
    dsa_pubkey_id: str
    kem_public_key: str
    dsa_public_key: str
    created_at: str


class RecipientCiphertextBundle(BaseModel):
    recipient_id: str
    kem_pubkey_id: str
    kem_ciphertext: str
    wrapped_key: str
    wrap_nonce: str
    wrap_tag: str
    ciphertext: str
    nonce: str
    tag: str
    document_hash: str
    original_filename: str


class EncryptJsonRequest(BaseModel):
    pdf_base64: str
    filename: Optional[str] = "document.pdf"
    recipient_ids: List[str]


class EncryptResponse(BaseModel):
    document_hash: str
    filename: str
    recipient_count: int
    bundles: Dict[str, RecipientCiphertextBundle]


class DecryptRequest(BaseModel):
    bundle: RecipientCiphertextBundle
    recipient_id: str
    kem_private_key: Optional[str] = None
    dsa_private_key: Optional[str] = None
    return_pdf_base64: bool = True


class DecryptionRecord(BaseModel):
    watermark_hash: str
    document_hash: str
    timestamp: str
    recipient_id: str
    recipient_pubkey_id: str
    session_nonce: str


class DecryptResponse(BaseModel):
    recipient_id: str
    document_hash: str
    watermark_hash: str
    timestamp: str
    signature: str
    ledger_entry: Dict[str, Any]
    watermarked_pdf_base64: Optional[str] = None
    original_filename: str


class LeakAttributeResponse(BaseModel):
    attributed: bool
    recipient_id: Optional[str] = None
    recipient_name: Optional[str] = None
    timestamp: Optional[str] = None
    document_hash: Optional[str] = None
    watermark_hash: Optional[str] = None
    signature_valid: bool
    chain_valid: bool
    ledger_index: Optional[int] = None
    chain_length: int
    pqc_algorithm_kem: str = "ML-KEM-768 (FIPS 203)"
    pqc_algorithm_dsa: str = "ML-DSA-65 (FIPS 204)"
    summary: str


class LedgerStatusResponse(BaseModel):
    chain_valid: bool
    chain_length: int
    broken_at_index: Optional[int] = None
    error: Optional[str] = None
    head_hash: Optional[str] = None
    entries: List[Dict[str, Any]]
