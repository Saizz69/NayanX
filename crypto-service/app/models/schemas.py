"""
Pydantic Schemas for Cryptographic Attribution Service.
"""

from __future__ import annotations
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class EngineStatusResponse(BaseModel):
    engine: str
    engine_note: str = "pure-Python reference implementation, not constant-time"
    fips_203_kem: str
    fips_204_dsa: str
    native_oqs_active: bool
    security_level: str
    vault_status: str
    ledger_entries_count: int
    self_test: Optional[Dict[str, bool]] = None



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
    bundle: Optional[RecipientCiphertextBundle] = None
    document_id: Optional[str] = None
    recipient_id: str
    session_no: Optional[int] = 1
    kem_private_key: Optional[str] = None
    dsa_private_key: Optional[str] = None
    return_pdf_base64: bool = True
    force_ledger_failure: bool = False  # Phase 2: Test fail-closed gate


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
    service_signature: Optional[str] = None
    ledger_entry: Dict[str, Any]
    watermarked_pdf_base64: Optional[str] = None
    original_filename: str
    step_events: Optional[List[Dict[str, Any]]] = None
    inclusion_proof: Optional[Dict[str, Any]] = None
    bundle_verified: Optional[bool] = None
    selective_keys_released: Optional[int] = None


class DocumentCapacityResponse(BaseModel):
    document_id: str
    wording_slots: int
    layout_slots: int
    total_slots: int
    delta_pt: float
    target_fpr: float
    largest_collusion_c: int


class StructuredSourceCreateRequest(BaseModel):
    document_id: Optional[str] = None
    title: Optional[str] = "CLASSIFIED BRIEFING"
    classification: Optional[str] = "TOP SECRET // AIR-GAPPED DISTRIBUTION"
    content: Optional[str] = None
    paragraphs: Optional[List[str]] = None
    delta_pt: Optional[float] = 0.35
    cutoff_t: Optional[float] = 0.05
    recipient_ids: List[str]
    max_sessions: Optional[int] = 2


class LeakAttributeResponse(BaseModel):
    verdict: str = "INCONCLUSIVE"  # "ATTRIBUTED", "SUSPECTED", "INCONCLUSIVE"
    attributed: bool = False
    recipient_id: Optional[str] = None
    recipient_name: Optional[str] = None
    timestamp: Optional[str] = None
    document_id: Optional[str] = None
    document_hash: Optional[str] = None
    watermark_hash: Optional[str] = None

    # Real Tardos Tracing Scores & Calibration Table
    score: Optional[float] = None
    candidate_scores: Dict[str, float] = Field(default_factory=dict)
    thresholds: Optional[Dict[str, Any]] = None
    observed_slots: Optional[Dict[str, Any]] = None

    # Pre-Distribution Cryptographic Commitments
    p_commitment_valid: bool = False
    codeword_commitment_valid: bool = False
    convenience_tag_detected: bool = False
    convenience_tag_match: bool = False

    # 6-Point Cryptographic Attribution Scorecard
    commitment_valid: bool = False
    watermark_hmac_valid: bool = False
    recipient_signature_valid: bool = False
    service_signature_valid: bool = False
    chain_valid: bool = False
    distribution_bundle_valid: bool = False

    # Backward-compatible fields
    signature_valid: bool = False
    ledger_index: Optional[int] = None
    chain_length: int = 0
    pqc_algorithm_kem: str = "ML-KEM-768 (FIPS 203)"
    pqc_algorithm_dsa: str = "ML-DSA-65 (FIPS 204)"
    summary: str

    # Complete Phase 4 Evidence Bundle & Section 65B(4) Certificate
    evidence_bundle: Optional[Dict[str, Any]] = None
    certificate_pdf_base64: Optional[str] = None
    certificate_filename: Optional[str] = None



class LedgerStatusResponse(BaseModel):
    chain_valid: bool
    chain_length: int
    broken_at_index: Optional[int] = None
    error: Optional[str] = None
    head_hash: Optional[str] = None
    entries: List[Dict[str, Any]]
