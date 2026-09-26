"""
REST API Routes for Forensic Post-Quantum Attribution Service.

Endpoints:
- POST /enroll: Post-Quantum recipient enrollment (ML-KEM-768 + ML-DSA-65)
- POST /documents/encrypt: AES-256-GCM symmetric encryption + ML-KEM key encapsulation
- POST /documents/decrypt: ML-KEM decapsulation, watermark injection, ML-DSA signature, ledger append
- POST /leak/attribute: Leaked PDF analysis, watermark extraction, PQC signature verification, ledger audit
- GET  /ledger: Complete tamper-evident audit ledger inspection
"""

from __future__ import annotations
import json
import uuid
import secrets
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Request, UploadFile, File, Form, HTTPException, status
from fastapi.responses import Response, FileResponse

from app import config
from app.core.pqc import PQCEngine, b64_encode, b64_decode
from app.core.symmetric import (
    generate_document_key,
    wrap_document_key,
    unwrap_document_key,
    encrypt_document_bytes,
    decrypt_document_bytes,
)
from app.core.keystore import LocalKeystore
from app.core.watermark import (
    compute_watermark_payload,
    embed_watermark_in_pdf,
    extract_watermark_from_pdf,
    compute_sha256,
)
from app.core.ledger import TamperEvidentLedger, canonical_json
from app.models.schemas import (
    EngineStatusResponse,
    EnrollRequest,
    RecipientPublicRecord,
    EncryptResponse,
    EncryptJsonRequest,
    RecipientCiphertextBundle,
    DecryptRequest,
    DecryptResponse,
    LeakAttributeResponse,
    LedgerStatusResponse,
)

router = APIRouter()

# Instantiate singletons for local air-gapped node
keystore = LocalKeystore(config.KEYSTORE_DIR, config.VAULT_PASSPHRASE)
ledger = TamperEvidentLedger(config.LEDGER_DB_PATH)


@router.get("/status", response_model=EngineStatusResponse, tags=["System Diagnostics"])
def get_system_status():
    """
    Returns the cryptographic engine status, post-quantum parameter sets,
    and ledger state.
    """
    status_info = PQCEngine.get_engine_status()
    return EngineStatusResponse(
        engine=status_info["engine"],
        fips_203_kem=status_info["fips_203_kem"],
        fips_204_dsa=status_info["fips_204_dsa"],
        native_oqs_active=status_info["native_oqs_active"],
        security_level=status_info["security_level"],
        vault_status="AES-256-GCM Encrypted Local Software Vault",
        ledger_entries_count=ledger.get_entry_count(),
    )


@router.get("/recipients", response_model=List[RecipientPublicRecord], tags=["Enrollment"])
def list_recipients():
    """Returns all enrolled recipients and their post-quantum public keys."""
    return keystore.get_all_recipients()


@router.post("/enroll", response_model=RecipientPublicRecord, tags=["Enrollment"])
def enroll_recipient(req: EnrollRequest):
    """
    POST /enroll
    1. Generates an ML-KEM-768 keypair for post-quantum key encapsulation (FIPS 203).
    2. Generates an ML-DSA-65 keypair for post-quantum digital signatures (FIPS 204).
    3. Seals private keys in the local encrypted software vault.
    4. Publishes public key IDs to the registry.

    Production Note: In an HSM deployment, the HSM generates and holds the private keys;
    this endpoint would invoke the HSM PKCS#11 C_GenerateKeyPair function.
    """
    recipient_id = req.recipient_id or f"rec-{uuid.uuid4().hex[:8]}"

    # Check if already exists
    existing = keystore.get_recipient_public(recipient_id)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Recipient with ID '{recipient_id}' already enrolled.",
        )

    # Generate PQC Keypairs
    kem_pk, kem_sk = PQCEngine.generate_kem_keypair()
    dsa_pk, dsa_sk = PQCEngine.generate_dsa_keypair()

    public_record = keystore.enroll_recipient(
        recipient_id=recipient_id,
        name=req.name,
        kem_pk=kem_pk,
        kem_sk=kem_sk,
        dsa_pk=dsa_pk,
        dsa_sk=dsa_sk,
        role=req.role or "Special Analyst",
    )

    return public_record


def _execute_document_encryption(
    pdf_bytes: bytes, filename: str, recipient_ids: List[str]
) -> EncryptResponse:
    """Helper for document encryption logic."""
    if not recipient_ids:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="At least one recipient ID must be provided.",
        )

    # Verify all recipients exist
    recipients = {}
    for r_id in recipient_ids:
        r_info = keystore.get_recipient_public(r_id)
        if not r_info:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Recipient '{r_id}' not found in public registry. Enroll first.",
            )
        recipients[r_id] = r_info

    # 1. Generate bulk 256-bit AES symmetric key
    doc_key = generate_document_key()

    # 2. Encrypt document bytes with AES-256-GCM
    doc_cipher = encrypt_document_bytes(pdf_bytes, doc_key)
    doc_hash = doc_cipher["document_hash"]

    bundles = {}

    # 3. For each recipient, encapsulate doc_key using recipient's ML-KEM-768 public key
    for r_id, r_info in recipients.items():
        kem_pk_bytes = b64_decode(r_info["kem_public_key"])
        shared_secret, kem_ciphertext = PQCEngine.kem_encapsulate(kem_pk_bytes)

        # Wrap doc_key with derived secret
        wrap_info = wrap_document_key(doc_key, shared_secret)

        bundles[r_id] = RecipientCiphertextBundle(
            recipient_id=r_id,
            kem_pubkey_id=r_info["kem_pubkey_id"],
            kem_ciphertext=b64_encode(kem_ciphertext),
            wrapped_key=wrap_info["wrapped_key"],
            wrap_nonce=wrap_info["wrap_nonce"],
            wrap_tag=wrap_info["wrap_tag"],
            ciphertext=doc_cipher["ciphertext"],
            nonce=doc_cipher["nonce"],
            tag=doc_cipher["tag"],
            document_hash=doc_hash,
            original_filename=filename,
        )

    return EncryptResponse(
        document_hash=doc_hash,
        filename=filename,
        recipient_count=len(bundles),
        bundles=bundles,
    )


@router.post("/documents/encrypt", response_model=EncryptResponse, tags=["Document Operations"])
async def encrypt_document(request: Request):
    """
    POST /documents/encrypt
    Takes a PDF + list of recipient IDs:
    Supports both:
    1. application/json: { "pdf_base64": "...", "filename": "...", "recipient_ids": [...] }
    2. multipart/form-data: file=<file upload>, recipient_ids="[...]" or "id1,id2"
    """
    content_type = request.headers.get("content-type", "")
    is_form = ("multipart/form-data" in content_type) or ("application/x-www-form-urlencoded" in content_type)
    if is_form:
        form = await request.form()
        file_obj = form.get("file")
        if file_obj and hasattr(file_obj, "read"):
            pdf_bytes = await file_obj.read()
            filename = getattr(file_obj, "filename", None) or "document.pdf"
        elif form.get("pdf_base64"):
            pdf_bytes = b64_decode(str(form.get("pdf_base64")))
            filename = str(form.get("filename") or "document.pdf")
        else:
            raise HTTPException(status_code=400, detail="Missing 'file' upload or 'pdf_base64' in form data.")

        rec_ids_raw = form.get("recipient_ids")
        if not rec_ids_raw:
            raise HTTPException(status_code=400, detail="Missing 'recipient_ids' in form data.")
        try:
            parsed_ids = json.loads(str(rec_ids_raw))
        except Exception:
            parsed_ids = [s.strip() for s in str(rec_ids_raw).split(",") if s.strip()]
        return _execute_document_encryption(pdf_bytes, filename, parsed_ids)
    else:
        try:
            body = await request.json()
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid JSON payload: {e}")
        pdf_b64 = body.get("pdf_base64")
        if not pdf_b64:
            raise HTTPException(status_code=400, detail="Missing 'pdf_base64' field in JSON body.")
        pdf_bytes = b64_decode(pdf_b64)
        filename = body.get("filename", "document.pdf")
        recipient_ids = body.get("recipient_ids", [])
        return _execute_document_encryption(pdf_bytes, filename, recipient_ids)


@router.post("/documents/decrypt", response_model=DecryptResponse, tags=["Document Operations"])
def decrypt_document(req: DecryptRequest):
    """
    POST /documents/decrypt
    Given a recipient's ciphertext bundle and private keys:
    a) Decapsulates the symmetric key using ML-KEM-768.
    b) Decrypts the PDF via AES-256-GCM and verifies authenticity tag.
    c) Generates a watermark payload = hash(recipient_id + session_nonce + timestamp + document_hash).
    d) Invisibly embeds the watermark payload into the PDF metadata and structure.
    e) Builds a decryption record {watermark_hash, document_hash, timestamp, recipient_pubkey_id, session_nonce},
       and signs it with recipient's ML-DSA-65 private key.
    f) Appends the signed record to the tamper-evident hash-chained ledger.
    g) Returns the watermarked, decrypted PDF with ledger receipt.
    """
    r_id = req.recipient_id
    bundle = req.bundle

    # 1. Fetch recipient keys (from request or local vault)
    if req.kem_private_key and req.dsa_private_key:
        kem_sk = b64_decode(req.kem_private_key)
        dsa_sk = b64_decode(req.dsa_private_key)
    else:
        priv_keys = keystore.get_recipient_private_keys(r_id)
        if not priv_keys:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Private keys for recipient '{r_id}' not found in vault. Provide them in request.",
            )
        kem_sk = priv_keys["kem_private_key"]
        dsa_sk = priv_keys["dsa_private_key"]

    r_pub = keystore.get_recipient_public(r_id)
    recipient_pubkey_id = r_pub["dsa_pubkey_id"] if r_pub else f"dsa-65-{r_id[:8]}"

    # 2. Decapsulate ML-KEM-768 shared secret
    kem_ct = b64_decode(bundle.kem_ciphertext)
    try:
        shared_secret = PQCEngine.kem_decapsulate(kem_sk, kem_ct)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"ML-KEM-768 decapsulation failed: {e}",
        )

    # 3. Unwrap document key
    try:
        doc_key = unwrap_document_key(
            {
                "wrapped_key": bundle.wrapped_key,
                "wrap_nonce": bundle.wrap_nonce,
                "wrap_tag": bundle.wrap_tag,
            },
            shared_secret,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Key unwrapping failed. Authentication tag mismatched: {e}",
        )

    # 4. Decrypt document bytes
    try:
        decrypted_pdf_bytes = decrypt_document_bytes(
            ciphertext_b64=bundle.ciphertext,
            nonce_b64=bundle.nonce,
            tag_b64=bundle.tag,
            doc_key=doc_key,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"AES-256-GCM document decryption failed: {e}",
        )

    # Verify original document hash
    actual_doc_hash = compute_sha256(decrypted_pdf_bytes)
    if actual_doc_hash != bundle.document_hash:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Decrypted document hash does not match bundle document hash.",
        )

    # 5. Generate forensic watermark payload
    session_nonce = secrets.token_hex(16)
    timestamp = datetime.now(timezone.utc).isoformat()
    wm_payload = compute_watermark_payload(
        recipient_id=r_id,
        session_nonce=session_nonce,
        timestamp=timestamp,
        document_hash=bundle.document_hash,
    )
    watermark_hash = wm_payload["watermark_hash"]

    # 6. Embed watermark invisibly into PDF
    watermarked_pdf_bytes = embed_watermark_in_pdf(decrypted_pdf_bytes, wm_payload)

    # 7. Build decryption record & sign with recipient's ML-DSA-65 private key
    decryption_record = {
        "watermark_hash": watermark_hash,
        "document_hash": bundle.document_hash,
        "timestamp": timestamp,
        "recipient_id": r_id,
        "recipient_pubkey_id": recipient_pubkey_id,
        "session_nonce": session_nonce,
    }
    canonical_record_bytes = canonical_json(decryption_record).encode("utf-8")
    dsa_sig_bytes = PQCEngine.dsa_sign(dsa_sk, canonical_record_bytes)
    dsa_sig_b64 = b64_encode(dsa_sig_bytes)

    # 8. Append to hash-chained tamper-evident ledger
    ledger_entry = ledger.append_record(
        record=decryption_record,
        signature_b64=dsa_sig_b64,
    )

    return DecryptResponse(
        recipient_id=r_id,
        document_hash=bundle.document_hash,
        watermark_hash=watermark_hash,
        timestamp=timestamp,
        signature=dsa_sig_b64,
        ledger_entry=ledger_entry,
        watermarked_pdf_base64=b64_encode(watermarked_pdf_bytes) if req.return_pdf_base64 else None,
        original_filename=f"watermarked_{bundle.original_filename}",
    )


def _execute_leak_attribution(leaked_pdf_bytes: bytes) -> LeakAttributeResponse:
    """Helper for leak attribution verification."""
    # 1. Extract forensic watermark payload from PDF
    extracted = extract_watermark_from_pdf(leaked_pdf_bytes)
    if not extracted or "watermark_hash" not in extracted:
        chain_audit = ledger.verify_chain_integrity()
        return LeakAttributeResponse(
            attributed=False,
            signature_valid=False,
            chain_valid=chain_audit["valid"],
            chain_length=chain_audit["chain_length"],
            summary="No forensic watermark payload found in leaked document. "
                    "File may have been stripped or was not generated by this protocol.",
        )

    extracted_wm_hash = extracted["watermark_hash"]
    extracted_rec_id = extracted.get("recipient_id")
    extracted_doc_hash = extracted.get("document_hash")

    # 2. Look up matching ledger entry
    entry = ledger.find_by_watermark_hash(extracted_wm_hash)
    if not entry:
        chain_audit = ledger.verify_chain_integrity()
        return LeakAttributeResponse(
            attributed=False,
            watermark_hash=extracted_wm_hash,
            document_hash=extracted_doc_hash,
            recipient_id=extracted_rec_id,
            signature_valid=False,
            chain_valid=chain_audit["valid"],
            chain_length=chain_audit["chain_length"],
            summary=f"Watermark hash '{extracted_wm_hash[:16]}...' found in document, "
                    f"but no corresponding entry exists in the ledger.",
        )

    # 3. Verify ML-DSA-65 post-quantum signature
    rec_id = entry["record"]["recipient_id"]
    r_pub = keystore.get_recipient_public(rec_id)
    sig_valid = False

    if r_pub and "dsa_public_key" in r_pub:
        dsa_pk = b64_decode(r_pub["dsa_public_key"])
        canonical_msg = canonical_json(entry["record"]).encode("utf-8")
        sig_bytes = b64_decode(entry["signature"])
        sig_valid = PQCEngine.dsa_verify(dsa_pk, canonical_msg, sig_bytes)

    # 4. Verify complete hash-chain integrity
    chain_audit = ledger.verify_chain_integrity()

    # Recipient friendly name
    recipient_name = r_pub["name"] if r_pub else rec_id

    summary = (
        f"FORENSIC MATCH CONFIRMED: Document leaked by '{recipient_name}' (ID: {rec_id}). "
        f"Post-Quantum ML-DSA-65 signature is {'VERIFIED VALID' if sig_valid else 'INVALID'}. "
        f"Ledger Merkle Hash-Chain is {'INTACT & UNTAMPERED' if chain_audit['valid'] else 'TAMPERED'}."
    )

    return LeakAttributeResponse(
        attributed=True,
        recipient_id=rec_id,
        recipient_name=recipient_name,
        timestamp=entry["timestamp"],
        document_hash=entry["document_hash"],
        watermark_hash=extracted_wm_hash,
        signature_valid=sig_valid,
        chain_valid=chain_audit["valid"],
        ledger_index=entry["entry_index"],
        chain_length=chain_audit["chain_length"],
        summary=summary,
    )


@router.post("/leak/attribute", response_model=LeakAttributeResponse, tags=["Forensic Attribution"])
async def attribute_leaked_document(request: Request):
    """
    POST /leak/attribute
    Given a leaked PDF:
    Supports:
    1. application/json: { "pdf_base64": "..." }
    2. multipart/form-data: file=<file upload> or pdf_base64="..."
    
    Workflow:
    1. Extracts the invisible forensic watermark payload.
    2. Queries the ledger for the matching decryption record.
    3. Verifies the ML-DSA-65 post-quantum signature against stored public key.
    4. Audits the entire hash-chained ledger to ensure no blocks have been modified or reordered.
    5. Returns a cryptographically verifiable attribution verdict.
    """
    content_type = request.headers.get("content-type", "")
    is_form = ("multipart/form-data" in content_type) or ("application/x-www-form-urlencoded" in content_type)

    if is_form:
        form = await request.form()
        file_obj = form.get("file")
        if file_obj and hasattr(file_obj, "read"):
            pdf_bytes = await file_obj.read()
        else:
            pdf_b64 = form.get("pdf_base64")
            if not pdf_b64:
                raise HTTPException(status_code=400, detail="Must provide 'file' upload or 'pdf_base64' in form.")
            pdf_bytes = b64_decode(str(pdf_b64))
    else:
        try:
            body = await request.json()
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid JSON payload: {e}")
        pdf_b64 = body.get("pdf_base64")
        if not pdf_b64:
            raise HTTPException(status_code=400, detail="Missing 'pdf_base64' in JSON body.")
        pdf_bytes = b64_decode(pdf_b64)

    return _execute_leak_attribution(pdf_bytes)


@router.get("/ledger", response_model=LedgerStatusResponse, tags=["Audit Ledger"])
def get_ledger():
    """
    GET /ledger
    Returns the complete tamper-evident hash-chained audit ledger,
    including cryptographic integrity status across all blocks.
    """
    audit = ledger.verify_chain_integrity()
    entries = ledger.get_all_entries()

    return LedgerStatusResponse(
        chain_valid=audit["valid"],
        chain_length=audit["chain_length"],
        broken_at_index=audit["broken_at_index"],
        error=audit["error"],
        head_hash=audit.get("head_hash"),
        entries=entries,
    )


@router.post("/demo/tamper", tags=["Demonstration & Judging"])
def tamper_ledger_block(block_index: int = 1):
    """
    Adversarial Tamper Simulation for Judges:
    Directly mutates an existing ledger block in SQLite without re-signing.
    Allows proving that `/leak/attribute` and `GET /ledger` immediately detect the attack.
    """
    ledger.tamper_simulate(block_index, new_recipient_id="adversary-forged-identity")
    return {
        "status": "tampered",
        "block_index": block_index,
        "message": f"Block #{block_index} was modified. Chain integrity will now fail on next verification.",
    }


@router.post("/demo/restore", tags=["Demonstration & Judging"])
def restore_ledger():
    """
    Restores any tampered ledger blocks back to their verified cryptographic records.
    """
    ledger.restore_all_tampered()
    audit = ledger.verify_chain_integrity()
    return {
        "status": "restored",
        "chain_valid": audit["valid"],
        "chain_length": audit["chain_length"],
        "message": "All tampered blocks restored. Merkle ledger hash-chain integrity is verified intact.",
    }


@router.get("/samples/list", tags=["Document Samples & Provenance"])
def list_sample_documents():
    """
    Returns available decrypted recipient documents and sample briefing for forensic testing.
    """
    from pathlib import Path
    samples = []
    metadata = {
        "rec-alice-01_watermarked.pdf": {
            "title": "Alice Vance — Decrypted & Watermarked Copy",
            "recipient_id": "rec-alice-01",
            "recipient_name": "Alice Vance",
            "role": "Chief Intelligence Officer",
            "watermarked": True,
            "description": "Individually watermarked via SHA-256 steganographic anchor bound to Alice Vance's keypair.",
        },
        "rec-bob-02_watermarked.pdf": {
            "title": "Bob Sterling — Decrypted & Watermarked Copy",
            "recipient_id": "rec-bob-02",
            "recipient_name": "Bob Sterling",
            "role": "Senior Cryptanalyst",
            "watermarked": True,
            "description": "Individually watermarked via SHA-256 steganographic anchor bound to Bob Sterling's keypair.",
        },
        "rec-charlie-03_watermarked.pdf": {
            "title": "Charlie Miller — Decrypted & Watermarked Copy",
            "recipient_id": "rec-charlie-03",
            "recipient_name": "Charlie Miller",
            "role": "Defense Logistics Attaché",
            "watermarked": True,
            "description": "Individually watermarked via SHA-256 steganographic anchor bound to Charlie Miller's keypair.",
        },
        "sample_briefing.pdf": {
            "title": "Original Classified Briefing (Unwatermarked)",
            "recipient_id": None,
            "recipient_name": None,
            "role": "Source Document",
            "watermarked": False,
            "description": "Master classified dossier prior to recipient-specific decryption and stego watermarking.",
        },
    }

    if config.SAMPLE_DOCS_DIR.exists():
        for f in sorted(config.SAMPLE_DOCS_DIR.glob("*.pdf")):
            raw_bytes = f.read_bytes()
            meta = metadata.get(f.name, {
                "title": f.name,
                "recipient_id": None,
                "recipient_name": None,
                "role": "Document",
                "watermarked": "watermarked" in f.name,
                "description": "Classified PDF document artifact.",
            })
            samples.append({
                "filename": f.name,
                "title": meta["title"],
                "recipient_id": meta["recipient_id"],
                "recipient_name": meta["recipient_name"],
                "role": meta["role"],
                "watermarked": meta["watermarked"],
                "description": meta["description"],
                "file_size": len(raw_bytes),
                "pdf_base64": b64_encode(raw_bytes),
                "download_url": f"/samples/download/{f.name}",
            })
    return samples


@router.get("/samples/download/{filename}", tags=["Document Samples & Provenance"])
def download_sample_document(filename: str):
    """
    Directly downloads a recipient's watermarked PDF or the original classified briefing.
    """
    from pathlib import Path
    safe_filename = Path(filename).name
    target_path = config.SAMPLE_DOCS_DIR / safe_filename
    if not target_path.exists() or not target_path.is_file():
        raise HTTPException(status_code=404, detail=f"Sample document '{safe_filename}' not found.")

    return FileResponse(
        path=str(target_path),
        media_type="application/pdf",
        filename=safe_filename,
    )
