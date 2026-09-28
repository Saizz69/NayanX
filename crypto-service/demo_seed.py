#!/usr/bin/env python3
"""
Forensic Post-Quantum Attribution Seed & Demo Script.

Hackathon Lifecycle Demonstration:
1. Enrolls 3 distinct recipients (Alice, Bob, Charlie) with:
   - ML-KEM-768 (FIPS 203) Key Encapsulation pairs
   - ML-DSA-65 (FIPS 204) Digital Signature pairs
2. Encrypts a sample classified briefing document with AES-256-GCM and encapsulates the symmetric key per recipient.
3. Decrypts separately for each recipient:
   - Derives recipient-specific forensic watermark: hash(recipient_id + nonce + timestamp + doc_hash)
   - Invisibly embeds the mark into the PDF (metadata, XMP, steganographic trailing anchor)
   - Builds decryption record and signs with recipient's post-quantum ML-DSA-65 private key
   - Appends block to the hash-chained Merkle ledger
   - Saves 3 visually identical, differently-watermarked PDF copies to disk
4. Simulates a classified document leak (picks Bob's copy).
5. Executes /leak/attribute to extract the mark, verify the ML-DSA signature, verify the hash chain,
   and cryptographically attribute the leak to Bob.

Production Architecture Note (for Judges):
- HSM/TPM Integration: Software vault can be replaced with PKCS#11 HSM (Thales Luna / YubiHSM2)
- Hardened Ledger: Local SQLite can be swapped for Hyperledger Fabric or Sigstore Rekor
- Watermarking: Upgraded to Boneh-Shaw / Tardos collusion-resistant codes for transform-domain resistance
"""

import io
import os
import sys
import json
import base64
from pathlib import Path

# Add project root to sys.path
SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

# Ensure DEMO_MODE is active for standalone demo execution
os.environ.setdefault("DEMO_MODE", "true")

import requests

from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors

from app.core.pqc import b64_encode, b64_decode

SERVER_URL = os.environ.get("CRYPTO_SERVICE_URL", "http://127.0.0.1:8000")
OUTPUT_DIR = SCRIPT_DIR / "data" / "samples"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def create_sample_pdf_file(filepath: Path) -> bytes:
    """Creates a sample PDF document."""
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=letter)
    
    # Header banner
    c.setFillColor(colors.HexColor("#1e1b4b"))
    c.rect(0, 720, 612, 72, fill=True, stroke=False)
    
    c.setFillColor(colors.HexColor("#ffffff"))
    c.setFont("Helvetica-Bold", 16)
    c.drawString(54, 755, "PROJECT HELIOS: POST-QUANTUM FORENSIC BRIEFING")
    c.setFont("Helvetica", 10)
    c.drawString(54, 735, "CLASSIFICATION: TOP SECRET // AIR-GAPPED DISTRIBUTION ONLY")
    
    # Body
    c.setFillColor(colors.HexColor("#0f172a"))
    c.setFont("Helvetica-Bold", 13)
    c.drawString(54, 680, "Executive Summary & Operational Mandate")
    
    c.setFont("Helvetica", 10.5)
    text_lines = [
        "1. This document is protected by NIST FIPS 203 (ML-KEM-768) and FIPS 204 (ML-DSA-65).",
        "2. Any decryption action constitutes a non-repudiable legal acknowledgement.",
        "3. Decryption embeds an invisible cryptographic watermark bound to the authorized recipient.",
        "4. Decryption records are immutably hash-chained in an append-only audit ledger.",
        "5. Unauthorized exfiltration or unauthorized distribution will be forensically attributed.",
        "",
        "Operational Directives:",
        "- Enclave systems must maintain strict air-gap integrity.",
        "- Cryptographic private keys must never cross network boundaries.",
        "- Recipient provenance is mathematically verifiable even if standard file metadata is altered.",
    ]
    
    y = 655
    for line in text_lines:
        c.drawString(54, y, line)
        y -= 22

    # Footer
    c.setStrokeColor(colors.HexColor("#cbd5e1"))
    c.setLineWidth(0.5)
    c.line(54, 100, 558, 100)
    c.setFillColor(colors.HexColor("#64748b"))
    c.setFont("Helvetica", 8)
    c.drawString(54, 85, "CONFIDENTIAL & PROPRIETARY — NAYANX FORENSIC ATTRIBUTION PROTOCOL")
    c.drawString(450, 85, "SECURITY LEVEL: FIPS 203/204")

    c.save()
    pdf_bytes = buf.getvalue()
    filepath.write_bytes(pdf_bytes)
    return pdf_bytes


def run_demo(use_http: bool = True):
    print("=" * 80)
    print(" HELIOS FORENSIC DOCUMENT-ATTRIBUTION SYSTEM — END-TO-END DEMO")
    print(" Standards: NIST FIPS 203 (ML-KEM-768) + NIST FIPS 204 (ML-DSA-65) + AES-256-GCM")
    print("=" * 80)

    # Setup client
    if use_http:
        try:
            r = requests.get(f"{SERVER_URL}/status", timeout=2)
            if r.status_code == 200:
                print(f"[OK] Connected to live backend at {SERVER_URL}")
                call_get = lambda ep: requests.get(f"{SERVER_URL}{ep}").json()
                call_post_json = lambda ep, payload: requests.post(f"{SERVER_URL}{ep}", json=payload).json()
                call_post_form = lambda ep, form_data: requests.post(f"{SERVER_URL}{ep}", data=form_data).json()
            else:
                use_http = False
        except Exception:
            use_http = False

    if not use_http:
        print("[INFO] Live HTTP server not running; executing directly with TestClient.")
        from fastapi.testclient import TestClient
        from app.main import app
        tc = TestClient(app)
        call_get = lambda ep: tc.get(ep).json()
        call_post_json = lambda ep, payload: tc.post(ep, json=payload).json()
        call_post_form = lambda ep, form_data: tc.post(ep, data=form_data).json()

    # Step 1: Diagnostics
    print("\n[STEP 1] Checking Cryptographic Engine Status...")
    status = call_get("/status")
    print(f"  * PQC Engine:         {status['engine']} (liboqs native: {status['native_oqs_active']})")
    print(f"  * Key Encapsulation:  {status['fips_203_kem']}")
    print(f"  * Digital Signature:  {status['fips_204_dsa']}")
    print(f"  * Security Category:  {status['security_level']}")
    print(f"  * Encrypted Keystore: {status['vault_status']}")

    # Step 2: Enroll 3 Recipients
    print("\n[STEP 2] Enrolling 3 Authorized Recipients (Generating ML-KEM + ML-DSA Keypairs)...")
    candidates = [
        {"name": "Alice Vance", "role": "Chief Intelligence Officer", "id": "rec-alice-01"},
        {"name": "Bob Sterling", "role": "Senior Cryptanalyst", "id": "rec-bob-02"},
        {"name": "Charlie Miller", "role": "Defense Logistics Attache", "id": "rec-charlie-03"},
    ]

    enrolled = {}
    for c in candidates:
        res = call_post_json("/enroll", {"name": c["name"], "role": c["role"], "recipient_id": c["id"]})
        # If already exists
        if "recipient_id" not in res:
            all_rec = call_get("/recipients")
            res = next(x for x in all_rec if x["recipient_id"] == c["id"])
        enrolled[c["id"]] = res
        print(f"  [OK] Enrolled: {res['name']} ({res['recipient_id']})")
        print(f"       - KEM Public Key ID: {res['kem_pubkey_id']} (ML-KEM-768, 1184 bytes)")
        print(f"       - DSA Public Key ID: {res['dsa_pubkey_id']} (ML-DSA-65, 1952 bytes)")

    # Step 3: Create Sample PDF & Encrypt
    print("\n[STEP 3] Generating & Encrypting Classified Document...")
    sample_pdf_path = OUTPUT_DIR / "sample_briefing.pdf"
    pdf_bytes = create_sample_pdf_file(sample_pdf_path)
    print(f"  * Created sample PDF: {sample_pdf_path.name} ({len(pdf_bytes)} bytes)")

    enc_payload = {
        "pdf_base64": b64_encode(pdf_bytes),
        "filename": "sample_briefing.pdf",
        "recipient_ids": list(enrolled.keys()),
    }
    enc_res = call_post_json("/documents/encrypt", enc_payload)
    doc_hash = enc_res["document_hash"]
    print(f"  [OK] AES-256-GCM Encryption Complete!")
    print(f"       - Document SHA-256: {doc_hash}")
    print(f"       - Bundles Created:  {enc_res['recipient_count']} distinct recipient packages")

    # Step 4: Decrypt Separately for Each Recipient
    print("\n[STEP 4] Decrypting Separately for Each Recipient & Injecting Forensic Watermarks...")
    copies = {}
    for r_id in enrolled.keys():
        bundle = enc_res["bundles"][r_id]
        dec_res = call_post_json("/documents/decrypt", {
            "bundle": bundle,
            "recipient_id": r_id,
            "return_pdf_base64": True,
        })
        
        # Save watermarked PDF
        wm_pdf_bytes = b64_decode(dec_res["watermarked_pdf_base64"])
        out_filename = f"{r_id}_watermarked.pdf"
        out_file = OUTPUT_DIR / out_filename
        out_file.write_bytes(wm_pdf_bytes)
        copies[r_id] = {
            "file": out_file,
            "bytes": wm_pdf_bytes,
            "dec_res": dec_res,
        }

        print(f"  [OK] Decrypted for {enrolled[r_id]['name']}:")
        print(f"       - Saved to:          {out_file.name}")
        print(f"       - Forensic Mark:     {dec_res['watermark_hash'][:24]}...")
        print(f"       - ML-DSA Signature:  {dec_res['signature'][:24]}... (3309 bytes)")
        print(f"       - Ledger Block #:    {dec_res['ledger_entry']['entry_index']}")
        print(f"       - Block Hash:        {dec_res['ledger_entry']['entry_hash'][:24]}...")

    # Step 5: Simulate a Leak (Bob's copy is leaked)
    leaker_id = "rec-bob-02"
    leaked_copy = copies[leaker_id]
    print(f"\n[STEP 5] SIMULATING DOCUMENT LEAK: Exfiltrated copy belonging to {enrolled[leaker_id]['name']}...")
    print(f"  * Leaked file: {leaked_copy['file'].name}")
    print(f"  * Submitting leaked document to /leak/attribute for forensic investigation...")

    # Step 6: Attribute the Leak
    attr_res = call_post_form("/leak/attribute", {"pdf_base64": b64_encode(leaked_copy["bytes"])})
    print("\n" + "=" * 80)
    print(" FORENSIC ATTRIBUTION REPORT (CRYPTOGRAPHIC PROOF VERIFIED)")
    print("=" * 80)
    print(f"  Attribution Status:       {'MATCH CONFIRMED' if attr_res['attributed'] else 'UNATTRIBUTED'}")
    print(f"  Identified Leaker:        {attr_res['recipient_name']} (ID: {attr_res['recipient_id']})")
    print(f"  Timestamp of Decryption:  {attr_res['timestamp']}")
    print(f"  Extracted Watermark Hash: {attr_res['watermark_hash']}")
    print(f"  Document Content Hash:    {attr_res['document_hash']}")
    print(f"  [1] SHA3-256 Commitment: {'VERIFIED' if attr_res.get('commitment_valid') else 'FAILED'}")
    print(f"  [2] HMAC Watermark:       {'VERIFIED' if attr_res.get('watermark_hmac_valid') else 'FAILED'}")
    print(f"  [3] Recipient ML-DSA-65:  {'VERIFIED' if attr_res.get('recipient_signature_valid') else 'FAILED'}")
    print(f"  [4] Service Counter-Sig:  {'VERIFIED' if attr_res.get('service_signature_valid') else 'FAILED'}")
    print(f"  [5] Ledger Hash-Chain:    {'VERIFIED' if attr_res.get('chain_valid') else 'FAILED'}")
    print(f"  [6] Distribution Bundle:  {'VERIFIED' if attr_res.get('distribution_bundle_valid') else 'FAILED'}")
    print(f"  Audit Ledger Block Index: #{attr_res['ledger_index']} (Chain Length: {attr_res['chain_length']})")
    print(f"\n  Summary: {attr_res['summary']}")
    print("=" * 80)

    # Step 7: Negative Test - Tampered Commitment
    print("\n[STEP 7] NEGATIVE TEST: Simulating Tampered SHA3-256 Pre-Distribution Commitment...")
    tamper_res = call_post_json(f"/demo/tamper-commitment?recipient_id={leaker_id}&document_hash={doc_hash}", {})
    print(f"  * Injected forged commitment: {tamper_res.get('forged_commitment', '0000...')}")
    attr_tampered = call_post_form("/leak/attribute", {"pdf_base64": b64_encode(leaked_copy["bytes"])})
    print(f"  * Tampered Verification Result -> Attributed: {attr_tampered['attributed']}, Commitment Valid: {attr_tampered['commitment_valid']}")
    assert attr_tampered["commitment_valid"] is False, "Tampered commitment MUST fail verification!"
    print("  [SUCCESS] Broken commitment was immediately detected and attribution rejected!")

    # Step 8: Negative Test - Forged Watermark HMAC
    print("\n[STEP 8] NEGATIVE TEST: Simulating Document with Forged Watermark...")
    from app.core.watermark import embed_watermark_in_pdf
    forged_bytes = embed_watermark_in_pdf(leaked_copy["bytes"], {
        "recipient_id": leaker_id,
        "document_hash": "0" * 64,
        "watermark_hash": "bad0" * 16,
        "timestamp": "2026-09-27T00:00:00Z",
    })
    attr_forged = call_post_form("/leak/attribute", {"pdf_base64": b64_encode(forged_bytes)})
    print(f"  * Forged Watermark Result -> Attributed: {attr_forged['attributed']}, HMAC Valid: {attr_forged['watermark_hmac_valid']}")
    assert attr_forged["watermark_hmac_valid"] is False, "Forged watermark MUST fail verification!"
    print("  [SUCCESS] Forged watermark HMAC was immediately detected and attribution rejected!")

    # Step 9: Ledger Audit
    print("\n[STEP 9] Inspecting Tamper-Evident Ledger...")
    ledger_audit = call_get("/ledger")
    print(f"  * Total Blocks in Ledger: {ledger_audit['chain_length']}")
    print(f"  * Entire Chain Integrity: {'100% VALID' if ledger_audit['chain_valid'] else 'COMPROMISED'}")
    print(f"  * Latest Head Hash:       {ledger_audit['head_hash']}")

    print("\n[COMPLETE] Seed & Demo workflow (positive and negative) completed successfully!")
    print(f"Watermarked artifacts saved in: {OUTPUT_DIR.resolve()}\n")


if __name__ == "__main__":
    run_demo(use_http=False)
