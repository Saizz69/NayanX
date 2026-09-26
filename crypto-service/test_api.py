"""
Comprehensive Unit & Integration Test Suite for Crypto Service.
Verifies all post-quantum endpoints, watermarking, signature, ledger chaining,
and leak attribution end-to-end.
"""

import io
import sys
from pathlib import Path

# Add app directory to sys.path
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

from fastapi.testclient import TestClient
from reportlab.pdfgen import canvas
from app.main import app
from app.core.pqc import b64_encode

client = TestClient(app)


def generate_sample_pdf(title: str = "TOP SECRET OPERATION HELIOS") -> bytes:
    """Generates an in-memory test PDF."""
    buf = io.BytesIO()
    c = canvas.Canvas(buf)
    c.setFont("Helvetica-Bold", 18)
    c.drawString(72, 750, title)
    c.setFont("Helvetica", 12)
    c.drawString(72, 720, "CLASSIFIED - DISSEMINATION RESTRICTED TO AUTHORIZED ENCLAVE")
    c.drawString(72, 690, "Quantum-resistant encryption applied via ML-KEM-768 & ML-DSA-65.")
    c.drawString(72, 660, "Forensic provenance will be cryptographically bound upon decryption.")
    c.drawString(72, 630, "Document Body: Project NayanX Air-Gapped Verification Protocol.")
    c.save()
    return buf.getvalue()


def test_full_attribution_lifecycle():
    print("\n--- 1. Testing System Diagnostics ---")
    resp = client.get("/status")
    assert resp.status_code == 200, resp.text
    status_data = resp.json()
    print("Status:", status_data)
    assert "ML-KEM-768" in status_data["fips_203_kem"]
    assert "ML-DSA-65" in status_data["fips_204_dsa"]

    print("\n--- 2. Enrolling 3 Recipients (Alice, Bob, Charlie) ---")
    recipients = [
        {"name": "Alice Vance", "role": "Chief Intelligence Officer", "id": "rec-alice-01"},
        {"name": "Bob Sterling", "role": "Senior Cryptanalyst", "id": "rec-bob-02"},
        {"name": "Charlie Miller", "role": "Defense Logistics Attaché", "id": "rec-charlie-03"},
    ]

    enrolled = {}
    for r in recipients:
        res = client.post("/enroll", json={"name": r["name"], "role": r["role"], "recipient_id": r["id"]})
        # If already exists from earlier test, fetch it
        if res.status_code == 409:
            res_list = client.get("/recipients").json()
            enrolled[r["id"]] = next(x for x in res_list if x["recipient_id"] == r["id"])
        else:
            assert res.status_code == 200, res.text
            enrolled[r["id"]] = res.json()
        print(f"Enrolled {r['name']} -> KEM: {enrolled[r['id']]['kem_pubkey_id']}, DSA: {enrolled[r['id']]['dsa_pubkey_id']}")

    print("\n--- 3. Encrypting Classified PDF for Alice, Bob, Charlie ---")
    pdf_bytes = generate_sample_pdf()
    pdf_b64 = b64_encode(pdf_bytes)

    enc_resp = client.post(
        "/documents/encrypt",
        json={
            "pdf_base64": pdf_b64,
            "filename": "helios_mission_dossier.pdf",
            "recipient_ids": list(enrolled.keys()),
        },
    )
    assert enc_resp.status_code == 200, enc_resp.text
    enc_data = enc_resp.json()
    print(f"Encrypted successfully. Doc Hash: {enc_data['document_hash']}")
    print(f"Generated {enc_data['recipient_count']} recipient bundles.")
    assert len(enc_data["bundles"]) == 3

    print("\n--- 4. Decrypting Separately for Each Recipient ---")
    decrypted_copies = {}
    for r_id in enrolled.keys():
        bundle = enc_data["bundles"][r_id]
        dec_resp = client.post(
            "/documents/decrypt",
            json={
                "bundle": bundle,
                "recipient_id": r_id,
                "return_pdf_base64": True,
            },
        )
        assert dec_resp.status_code == 200, dec_resp.text
        dec_data = dec_resp.json()
        decrypted_copies[r_id] = dec_data
        print(f"Decrypted for {r_id} -> WM Hash: {dec_data['watermark_hash'][:16]}... Ledger Index: {dec_data['ledger_entry']['entry_index']}")

    # Ensure all 3 watermark hashes are distinct
    wm_hashes = [d["watermark_hash"] for d in decrypted_copies.values()]
    assert len(set(wm_hashes)) == 3, "Watermark hashes must be unique per decryption event!"

    print("\n--- 5. Simulating Document Leak (Bob's Copy is Leaked) ---")
    bobs_leaked_pdf_b64 = decrypted_copies["rec-bob-02"]["watermarked_pdf_base64"]

    attr_resp = client.post(
        "/leak/attribute",
        data={"pdf_base64": bobs_leaked_pdf_b64},
    )
    assert attr_resp.status_code == 200, attr_resp.text
    attr_data = attr_resp.json()
    print("Forensic Attribution Result:")
    print(f"  - Attributed: {attr_data['attributed']}")
    print(f"  - Recipient ID: {attr_data['recipient_id']} ({attr_data['recipient_name']})")
    print(f"  - ML-DSA-65 Signature Valid: {attr_data['signature_valid']}")
    print(f"  - Merkle Chain Valid: {attr_data['chain_valid']}")
    print(f"  - Summary: {attr_data['summary']}")

    assert attr_data["attributed"] is True
    assert attr_data["recipient_id"] == "rec-bob-02"
    assert attr_data["signature_valid"] is True
    assert attr_data["chain_valid"] is True

    print("\n--- 6. Auditing Full Hash-Chained Ledger ---")
    ledger_resp = client.get("/ledger")
    assert ledger_resp.status_code == 200, ledger_resp.text
    ledger_data = ledger_resp.json()
    print(f"Ledger Chain Length: {ledger_data['chain_length']}, Valid: {ledger_data['chain_valid']}")
    assert ledger_data["chain_valid"] is True
    assert ledger_data["chain_length"] >= 4  # Genesis + Alice + Bob + Charlie

    print("\nALL VERIFICATIONS PASSED SUCCESSFULLY!")


if __name__ == "__main__":
    test_full_attribution_lifecycle()
