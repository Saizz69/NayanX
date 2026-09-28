"""
Phase 4 Test Suite: Attack Lab Verification, Evidence Bundle, and Section 65B(4) Certificate.
"""

import os
import sys
import io
from pathlib import Path
import pytest
from pypdf import PdfReader
from fastapi.testclient import TestClient

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))
os.environ.setdefault("DEMO_MODE", "true")

from app.main import app
from app.core.pqc import b64_encode, b64_decode
from app.core.certificate import generate_section_65b_certificate
from attack_lab import (
    create_test_environment,
    run_diffing_attack,
    run_metadata_stripping_attack,
    run_framing_attack,
    run_tampered_commitments_attack,
)


@pytest.fixture
def client():
    return TestClient(app)


def test_evidence_bundle_and_certificate_in_attribution(client):
    """
    Test 1: Verify that /leak/attribute generates a complete evidence bundle
    and Section 65B(4) certificate for an attributed document.
    """
    # 1. Enroll recipients
    r1 = client.post("/enroll", json={"recipient_id": "rec-phase4-alice", "name": "Alice Phase4", "role": "Senior Agent"}).json()
    r2 = client.post("/enroll", json={"recipient_id": "rec-phase4-bob", "name": "Bob Phase4", "role": "Field Analyst"}).json()

    # 2. Create structured document
    doc_res = client.post("/documents/structured", json={
        "document_id": "doc-phase4-evidence",
        "title": "PHASE 4 EVIDENCE EVALUATION BRIEFING",
        "classification": "TOP SECRET // SECTION 65B",
        "paragraphs": [
            "The courier will {{infiltrate|penetrate}} the facility at zero-dark-thirty.",
            "All secondary units will {{fall back|withdraw}} to checkpoint Charlie.",
            "Confirm transmission via {{frequency|channel}} seven upon egress.",
            "The team leader will {{initiate|commence}} protocol Delta-Nine on signal.",
            "Evacuate injured personnel to {{outpost|station}} Alpha without delay.",
        ],
        "recipient_ids": ["rec-phase4-alice", "rec-phase4-bob"],
        "delta_pt": 0.35,
    })
    assert doc_res.status_code == 200, doc_res.text
    doc_data = doc_res.json()
    doc_id = doc_data["document_id"]

    # 3. Decrypt document for Alice to obtain rendered watermarked PDF
    dec_res = client.post("/documents/decrypt", json={
        "recipient_id": "rec-phase4-alice",
        "document_id": doc_id,
        "session_no": 1,
        "return_pdf_base64": True,
    })
    assert dec_res.status_code == 200, dec_res.text
    pdf_b64 = dec_res.json()["watermarked_pdf_base64"]
    assert pdf_b64 is not None

    # 4. Attribute leaked document
    attr_res = client.post("/leak/attribute", json={"pdf_base64": pdf_b64})
    assert attr_res.status_code == 200, attr_res.text
    attr_data = attr_res.json()

    # Verify attribution verdict
    assert attr_data["verdict"] == "ATTRIBUTED"
    assert attr_data["attributed"] is True
    assert attr_data["recipient_id"] == "rec-phase4-alice"

    # Verify complete Phase 4 evidence bundle
    bundle = attr_data.get("evidence_bundle")
    assert bundle is not None
    assert "observed_vector" in bundle
    assert isinstance(bundle["observed_vector"], list)
    assert len(bundle["observed_vector"]) > 0

    assert "recipient_scores" in bundle
    assert "rec-phase4-alice" in bundle["recipient_scores"]
    assert bundle["recipient_scores"]["rec-phase4-alice"] > 0

    assert "calibration_table" in bundle
    assert "threshold_attributed" in bundle["calibration_table"]

    assert "inclusion_proofs" in bundle
    assert "p_commitment" in bundle["inclusion_proofs"]
    assert "codeword_commitment" in bundle["inclusion_proofs"]

    assert "block_headers" in bundle
    assert "checkpoint_reference" in bundle
    assert bundle["checkpoint_reference"] is not None
    assert "signatures" in bundle["checkpoint_reference"]

    assert "cryptographic_booleans" in bundle
    booleans = bundle["cryptographic_booleans"]
    assert booleans["p_commitment_valid"] is True
    assert booleans["codeword_commitment_valid"] is True
    assert booleans["chain_valid"] is True
    assert booleans["threshold_attributed_met"] is True

    assert "legal_notice" in bundle
    assert "LEGAL NON-DETERMINATION NOTICE" in bundle["legal_notice"]

    # Verify Section 65B(4) Certificate PDF Base64
    cert_b64 = attr_data.get("certificate_pdf_base64")
    assert cert_b64 is not None
    cert_bytes = b64_decode(cert_b64)
    assert cert_bytes.startswith(b"%PDF-")

    # Verify PDF parses correctly and contains key sections
    pdf_reader = PdfReader(io.BytesIO(cert_bytes))
    assert len(pdf_reader.pages) >= 1
    page_text = pdf_reader.pages[0].extract_text()
    assert "CERTIFICATE OF ELECTRONIC EVIDENCE" in page_text
    assert "Section 65B(4)" in page_text
    assert "LEGAL NON-DETERMINATION NOTICE" in page_text

    # Verify certificate filename
    assert attr_data["certificate_filename"] is not None
    assert attr_data["certificate_filename"].startswith("Section_65B_Certificate_")


def test_get_certificate_endpoint(client):
    """
    Test 2: Test GET /leak/certificate/{doc_id}/{recipient_id}
    """
    # 1. Successful download of Section 65B certificate
    res = client.get("/leak/certificate/doc-phase4-evidence/rec-phase4-alice")
    assert res.status_code == 200
    assert res.headers["content-type"] == "application/pdf"
    assert "attachment; filename=\"Section_65B_Certificate_doc-phase4-evidence_rec-phase4-alice.pdf\"" in res.headers.get("content-disposition", "")
    assert res.content.startswith(b"%PDF-")

    # 2. 404 for non-existent document
    res_404_doc = client.get("/leak/certificate/non-existent-doc-999/rec-phase4-alice")
    assert res_404_doc.status_code == 404

    # 3. 404 for non-existent recipient
    res_404_rec = client.get("/leak/certificate/doc-phase4-evidence/non-existent-rec-999")
    assert res_404_rec.status_code == 404


def test_section_65b_certificate_statutory_text():
    """
    Test 3: Direct unit test of generate_section_65b_certificate to ensure
    all mandatory statutory language and disclaimers are present.
    """
    evidence_data = {
        "verdict": "ATTRIBUTED",
        "recipient_id": "rec-test-01",
        "document_id": "doc-test-statutory",
        "document_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "timestamp": "2026-09-28T12:00:00Z",
        "score": 45.678,
        "thresholds": {
            "t_attributed": 20.0,
            "t_suspected": 12.0,
            "trials": 20000,
        },
    }

    pdf_bytes = generate_section_65b_certificate(evidence_data)
    assert pdf_bytes.startswith(b"%PDF-")

    reader = PdfReader(io.BytesIO(pdf_bytes))
    all_text = "".join(p.extract_text() for p in reader.pages)

    # Statutory references
    assert "CERTIFICATE OF ELECTRONIC EVIDENCE" in all_text
    assert "Section 65B(4)" in all_text
    assert "Section 63 BSA 2023" in all_text

    # Mandatory Legal Non-Determination Notice
    assert "LEGAL NON-DETERMINATION NOTICE" in all_text
    assert "does NOT constitute a judicial determination" in all_text

    # Stated Technical Limitations
    assert "TECHNICAL LIMITATIONS" in all_text
    assert "Content wording channel resists manual re-typing" in all_text
    assert "Micro-spacing layout channel is vulnerable" in all_text

    # Certification by responsible officer
    assert "CERTIFICATION BY RESPONSIBLE OFFICER" in all_text
    assert "ordinary course of operation" in all_text


def test_attack_lab_robustness_and_bounds():
    """
    Test 4: Attack Lab components verification:
    - Text diffing reveals differences between distinct recipients.
    - Metadata stripping does not impair mathematical attribution.
    - Framing attack fails (victim's score does not exceed threshold).
    - Tampered commitment is detected.
    """
    doc, p_vector, recipients = create_test_environment(num_recipients=4)
    r1 = recipients["operative-01"]
    r2 = recipients["operative-02"]

    # 1. Diffing attack test
    diff_res = run_diffing_attack(doc, r1, r2)
    assert diff_res["total_slots"] > 0
    assert diff_res["differing_slots_detected"] > 0
    # On random binary codewords with p ~ [cutoff, 1-cutoff], ~30-40% of slots differ
    assert 15.0 < diff_res["detection_percentage"] < 60.0

    # 2. Metadata stripping attack test
    strip_res = run_metadata_stripping_attack(doc, r1, p_vector)
    assert strip_res["metadata_present_before"] is True
    assert strip_res["metadata_present_after"] is False
    assert strip_res["extracted_slots"] > 0
    assert strip_res["accusation_score"] > 20.0  # Strongly positive
    assert strip_res["survived"] is True

    # 3. Framing attack test
    frame_res = run_framing_attack(doc, innocent_rec=r1, doc_secret=b"lab-secret-key-1234567890123456", p_vector=p_vector)
    assert frame_res["injected_tag_found"] is True
    assert frame_res["framing_thwarted"] is True
    assert frame_res["verdict"] == "INCONCLUSIVE"
    # The innocent victim's score on framed document is below threshold
    assert frame_res["measured_accusation_score"] < frame_res["threshold_suspected"]

    # 4. Tampered commitment test
    tamper_res = run_tampered_commitments_attack(p_vector, r1["codeword"])
    assert tamper_res["tamper_detected"] is True
    assert tamper_res["commit_reveal_matches"] is False
