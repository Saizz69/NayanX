"""
Phase 1 Unit & Integration Test Suite:
- Tardos fingerprinting code properties (deterministic p-vector, symmetric scoring, unbiasedness)
- Monte Carlo calibration (>=20,000 trials, false-accusation targets)
- Structured document parsing & slot capacity (GET /documents/{id}/capacity)
- Real extraction of wording & layout channels from rendered PDF bytes
- Pre-distribution ledger commitments (H_p, C_r)
- Session policy enforcement (max_sessions = 2)
- Attribution verdicts (ATTRIBUTED, SUSPECTED, INCONCLUSIVE) and framing resistance
"""

import io
import os
import sys
import math
import secrets
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

# Ensure crypto-service root is in sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))
os.environ.setdefault("DEMO_MODE", "true")

from app.main import app
from app.core.pqc import b64_encode, b64_decode
from app.core.tardos import (
    generate_p_vector,
    compute_p_commitment,
    derive_recipient_codeword,
    compute_codeword_commitment,
    compute_accusation_score,
    calibrate_thresholds,
    estimate_collusion_capacity,
)
from app.core.document_variants import StructuredDocument
from app.core.extractor import extract_document_slots
from app.core.watermark import embed_watermark_in_pdf


client = TestClient(app)


def test_tardos_mathematical_properties():
    """Verify p-vector bounds, deterministic derivation, and symmetric scoring."""
    doc_secret = b"test_secret_for_tardos_math_001"
    num_slots = 50
    t = 0.05
    p_vec = generate_p_vector(doc_secret, num_slots, cutoff_t=t)

    assert len(p_vec) == num_slots
    # All p_i in [t, 1-t]
    for p_i in p_vec:
        assert t <= p_i <= (1.0 - t)

    # Determinism
    p_vec2 = generate_p_vector(doc_secret, num_slots, cutoff_t=t)
    assert p_vec == p_vec2

    # Symmetric Tardos scoring properties
    p_sample = [0.2, 0.5, 0.8]
    # Match: y=1, x=1 -> +sqrt((1-p)/p) = +2.0
    # Match: y=0, x=0 -> +sqrt(p/(1-p)) = +1.0
    # Erasure: y=None -> skipped
    obs = [1, 0, None]
    cand = [1, 0, 1]
    score = compute_accusation_score(cand, obs, p_sample)
    expected_score = math.sqrt((1 - 0.2) / 0.2) + math.sqrt(0.5 / (1 - 0.5))
    assert abs(score - expected_score) < 1e-6

    # Mismatch: y=1, x=0 -> -sqrt(p/(1-p)) = -sqrt(0.2/0.8) = -0.5
    cand_mismatch = [0, 1, 0]
    score_mismatch = compute_accusation_score(cand_mismatch, obs, p_sample)
    expected_mismatch = -math.sqrt(0.2 / 0.8) - math.sqrt((1 - 0.5) / 0.5)
    assert abs(score_mismatch - expected_mismatch) < 1e-6


def test_tardos_monte_carlo_calibration():
    """Verify Monte Carlo threshold calibration runs >= 20,000 trials and yields valid percentiles."""
    doc_secret = b"doc_secret_for_calibration_002"
    p_vec = generate_p_vector(doc_secret, 60, cutoff_t=0.05)

    calib = calibrate_thresholds(
        p_vector=p_vec,
        num_trials=20_000,
        max_sessions=2,
        target_attributed_fpr=1e-3,
        target_suspected_fpr=1e-2,
    )

    assert calib["num_trials"] >= 20_000
    assert calib["effective_slots"] == 60
    # Threshold for 1e-3 (99.9th percentile) must be strictly greater than for 1e-2 (99th percentile)
    assert calib["threshold_attributed"] > calib["threshold_suspected"]
    assert calib["threshold_suspected"] > 0
    # Innocent candidate scores are centered near 0
    assert abs(calib["mean_innocent"]) < 1.0


def test_structured_document_slots_and_capacity():
    """Verify parsing of wording and layout slots and GET /documents/{id}/capacity endpoint."""
    raw_source = {
        "title": "CLASSIFIED DISPATCH 2026",
        "paragraphs": [
            "The {{preliminary|initial}} report indicates {{routine|standard}} telemetry data.",
            "Immediate {{verification|confirmation}} is required for {{sector|region}} Alpha.",
            "Field operatives must {{maintain|observe}} operational silence during {{transit|deployment}}."
        ]
    }
    doc = StructuredDocument(raw_source, delta_pt=0.35)
    cap = doc.get_capacity(target_fpr=1e-3)

    assert cap["wording_slots"] == 6
    assert cap["layout_slots"] > 10
    assert cap["total_slots"] == cap["wording_slots"] + cap["layout_slots"]
    assert cap["largest_collusion_c"] >= 1


def test_real_extraction_wording_and_layout_channels():
    """Verify byte-driven extraction of both wording and layout channels from rendered PDF."""
    raw_source = {
        "title": "SECURE TELEMETRY REPORT",
        "paragraphs": [
            "The {{preliminary|initial}} report indicates {{routine|standard}} telemetry.",
            "Immediate {{verification|confirmation}} is required for {{sector|region}} Alpha."
        ]
    }
    doc = StructuredDocument(raw_source, delta_pt=0.35)
    ref_pdf = doc.render_reference_layout()

    # Create test codeword: specific wording and layout bits
    w_count = len(doc.wording_slots)
    l_count = doc.layout_slots_count
    assigned_wording = [1, 0, 1, 0]  # initial, routine, confirmation, sector
    assigned_layout = [1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1]
    codeword = assigned_wording + assigned_layout[:l_count]

    rendered_pdf = doc.render_pdf(codeword)
    extraction = extract_document_slots(rendered_pdf, doc, ref_pdf)

    # Verify extracted vector matches assigned codeword with 0 erasures
    assert extraction["total_erased"] == 0
    assert extraction["erasure_rate"] == 0.0
    assert extraction["observed_vector"] == codeword


def test_end_to_end_tardos_lifecycle_and_verdicts():
    """Test full structured document lifecycle: create -> enroll -> decrypt sessions -> leak attribute."""
    # 1. Enroll Alice and Bob
    rec_alice = client.post("/enroll", json={"name": "Alice Tardos", "role": "Analyst", "recipient_id": "rec-tardos-alice"}).json()
    rec_bob = client.post("/enroll", json={"name": "Bob Tardos", "role": "Cryptanalyst", "recipient_id": "rec-tardos-bob"}).json()

    # 2. Create structured document
    doc_req = {
        "document_id": "doc-tardos-test-01",
        "title": "POST-QUANTUM INTEL BRIEFING",
        "paragraphs": [
            "The {{preliminary|initial}} report indicates {{routine|standard}} telemetry.",
            "Immediate {{verification|confirmation}} is required for {{sector|region}} Alpha.",
            "Special operatives should {{maintain|observe}} strict protocol during {{transit|deployment}}."
        ],
        "delta_pt": 0.35,
        "cutoff_t": 0.05,
        "recipient_ids": ["rec-tardos-alice", "rec-tardos-bob"],
        "max_sessions": 2,
    }
    create_resp = client.post("/documents/structured", json=doc_req)
    assert create_resp.status_code == 200, create_resp.text
    create_data = create_resp.json()
    assert create_data["status"] == "created"
    assert "p_commitment" in create_data

    # 3. Check capacity endpoint
    cap_resp = client.get(f"/documents/{doc_req['document_id']}/capacity")
    assert cap_resp.status_code == 200
    cap_data = cap_resp.json()
    assert cap_data["document_id"] == doc_req["document_id"]
    assert cap_data["total_slots"] > 10

    # 4. Decrypt Bob's copy (Session 1)
    dec_resp_bob = client.post(
        "/documents/decrypt",
        json={
            "document_id": doc_req["document_id"],
            "recipient_id": "rec-tardos-bob",
            "session_no": 1,
            "return_pdf_base64": True,
        }
    )
    assert dec_resp_bob.status_code == 200, dec_resp_bob.text
    dec_data_bob = dec_resp_bob.json()
    bobs_pdf_b64 = dec_data_bob["watermarked_pdf_base64"]

    # 5. Attribute Bob's leaked document
    attr_resp = client.post("/leak/attribute", data={"pdf_base64": bobs_pdf_b64})
    assert attr_resp.status_code == 200, attr_resp.text
    attr_data = attr_resp.json()

    print("Attribution verdict:", attr_data["verdict"])
    print("Candidate scores:", attr_data["candidate_scores"])
    print("Thresholds:", attr_data["thresholds"])

    assert attr_data["verdict"] == "ATTRIBUTED"
    assert attr_data["attributed"] is True
    assert attr_data["recipient_id"] == "rec-tardos-bob"
    assert attr_data["p_commitment_valid"] is True
    assert attr_data["codeword_commitment_valid"] is True
    assert attr_data["candidate_scores"]["rec-tardos-bob"] > attr_data["thresholds"]["threshold_attributed"]


def test_session_policy_enforcement():
    """Verify max_sessions limit is enforced per (recipient, doc)."""
    doc_id = "doc-tardos-test-01"
    # Session 2 decrypt succeeds
    s2_resp = client.post(
        "/documents/decrypt",
        json={"document_id": doc_id, "recipient_id": "rec-tardos-bob", "session_no": 2}
    )
    assert s2_resp.status_code == 200

    # Session 3 decrypt must fail with 403 Forbidden
    s3_resp = client.post(
        "/documents/decrypt",
        json={"document_id": doc_id, "recipient_id": "rec-tardos-bob", "session_no": 3}
    )
    assert s3_resp.status_code == 403
    assert "Session policy violation" in s3_resp.json()["detail"]


def test_framing_attack_resistance():
    """Framing test: Unmarked/clean file with Alice's copied metadata must yield INCONCLUSIVE."""
    doc_id = "doc-tardos-test-01"
    # Decrypt Alice's copy
    dec_resp_alice = client.post(
        "/documents/decrypt",
        json={"document_id": doc_id, "recipient_id": "rec-tardos-alice", "session_no": 1}
    )
    assert dec_resp_alice.status_code == 200

    # Create an unwatermarked clean PDF and inject ONLY Alice's copied metadata
    from reportlab.pdfgen import canvas
    buf = io.BytesIO()
    c = canvas.Canvas(buf)
    c.drawString(72, 700, "Clean unwatermarked text with no variant slots.")
    c.save()
    clean_bytes = buf.getvalue()

    # Frame Alice by injecting her metadata into the clean PDF
    framed_pdf = embed_watermark_in_pdf(clean_bytes, {
        "recipient_id": "rec-tardos-alice",
        "document_hash": "0" * 64,
        "watermark_hash": "a" * 64,
        "timestamp": "2026-09-28T00:00:00Z",
    })

    attr_framed = client.post("/leak/attribute", data={"pdf_base64": b64_encode(framed_pdf)})
    assert attr_framed.status_code == 200
    framed_data = attr_framed.json()

    # Must NOT attribute to Alice because content-level slot scores are zero/inconclusive
    assert framed_data["verdict"] == "INCONCLUSIVE"
    assert framed_data["attributed"] is False
