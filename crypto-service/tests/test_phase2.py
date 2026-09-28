"""
Phase 2 Test Suite: Commit-Before-Release, Selective Key Release, and Merkle Proofs.
"""

import os
import sys
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from cryptography.exceptions import InvalidTag

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))
os.environ.setdefault("DEMO_MODE", "true")

from app.main import app
from app.core.pqc import PQCEngine, b64_encode, b64_decode
from app.core.merkle import MerkleTree, verify_merkle_proof, sha3_256_hash
from app.core.selective_encryption import (
    generate_aes_key,
    encrypt_block_gcm,
    decrypt_block_gcm,
    SelectiveDocumentEncryptor,
)


@pytest.fixture
def client():
    return TestClient(app)


def test_selective_key_restriction():
    """
    Test 1: Selective Key Release Restriction.
    Verifies that a recipient receives ONLY the key for their assigned alternate,
    and mathematically cannot decrypt the unassigned alternate.
    """
    wording_slots = [
        (0, "operation vanguard", "operation sentinel"),
        (1, "covert assets", "clandestine operatives"),
        (2, "deploy instantly", "mobilize immediately"),
    ]
    common_blocks = ["TOP SECRET DOCUMENT HEADER", "AUTHORIZED PERSONNEL ONLY"]
    
    encryptor = SelectiveDocumentEncryptor(
        doc_id="doc-selective-001",
        wording_slots=wording_slots,
        common_blocks=common_blocks,
    )

    shared_secret = b"shared_secret_32_bytes_long!!!!"
    # Recipient assigned bits: slot 0 -> bit 1, slot 1 -> bit 0, slot 2 -> bit 1
    recipient_bits = [1, 0, 1]

    bundle = encryptor.assemble_recipient_key_bundle(recipient_bits, shared_secret)
    unwrapped = SelectiveDocumentEncryptor.unwrap_recipient_key_bundle(bundle, shared_secret)

    # 1. Recipient can decrypt common block
    decrypted_common = decrypt_block_gcm(
        encryptor.encrypted_common[0],
        unwrapped["k_common"],
        aad=b"doc:doc-selective-001|common",
    )
    assert decrypted_common == "TOP SECRET DOCUMENT HEADER"

    # 2. Recipient can decrypt assigned variant for slot 0 (variant 1)
    slot0_key = unwrapped["slots"]["0"]["key"]
    assert unwrapped["slots"]["0"]["assigned_variant"] == 1
    decrypted_alt1 = decrypt_block_gcm(
        encryptor.encrypted_alternates[0][1],
        slot0_key,
        aad=b"doc:doc-selective-001|slot:0|variant:1",
    )
    assert decrypted_alt1 == "operation sentinel"

    # 3. Recipient CANNOT decrypt unassigned variant for slot 0 (variant 0)
    # The key for variant 0 is NOT in unwrapped["slots"]["0"]
    # If they attempt to decrypt variant 0's ciphertext using slot0_key (variant 1 key):
    with pytest.raises(InvalidTag):
        decrypt_block_gcm(
            encryptor.encrypted_alternates[0][0],
            slot0_key,
            aad=b"doc:doc-selective-001|slot:0|variant:0",
        )

    # 4. AAD tamper detection: modifying AAD fails decryption even with correct key
    with pytest.raises(InvalidTag):
        decrypt_block_gcm(
            encryptor.encrypted_alternates[0][1],
            slot0_key,
            aad=b"doc:doc-selective-001|slot:0|variant:0",  # tampered AAD
        )


def test_merkle_tree_proof_generation_and_offline_verification():
    """
    Test 2: SHA3-256 Merkle Tree Construction and Inclusion Proofs.
    Verifies offline verification with no server running.
    """
    leaves = [
        sha3_256_hash(f"leaf_data_block_{i}".encode("utf-8"))
        for i in range(11)  # odd number of leaves tests duplication behavior
    ]
    tree = MerkleTree(leaves)

    assert tree.root is not None
    assert len(tree.root) == 64

    # Verify proof for each leaf offline
    for i, leaf in enumerate(leaves):
        proof = tree.get_proof(i)
        is_valid = verify_merkle_proof(leaf, proof, tree.root)
        assert is_valid, f"Merkle proof verification failed for leaf {i}"

    # Tampered leaf hash must fail verification
    tampered_leaf = sha3_256_hash(b"attacker_modified_leaf")
    proof_0 = tree.get_proof(0)
    assert not verify_merkle_proof(tampered_leaf, proof_0, tree.root)


def test_ordered_decrypt_pipeline_step_events(client):
    """
    Test 3: Decrypt Pipeline Ordered 7 Steps.
    Verifies that POST /documents/decrypt executes and reports all 7 steps in order:
    authenticate_recipient -> session_policy_check -> derive_codeword_and_commitment
    -> append_ledger_record -> obtain_merkle_proof -> verify_merkle_proof -> unwrap_keys_and_render
    """
    # 1. Enroll recipient
    enroll_resp = client.post("/enroll", json={"name": "Major Sarah Connor", "role": "Commander"})
    assert enroll_resp.status_code == 200
    r_id = enroll_resp.json()["recipient_id"]

    # 2. Create structured document
    doc_payload = {
        "title": "TOP SECRET MISSION REPORT",
        "paragraphs": [
            "Primary operative will {{infiltrate|penetrate}} the facility silently.",
            "Maintain radio silence until {{extraction|rendezvous}} point is reached.",
        ],
        "recipient_ids": [r_id],
        "max_sessions": 2,
    }
    create_resp = client.post("/documents/structured", json=doc_payload)
    assert create_resp.status_code == 200
    doc_id = create_resp.json()["document_id"]

    # 3. Decrypt document
    decrypt_resp = client.post(
        "/documents/decrypt",
        json={"document_id": doc_id, "recipient_id": r_id, "session_no": 1},
    )
    assert decrypt_resp.status_code == 200
    data = decrypt_resp.json()

    # Verify step_events
    steps = data.get("step_events", [])
    assert len(steps) == 7

    step_names = [s["step"] for s in steps]
    expected_order = [
        "authenticate_recipient",
        "session_policy_check",
        "derive_codeword_and_commitment",
        "append_ledger_record",
        "obtain_merkle_proof",
        "verify_merkle_proof",
        "unwrap_keys_and_render",
    ]
    assert step_names == expected_order

    for s in steps:
        assert s["status"] == "success"

    # Verify inclusion proof is returned and valid
    inc_proof = data.get("inclusion_proof")
    assert inc_proof is not None
    assert "leaf_hash" in inc_proof
    assert "root_hash" in inc_proof
    assert "proof" in inc_proof

    # Offline verify proof
    valid_proof = verify_merkle_proof(
        inc_proof["leaf_hash"], inc_proof["proof"], inc_proof["root_hash"]
    )
    assert valid_proof is True


def test_fail_closed_gate(client):
    """
    Test 4: Fail-Closed Gate on Ledger Failure.
    Verifies that if ledger commit fails (tested via force_ledger_failure=True),
    zero bytes and zero keys are released, returning HTTP 503.
    """
    # 1. Enroll recipient
    enroll_resp = client.post("/enroll", json={"name": "Agent Marcus Wright", "role": "Infiltrator"})
    assert enroll_resp.status_code == 200
    r_id = enroll_resp.json()["recipient_id"]

    # 2. Create structured document
    doc_payload = {
        "title": "CLASSIFIED EXPERIMENTAL PROTOCOL",
        "paragraphs": [
            "Test unit will {{execute|perform}} sequence Alpha.",
        ],
        "recipient_ids": [r_id],
        "max_sessions": 2,
    }
    create_resp = client.post("/documents/structured", json=doc_payload)
    assert create_resp.status_code == 200
    doc_id = create_resp.json()["document_id"]

    # 3. Decrypt with force_ledger_failure=True
    decrypt_resp = client.post(
        "/documents/decrypt",
        json={
            "document_id": doc_id,
            "recipient_id": r_id,
            "session_no": 1,
            "force_ledger_failure": True,
        },
    )
    # Must fail closed: HTTP 503
    assert decrypt_resp.status_code == 503
    error_detail = decrypt_resp.json().get("detail", "")
    assert "Zero document bytes released" in error_detail


def test_get_ledger_proof_endpoint(client):
    """
    Test 5: GET /ledger/proof/{entry_id} endpoint.
    Verifies that clients can retrieve and verify Merkle proofs for any entry.
    """
    # Query latest entry from ledger
    ledger_resp = client.get("/ledger")
    assert ledger_resp.status_code == 200
    entries = ledger_resp.json()["entries"]
    assert len(entries) > 0

    latest_entry = entries[-1]
    entry_index = latest_entry["entry_index"]

    # Request proof by entry index
    proof_resp = client.get(f"/ledger/proof/{entry_index}")
    assert proof_resp.status_code == 200
    proof_data = proof_resp.json()

    assert proof_data["entry_index"] == entry_index
    assert proof_data["verified"] is True
    assert proof_data["leaf_hash"] == latest_entry["entry_hash"]

    # Verify offline
    assert verify_merkle_proof(
        proof_data["leaf_hash"], proof_data["proof"], proof_data["root_hash"]
    )
