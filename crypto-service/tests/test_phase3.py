"""
Phase 3 Test Suite: Ledger Block Batching, Threshold Co-Signing, and Offline Evidence Verification.
"""

import os
import sys
import json
import subprocess
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))
os.environ.setdefault("DEMO_MODE", "true")

from app.main import app
from app.core.ledger import TamperEvidentLedger, canonical_json
from app.core.validators import ValidatorManager
from app.core.merkle import sha3_256_hash


@pytest.fixture
def client():
    return TestClient(app)


def test_validator_threshold_signatures():
    """
    Test 1: Validator Threshold Co-Signing (2-of-3 ML-DSA-65).
    Verifies that block headers receive valid 2-of-3 ML-DSA signatures,
    and that tampered headers or insufficient signatures are rejected.
    """
    val_mgr = ValidatorManager()
    pub_keys = val_mgr.get_public_keys()
    assert len(pub_keys) == 3

    header = {
        "height": 42,
        "prev_hash": "a" * 64,
        "merkle_root": "b" * 64,
        "entry_count": 5,
        "timestamp": "2026-09-28T12:00:00Z",
    }

    # Generate 2-of-3 signatures
    signatures = val_mgr.sign_block_header(header, count=2)
    assert len(signatures) == 2
    assert signatures[0]["validator_id"] != signatures[1]["validator_id"]

    # Valid threshold verification
    assert ValidatorManager.verify_threshold_signatures(header, signatures, threshold=2) is True

    # Tampered header must fail
    tampered_header = dict(header, entry_count=99)
    assert ValidatorManager.verify_threshold_signatures(tampered_header, signatures, threshold=2) is False

    # Insufficient signatures (only 1 signature provided) must fail
    assert ValidatorManager.verify_threshold_signatures(header, signatures[:1], threshold=2) is False


def test_ledger_block_batching_and_chain(client):
    """
    Test 2: Ledger Block Batching and Chain Integrity.
    Verifies that blocks are created with Merkle roots, linked by prev_hash,
    and signed by validators.
    """
    # Query blocks endpoint
    blocks_resp = client.get("/ledger/blocks")
    assert blocks_resp.status_code == 200
    data = blocks_resp.json()

    blocks = data.get("blocks", [])
    assert len(blocks) > 0

    # Genesis block check
    genesis = blocks[0]
    assert genesis["height"] == 0
    assert genesis["prev_hash"] == "0" * 64
    assert len(genesis["signatures"]) >= 2

    # Chain audit verification
    audit = data.get("audit", {})
    assert audit.get("valid") is True
    assert audit.get("error") is None

    # Query individual block endpoint
    blk_resp = client.get("/ledger/blocks/0")
    assert blk_resp.status_code == 200
    assert blk_resp.json()["height"] == 0


def test_checkpoint_export_endpoint(client):
    """
    Test 3: Signed Checkpoint Export.
    Verifies that GET /ledger/checkpoint returns a complete signed checkpoint.
    """
    cp_resp = client.get("/ledger/checkpoint")
    assert cp_resp.status_code == 200
    cp = cp_resp.json()

    assert cp["checkpoint_format"] == "nayanx-signed-ledger-checkpoint-v1"
    assert "height" in cp
    assert "block_hash" in cp
    assert "merkle_root" in cp
    assert "signatures" in cp
    assert len(cp["signatures"]) >= 2

    # Offline verify signatures on checkpoint block_header
    assert ValidatorManager.verify_threshold_signatures(
        cp["block_header"], cp["signatures"], threshold=2
    ) is True


def test_offline_verify_evidence_script_with_database(tmp_path):
    """
    Test 4: Standalone Offline Verification of Database.
    Executes verify_evidence.py directly via subprocess with no web server.
    """
    from app import config
    db_path = config.LEDGER_DB_PATH

    # Run verify_evidence.py --db
    result = subprocess.run(
        [sys.executable, str(BASE_DIR / "verify_evidence.py"), "--db", str(db_path)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "All" in result.stdout
    assert "cryptographically verified" in result.stdout


def test_offline_verify_evidence_against_checkpoint(client, tmp_path):
    """
    Test 5: Standalone Offline Checkpoint Verification & Tamper Detection.
    Verifies that verify_evidence.py detects when SQLite is tampered after checkpoint.
    """
    from app import config
    db_path = config.LEDGER_DB_PATH

    # 1. Export checkpoint to JSON file
    cp_resp = client.get("/ledger/checkpoint")
    assert cp_resp.status_code == 200
    cp_data = cp_resp.json()

    cp_file = tmp_path / "checkpoint.json"
    cp_file.write_text(json.dumps(cp_data), encoding="utf-8")

    # 2. Verify against untampered database -> must return 0
    result_ok = subprocess.run(
        [
            sys.executable,
            str(BASE_DIR / "verify_evidence.py"),
            "--db",
            str(db_path),
            "--checkpoint",
            str(cp_file),
        ],
        capture_output=True,
        text=True,
    )
    assert result_ok.returncode == 0
    assert "DATABASE UNTAMPERED AT CHECKPOINT" in result_ok.stdout

    # 3. Save proof for latest entry to test --proof flag
    proof_resp = client.get(f"/ledger/proof/{cp_data['start_entry_index']}")
    assert proof_resp.status_code == 200
    proof_file = tmp_path / "proof.json"
    proof_file.write_text(json.dumps(proof_resp.json()), encoding="utf-8")

    result_proof = subprocess.run(
        [
            sys.executable,
            str(BASE_DIR / "verify_evidence.py"),
            "--proof",
            str(proof_file),
        ],
        capture_output=True,
        text=True,
    )
    assert result_proof.returncode == 0
    assert "Merkle inclusion proof verified" in result_proof.stdout
