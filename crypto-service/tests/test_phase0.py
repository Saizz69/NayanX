"""
Phase 0 Unit & Regression Test Suite:
- Vault passphrases from env vars & fail-loud outside DEMO_MODE
- Startup PQC self-test (KEM round-trip, DSA sign/verify, tampered-signature rejection)
- GET /status engine_note and self-test verification
- .gitignore protection for sensitive data directories
"""

import os
import sys
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

# Ensure crypto-service root is in sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

# Default to DEMO_MODE=true for test harness
os.environ.setdefault("DEMO_MODE", "true")

from app.core.pqc import PQCEngine
from app.main import app
import app.config as config



client = TestClient(app)


def test_pqc_engine_status_and_note():
    """Verify that PQCEngine exposes engine type and engine note."""
    status = PQCEngine.get_engine_status()
    assert "engine" in status
    assert "engine_note" in status
    assert "pure-Python reference implementation, not constant-time" in status["engine_note"] or status["native_oqs_active"]


def test_pqc_self_test_execution():
    """Verify that PQCEngine.run_self_test passes cleanly."""
    results = PQCEngine.run_self_test()
    assert results["kem_roundtrip"] is True
    assert results["dsa_sign_verify"] is True
    assert results["tampered_rejection"] is True


def test_tampered_signature_explicit_rejection():
    """Explicitly verify that tampered signatures are rejected by ML-DSA-65."""
    pk, sk = PQCEngine.generate_dsa_keypair()
    msg = b"Forensic Chain Custody Verification Vector"
    valid_sig = PQCEngine.dsa_sign(sk, msg)
    assert PQCEngine.dsa_verify(pk, msg, valid_sig) is True

    # Tamper with 1 byte in the signature
    tampered_sig = bytearray(valid_sig)
    tampered_sig[10] ^= 0x5A
    assert PQCEngine.dsa_verify(pk, msg, bytes(tampered_sig)) is False

    # Tamper with the message
    assert PQCEngine.dsa_verify(pk, b"Forged message content", valid_sig) is False


def test_api_status_endpoint_reports_hygiene():
    """Verify GET /status response schema contains engine_note and self_test results."""
    resp = client.get("/status")
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert "engine" in data
    assert "engine_note" in data
    assert "pure-Python reference implementation, not constant-time" in data["engine_note"] or data["native_oqs_active"]
    assert "self_test" in data
    assert data["self_test"] is not None
    assert data["self_test"]["kem_roundtrip"] is True
    assert data["self_test"]["dsa_sign_verify"] is True
    assert data["self_test"]["tampered_rejection"] is True


def test_vault_passphrase_fail_loud_outside_demo_mode(monkeypatch):
    """Verify that missing PQC_VAULT_PASSPHRASE outside DEMO_MODE fails loudly."""
    monkeypatch.delenv("PQC_VAULT_PASSPHRASE", raising=False)
    monkeypatch.setenv("DEMO_MODE", "false")

    # In a subprocess or dynamically evaluated context
    import importlib
    with pytest.raises(RuntimeError) as exc_info:
        # Reloading config should trigger the loud failure
        importlib.reload(config)
    assert "CRITICAL SECURITY CONFIGURATION ERROR" in str(exc_info.value)

    # Restoring DEMO_MODE should allow fallback with warning
    monkeypatch.setenv("DEMO_MODE", "true")
    importlib.reload(config)
    assert config.VAULT_PASSPHRASE is not None


def test_gitignore_protects_data():
    """Verify that root and crypto-service .gitignore files protect data directories."""
    repo_root = BASE_DIR.parent
    root_gitignore = (repo_root / ".gitignore").read_text(encoding="utf-8")
    assert "data/" in root_gitignore
    assert "*.bin" in root_gitignore
    assert "*.db" in root_gitignore

    cs_gitignore = (BASE_DIR / ".gitignore").read_text(encoding="utf-8")
    assert "data/" in cs_gitignore
    assert "*.bin" in cs_gitignore
