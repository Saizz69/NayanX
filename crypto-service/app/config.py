"""
Configuration for Forensic Crypto Service.
"""

from __future__ import annotations
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

LEDGER_DB_PATH = DATA_DIR / "ledger.db"
KEYSTORE_DIR = DATA_DIR / "keystore"
SAMPLE_DOCS_DIR = DATA_DIR / "samples"
SAMPLE_DOCS_DIR.mkdir(parents=True, exist_ok=True)

VAULT_PASSPHRASE = os.environ.get("PQC_VAULT_PASSPHRASE", "airgap-helios-vault-2026-fips-compliant")
HOST = os.environ.get("CRYPTO_SERVICE_HOST", "127.0.0.1")
PORT = int(os.environ.get("CRYPTO_SERVICE_PORT", "8000"))
