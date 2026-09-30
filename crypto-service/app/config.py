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

import logging

logger = logging.getLogger("crypto_service.config")

# Air-Gapped Security: Vault Passphrase Configuration
DEMO_MODE = os.environ.get("DEMO_MODE", "true").lower() in ("true", "1", "yes")

_env_passphrase = os.environ.get("PQC_VAULT_PASSPHRASE")
if not _env_passphrase:
    if DEMO_MODE:
        VAULT_PASSPHRASE = "airgap-helios-vault-2026-fips-compliant"
        logger.info(
            "PQC_VAULT_PASSPHRASE not specified; DEMO_MODE active with default air-gapped demo passphrase."
        )
    else:
        raise RuntimeError(
            "CRITICAL SECURITY CONFIGURATION ERROR: 'PQC_VAULT_PASSPHRASE' environment variable "
            "is not set. Set PQC_VAULT_PASSPHRASE in the environment, or enable DEMO_MODE=true for testing."
        )
else:
    VAULT_PASSPHRASE = _env_passphrase.strip()

HOST = os.environ.get("CRYPTO_SERVICE_HOST", "127.0.0.1")
PORT = int(os.environ.get("CRYPTO_SERVICE_PORT", "8000"))

