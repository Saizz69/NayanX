"""
Main FastAPI Application Entrypoint.
Forensic Document Attribution Protocol (Air-Gapped Post-Quantum MVP).
"""

from __future__ import annotations
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.routes import router
from app.core.pqc import PQCEngine
from app import config

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("crypto_service")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup diagnostics
    logger.info("Initializing Post-Quantum Forensic Attribution Service...")
    status = PQCEngine.get_engine_status()
    logger.info("PQC Status: Engine=%s, KEM=%s, DSA=%s", status["engine"], status["fips_203_kem"], status["fips_204_dsa"])
    logger.info("Data Directory: %s", config.DATA_DIR)
    yield
    logger.info("Shutting down crypto service.")


app = FastAPI(
    title="Helios Post-Quantum Forensic Attribution Engine",
    description="""
    Offline, Air-Gapped Forensic Document-Attribution System for Hackathon.
    
    Cryptographic Architecture:
    - Key Encapsulation: NIST FIPS 203 ML-KEM-768
    - Digital Signatures: NIST FIPS 204 ML-DSA-65
    - Bulk Symmetric Encryption: AES-256-GCM (NIST SP 800-38D)
    - Ledger: Hash-Chained Tamper-Evident Append-Only Store
    - Watermarking: Cryptographic Digest & Invisible PDF Metadata Injection
    """,
    version="1.0.0",
    lifespan=lifespan,
)

# Enable permissive CORS for local monorepo web app
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routes at both root and /api for maximum compatibility
app.include_router(router)
app.include_router(router, prefix="/api")


@app.get("/", tags=["Root"])
def root():
    return {
        "service": "Helios Post-Quantum Forensic Attribution Engine",
        "version": "1.0.0",
        "status": "operational",
        "pqc_standards": {
            "kem": "ML-KEM-768 (FIPS 203)",
            "dsa": "ML-DSA-65 (FIPS 204)",
            "bulk_cipher": "AES-256-GCM",
        },
        "docs_url": "/docs",
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host=config.HOST, port=config.PORT, reload=True)
