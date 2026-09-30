"""
Main FastAPI Application Entrypoint.
Forensic Document Attribution Protocol (Air-Gapped Post-Quantum MVP).
"""

from __future__ import annotations
import logging
from contextlib import asynccontextmanager
import traceback
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from app.api.routes import router
from app.api.auth import auth_router
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
    # Startup diagnostics and cryptographic self-test
    logger.info("Initializing Post-Quantum Forensic Attribution Service...")
    logger.info("Running PQC Startup Self-Test (ML-KEM round-trip, ML-DSA sign/verify, tampered-signature rejection)...")
    try:
        self_test_res = PQCEngine.run_self_test()
        app.state.self_test = self_test_res
        logger.info("PQC Startup Self-Test PASSED: %s", self_test_res)
    except Exception as e:
        logger.critical("FATAL: PQC Startup Self-Test FAILED: %s", e)
        raise RuntimeError(f"Service startup aborted due to cryptographic self-test failure: {e}") from e

    status = PQCEngine.get_engine_status()
    logger.info("PQC Status: Engine=%s (%s), KEM=%s, DSA=%s", status["engine"], status["engine_note"], status["fips_203_kem"], status["fips_204_dsa"])
    logger.info("Data Directory: %s", config.DATA_DIR)
    yield
    logger.info("Shutting down crypto service.")



app = FastAPI(
    title="WebEye Post-Quantum Forensic Attribution Engine",
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

# Enable permissive CORS for local monorepo web app, including Private Network Access (PNA)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    allow_private_network=True,
)


@app.middleware("http")
async def add_private_network_headers(request, call_next):
    response = await call_next(request)
    if "origin" in request.headers:
        response.headers["Access-Control-Allow-Private-Network"] = "true"
    return response


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    tb = traceback.format_exc()
    logger.error("Unhandled exception on %s: %s\n%s", request.url, exc, tb)
    return JSONResponse(
        status_code=500,
        content={"detail": str(exc), "traceback": tb},
    )

# Register routes at both root and /api for maximum compatibility
app.include_router(auth_router)
app.include_router(auth_router, prefix="/api")
app.include_router(router)
app.include_router(router, prefix="/api")


@app.get("/", tags=["Root"])
def root():
    return {
        "service": "WebEye Post-Quantum Forensic Attribution Engine",
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
