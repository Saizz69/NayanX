# WebEye — Air-Gapped Forensic Document-Attribution System

An offline, air-gapped forensic document-attribution and post-quantum provenance protocol designed for defense, intelligence, and high-security enterprise enclaves.

---

## Architecture Overview

```
WebEye/
├── crypto-service/          # Python 3.12/3.13 + FastAPI Post-Quantum Cryptographic Engine
│   ├── app/
│   │   ├── core/
│   │   │   ├── pqc.py       # ML-KEM-768 (FIPS 203) & ML-DSA-65 (FIPS 204) engine
│   │   │   ├── symmetric.py # AES-256-GCM + HKDF-SHA256 key-wrapping
│   │   │   ├── keystore.py  # Local authenticated AES-256-GCM vault (HSM/TPM drop-in)
│   │   │   ├── watermark.py # Invisible PDF metadata/XMP & steganographic anchor
│   │   │   └── ledger.py    # Tamper-evident hash-chained append-only Merkle ledger
│   │   ├── api/routes.py    # REST API endpoints (/enroll, /encrypt, /decrypt, /leak/attribute, /ledger)
│   │   ├── models/          # Pydantic request & response schemas
│   │   └── main.py          # FastAPI application entrypoint with CORS & diagnostics
│   ├── demo_seed.py         # End-to-end hackathon demonstration script
│   ├── test_api.py          # Automated integration & unit test suite
│   └── requirements.txt
│
└── web/                     # Next.js 16 (App Router, TypeScript) WebEye Dashboard UI
    ├── src/app/
    │   ├── page.tsx         # WebEye Dark Obsidian interactive dashboard & JSON inspector
    │   ├── layout.tsx       # Root layout & typography
    │   └── globals.css      # Custom Vanilla CSS tokens, neon glow, and glassmorphism
    └── package.json
```

---

## Cryptographic Standards & Specifications

| Component | Standard / Algorithm | Security Level | Purpose |
|---|---|---|---|
| **Key Encapsulation** | **NIST FIPS 203 (ML-KEM-768)** | Category 3 (192-bit classical, 128-bit quantum) | Asymmetric encapsulation of bulk document keys |
| **Digital Signatures** | **NIST FIPS 204 (ML-DSA-65)** | Category 3 (SHA3-384 collision resistance) | Non-repudiation signing of decryption records |
| **Bulk Encryption** | **AES-256-GCM (NIST SP 800-38D)** | 256-bit symmetric security | Authenticated payload encryption with 128-bit tag |
| **Key Derivation** | **HKDF-SHA256 (RFC 5869)** | 256-bit entropy expansion | Derives key-wrapping keys from ML-KEM shared secrets |
| **Audit Ledger** | **Merkle Hash Chain (SHA-256)** | Pre-image & collision resistant | Cryptographic blockheader chaining with previous hash pointers |
| **Watermarking** | **Forensic Digest + PDF XMP/Info** | SHA-256 canonical hash | Invisible forensic mark bound to recipient, nonce & timestamp |

---

## Quickstart Guide

### 1. Start the Crypto-Service Backend
```bash
cd crypto-service
python -m pip install -r requirements.txt
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```
- API Docs: `http://127.0.0.1:8000/docs`
- Diagnostics: `http://127.0.0.1:8000/status`

### 2. Start the Helios Web Dashboard
```bash
cd web
npm run dev -- -p 3000
```
- Open browser at: `http://localhost:3000`

### 3. Run the Automated Demo Seed Script
```bash
cd crypto-service
python demo_seed.py
```
This script automatically:
1. Enrolls 3 officers: Alice Vance, Bob Sterling, Charlie Miller (generates ML-KEM-768 & ML-DSA-65 keypairs).
2. Encrypts a sample classified dossier via AES-256-GCM with ML-KEM encapsulated keys.
3. Decrypts separately for each recipient, producing 3 visually identical but differently-watermarked copies.
4. Simulates a leak of Bob's copy.
5. Invokes `POST /leak/attribute` to extract the watermark, verify the ML-DSA signature, verify the hash chain, and cryptographically attribute the leak to Bob.

---

## Production & Air-Gapped Scoping Decisions (For Judges)

### 1. Hardware Security Modules (HSM / TPM 2.0)
* **MVP Implementation:** Keys are sealed in a local software vault encrypted with AES-256-GCM using PBKDF2-HMAC-SHA256 key derivation.
* **Production Architecture:**
  - The software vault is a placeholder for a **PKCS#11 compliant Hardware Security Module** (e.g., Thales Luna PCIe or YubiHSM2 conforming to FIPS 140-3 Level 3).
  - Private key material never leaves the silicon boundary. The `PQCEngine.kem_decapsulate` and `PQCEngine.dsa_sign` calls are directed to hardware tokens via PKCS#11 `C_Sign` and `C_DeriveKey`.
  - On tactical edge devices, platform configuration registers (PCRs) in a **TPM 2.0** chip seal the vault passphrase, rendering keys inaccessible if firmware or kernel integrity is violated.

### 2. Distributed Consensus Ledger (Hyperledger Fabric vs Local Chain)
* **MVP Implementation:** Append-only SQLite & JSONL database where each block stores `entry_hash = SHA256(index || timestamp || previous_hash || canonical_record || ML-DSA-sig)`.
* **Production Architecture:**
  - In a joint-forces or multi-agency environment, a local database is vulnerable to a compromised host root administrator retroactively altering records.
  - Production deployments drop in **Hyperledger Fabric smart contracts (chaincode)** with Raft/BFT consensus across separate air-gapped enclaves.
  - Private Data Collections (PDC) ensure confidential recipient identities are compartmentalized while all nodes validate the cryptographic Merkle chain.

### 3. Collusion-Resistant Watermarking (Boneh-Shaw / Tardos Codes)
* **MVP Implementation:** Watermark is computed as `hash(recipient_id + session_nonce + timestamp + document_hash)` and embedded into PDF Info dictionaries, XMP metadata, and trailing structural anchors.
* **Production Architecture:**
  - If malicious recipients collude (e.g., Alice and Bob compare their PDFs to find differing bits), simple metadata watermarks could be identified.
  - Production deployments use **Boneh-Shaw fingerprinting codes** or **Tardos codes** combined with **Transform-Domain Spread-Spectrum Steganography (DWT/DCT)**.
  - Bits are modulated across discrete wavelet coefficients in embedded fonts/vector art using Quantization Index Modulation (QIM), surviving rasterization, OCR, and physical print-and-scan attacks.
