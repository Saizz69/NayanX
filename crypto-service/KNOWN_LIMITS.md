# WebEye: Cryptographic & Forensic Limitations (`KNOWN_LIMITS.md`)

This document discloses the exact technical, mathematical, and operational limitations of the WebEye air-gapped forensic document attribution system. In compliance with strict forensic engineering standards, no marketing claims of "100% security", "zero false positives", or "absolute tamper-proof guarantees" are made. Every metric in WebEye is bounded by empirical calibration and stated assumptions.

---

## 1. Dual-Channel Robustness: Content Wording vs. Micro-Layout Spacing

WebEye embeds forensic fingerprinting across two distinct physical channels:
1. **Content Wording Channel (`{{a|b}}` synonym slots):**
   - **Resilience:** Survives manual re-typing, text copy-pasting, document re-formatting, machine translation, and optical character recognition (OCR).
   - **Limitation:** Can be modified if an adversary manually edits or removes specific sentences, or if two colluders detect wording differences through text diffing.

2. **Micro-Layout Spacing Channel ($+\delta$ pt inter-word gaps):**
   - **Resilience:** Invisible to the naked human eye ($+\delta \approx 0.35$ pt), invariant to font resizing and word shifts from earlier paragraphs, and persists through native PDF rendering, printing, and digital PDF forwarding.
   - **Limitation (Out of Scope):** Destroyed if the document is re-typeset with different fonts/margins, copied into raw plaintext editors (e.g. Notepad), or rasterized and re-generated through an OCR pipeline. Layout spacing analysis requires preservation of the underlying PDF vector text stream and positioning operators (`TJ`/`Tj`).

---

## 2. Mathematical Collusion Capacity Bounds (Tardos Code)

The symmetric Tardos fingerprinting code provides provable bounds against coalition attacks of size $c$, where the required codeword length $L$ scales asymptotically as:

$$L \ge C \cdot c^2 \cdot \ln(1 / \epsilon_1)$$

where:
- $c$ is the coalition size (number of colluding recipients),
- $\epsilon_1$ is the target false-positive rate (default: $\alpha \le 10^{-3}$),
- $C \approx 2 \pi^2 \approx 19.74$ is the Tardos scaling constant.

### Practical Impact:
- In short briefing documents with limited wording slots (e.g., $L = 30$ to $80$ slots), the system is robust against individual leaks ($c = 1$) and pairwise collusion ($c = 2$).
- High collusion resistance ($c \ge 5$ or $c \ge 10$) mathematically requires longer documents or higher slot density ($L \ge 500$ to $2,000$ slots). If an adversary forms a coalition exceeding the document's calibrated capacity, the accusation scores degrade toward inconclusive thresholds.

---

## 3. Server-Side Key Gate vs. Hardware-Isolated Enclaves

### Demonstration Architecture:
In this hackathon reference implementation, private vaults, ML-KEM private keys, and selective AES-GCM unwrapping execute server-side in a Python service. The commit-before-release gate enforces that ledger commitments, Merkle proofs, and dual signatures are recorded prior to key release.

### Production Requirement:
A server-side gate cannot prevent an administrative compromise of the host server itself. In an enterprise or classified defense deployment:
- Key decapsulation (ML-KEM-768), key unwrapping, and PDF rasterization **must** occur inside the hardware-backed secure boundary of the recipient's endpoint device (e.g., **Apple Secure Enclave**, **Android StrongBox**, or **TPM 2.0 Enclave**).
- The server releases only encrypted alternates; the hardware enclave unwraps only the assigned variant and renders the document directly to the secure display pipeline with screen-capture prevention.

---

## 4. Pure-Python Post-Quantum Reference Implementations

WebEye utilizes pure-Python implementations of NIST FIPS 203 (ML-KEM-768) and FIPS 204 (ML-DSA-65) (`kyber-py` and `dilithium-py`):
- **Timing Side Channels:** Pure-Python arithmetic is **not constant-time**. On shared cloud hardware or co-located virtual machines, timing fluctuations and cache access patterns could potentially leak private key information to a local side-channel attacker.
- **Production Remedy:** Deploy compiled, constant-time C implementations (such as Open Quantum Safe `liboqs`) with hardware AES-NI and AVX2 vector acceleration.

---

## 5. Provenance of the Electronic Copy vs. Physical Actor

Forensic document attribution establishes the provenance of the **electronic copy**:
- The cryptographic scorecard proves that a specific recipient's key material or authenticated session was used to generate the leaked document variant.
- **What it does NOT prove:** It does not identify the physical human being who pressed the keyboard or captured a photograph of the screen. A compromised workstation, shoulder-surfing colleague, or stolen credential could leak a document assigned to an innocent analyst.
- Consequently, WebEye outputs an **Attribution Scorecard and Section 65B(4) Evidence Certificate** for human forensic examiners, rather than an automated judicial verdict.

---

## 6. Ledger Integrity vs. Host Root Compromise

The local SQLite audit ledger uses SHA-256 hash chaining, Merkle tree block batching, and 2-of-3 ML-DSA-65 validator threshold signatures.
- **Local Protection:** Any tampering with entries, hashes, or blocks is immediately detected by `verify_evidence.py` and `/ledger`.
- **Root Admin Threat:** A host administrator with write access could theoretically rewrite SQLite and generate new blocks if all 3 validator private keys were compromised.
- **Production Remedy:** Distribute validator keystores across independent physical machines or air-gapped organizational nodes using a Byzantine Fault Tolerant (BFT) consensus protocol (e.g., Hyperledger Fabric or Sigstore Rekor).
