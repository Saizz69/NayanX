# Forensic Post-Quantum Document Attribution — Recipient Test Copies

This folder contains the authentic decrypted, watermarked documents generated for each authorized recipient, plus the unwatermarked original. You can use these files to test and prove the validity of the Helios system.

---

## Files in this Directory

| File | Recipient | Role | Watermark Payload | Expected Attribution Result |
|---|---|---|---|---|
| **`1_Alice_Vance_Decrypted_Watermarked.pdf`** | **Alice Vance** (`rec-alice-01`) | Chief Intelligence Officer | Invisible SHA-256 bound to Alice | **Attributed to Alice Vance** <br>ML-DSA-65: **Valid** <br>Chain: **Intact** |
| **`2_Bob_Sterling_Decrypted_Watermarked.pdf`** | **Bob Sterling** (`rec-bob-02`) | Senior Cryptanalyst | Invisible SHA-256 bound to Bob | **Attributed to Bob Sterling** <br>ML-DSA-65: **Valid** <br>Chain: **Intact** |
| **`3_Charlie_Miller_Decrypted_Watermarked.pdf`** | **Charlie Miller** (`rec-charlie-03`) | Defense Logistics Attaché | Invisible SHA-256 bound to Charlie | **Attributed to Charlie Miller** <br>ML-DSA-65: **Valid** <br>Chain: **Intact** |
| **`0_Original_Unwatermarked_Classified_Briefing.pdf`** | *None* (Unwatermarked) | Source Dossier | *No watermark* | **Unattributed / Unknown Source** <br>Correctly rejected because no forensic mark exists |

---

## How to Test on the Helios Web Dashboard (http://localhost:3000)

1. Open **[http://localhost:3000](http://localhost:3000)** in your browser.
2. Navigate to **Leak Attribution** in the left sidebar (or use the one-click test cards on the Dashboard).
3. Either:
   - **Upload**: Click "Choose File" or Drag-and-Drop any of the PDF files above into the upload box and click **"Attribute Leaked Document"**.
   - **One-Click Quick Test**: Click any of the pre-loaded buttons:
     - `Test Alice's Copy`
     - `Test Bob's Copy`
     - `Test Charlie's Copy`
     - `Test Unwatermarked Copy`
4. The system will extract the invisible watermark, query the Merkle ledger, verify the NIST FIPS 204 (ML-DSA-65) post-quantum digital signature, audit the entire SHA-256 Merkle hash chain, and display the non-repudiable forensic verdict.
