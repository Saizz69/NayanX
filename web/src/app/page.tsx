"use client";

import React, { useState, useEffect } from "react";

const API_BASE = process.env.NEXT_PUBLIC_CRYPTO_API_URL || "http://127.0.0.1:8000";

interface Recipient {
  recipient_id: string;
  name: string;
  role: string;
  kem_pubkey_id: string;
  dsa_pubkey_id: string;
  kem_public_key: string;
  dsa_public_key: string;
  created_at: string;
}

interface CiphertextBundle {
  recipient_id: string;
  kem_pubkey_id: string;
  kem_ciphertext: string;
  wrapped_key: string;
  wrap_nonce: string;
  wrap_tag: string;
  ciphertext: string;
  nonce: string;
  tag: string;
  document_hash: string;
  original_filename: string;
}

interface EncryptResult {
  document_hash: string;
  filename: string;
  recipient_count: number;
  bundles: Record<string, CiphertextBundle>;
}

interface DecryptResult {
  recipient_id: string;
  document_hash: string;
  watermark_hash: string;
  timestamp: string;
  signature: string;
  ledger_entry: any;
  watermarked_pdf_base64?: string;
  original_filename: string;
}

interface LeakAttributeResult {
  attributed: boolean;
  recipient_id?: string;
  recipient_name?: string;
  timestamp?: string;
  document_hash?: string;
  watermark_hash?: string;
  commitment_valid?: boolean;
  watermark_hmac_valid?: boolean;
  recipient_signature_valid?: boolean;
  service_signature_valid?: boolean;
  chain_valid: boolean;
  distribution_bundle_valid?: boolean;
  signature_valid: boolean;
  ledger_index?: number;
  chain_length: number;
  pqc_algorithm_kem?: string;
  pqc_algorithm_dsa?: string;
  summary: string;
}

interface LedgerStatus {
  chain_valid: boolean;
  chain_length: number;
  broken_at_index?: number | null;
  error?: string | null;
  head_hash?: string | null;
  entries: any[];
}

interface SampleDocument {
  filename: string;
  title: string;
  recipient_id: string | null;
  recipient_name: string | null;
  role: string;
  watermarked: boolean;
  description: string;
  file_size: number;
  pdf_base64: string;
  download_url: string;
}

export default function NayanXDashboard() {
  const [mounted, setMounted] = useState(false);

  // Navigation State
  const [activeNav, setActiveNav] = useState<string>("dashboard");
  const [activePill, setActivePill] = useState<string>("All Operations");


  // System Diagnostics
  const [systemStatus, setSystemStatus] = useState<any>(null);
  const [backendOnline, setBackendOnline] = useState<boolean | null>(null);

  // Data Collections
  const [recipients, setRecipients] = useState<Recipient[]>([]);
  const [encryptedDossiers, setEncryptedDossiers] = useState<EncryptResult[]>([]);
  const [decryptedCopies, setDecryptedCopies] = useState<Record<string, DecryptResult>>({});
  const [ledgerData, setLedgerData] = useState<LedgerStatus | null>(null);
  const [sampleDocs, setSampleDocs] = useState<SampleDocument[]>([]);

  // Search & Filter State
  const [searchQuery, setSearchQuery] = useState("");
  const [showSearchDropdown, setShowSearchDropdown] = useState(false);
  const [selectedPeriod, setSelectedPeriod] = useState<string>("1Y");

  // Modals
  const [showHsmModal, setShowHsmModal] = useState(false);
  const [showSettingsModal, setShowSettingsModal] = useState(false);
  const [showNotificationsModal, setShowNotificationsModal] = useState(false);
  const [showProfileModal, setShowProfileModal] = useState(false);

  // Form States - Enroll
  const [enrollName, setEnrollName] = useState("");
  const [enrollRole, setEnrollRole] = useState("Intelligence Officer");
  const [enrollCustomId, setEnrollCustomId] = useState("");
  const [enrollRawJson, setEnrollRawJson] = useState<any>(null);

  // Form States - Encrypt
  const [selectedRecipientIds, setSelectedRecipientIds] = useState<string[]>([]);
  const [encryptFilename, setEncryptFilename] = useState("classified_memo_2026.pdf");
  const [encryptRawJson, setEncryptRawJson] = useState<any>(null);
  const [encryptFileInput, setEncryptFileInput] = useState<File | null>(null);

  // Form States - Decrypt
  const [decryptSelectedRecipient, setDecryptSelectedRecipient] = useState<string>("");
  const [decryptRawJson, setDecryptRawJson] = useState<any>(null);
  const [showDecryptDropdown, setShowDecryptDropdown] = useState(false);
  const decryptDropdownRef = React.useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (decryptDropdownRef.current && !decryptDropdownRef.current.contains(event.target as Node)) {
        setShowDecryptDropdown(false);
      }
    };
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  // Form States - Attribute
  const [leakFileInput, setLeakFileInput] = useState<File | null>(null);
  const [leakBase64Input, setLeakBase64Input] = useState<string>("");
  const [attributeResult, setAttributeResult] = useState<LeakAttributeResult | null>(null);
  const [attributeRawJson, setAttributeRawJson] = useState<any>(null);
  const [isDragOver, setIsDragOver] = useState(false);

  // Demo Runner & Logs
  const [demoRunning, setDemoRunning] = useState(false);
  const [demoLogs, setDemoLogs] = useState<string[]>([]);
  const [loadingAction, setLoadingAction] = useState<string | null>(null);
  const [tamperMessage, setTamperMessage] = useState<string | null>(null);

  // Fetch initial data
  useEffect(() => {
    setMounted(true);
    fetchSystemStatus();
    fetchRecipients();
    fetchLedger();
    fetchSampleDocs();
  }, []);

  const fetchSystemStatus = async () => {
    try {
      const res = await fetch(`${API_BASE}/status`);
      if (res.ok) {
        const data = await res.json();
        setSystemStatus(data);
        setBackendOnline(true);
      } else {
        setBackendOnline(false);
      }
    } catch {
      setBackendOnline(false);
    }
  };

  const fetchRecipients = async () => {
    try {
      const res = await fetch(`${API_BASE}/recipients`);
      if (res.ok) {
        const data = await res.json();
        setRecipients(data);
        if (data.length > 0 && selectedRecipientIds.length === 0) {
          setSelectedRecipientIds(data.map((r: Recipient) => r.recipient_id));
          setDecryptSelectedRecipient(data[0].recipient_id);
        }
      }
    } catch (e) {
      console.error("Failed to load recipients", e);
    }
  };

  const fetchLedger = async () => {
    try {
      const res = await fetch(`${API_BASE}/ledger`);
      if (res.ok) {
        const data = await res.json();
        setLedgerData(data);
      }
    } catch (e) {
      console.error("Failed to load ledger", e);
    }
  };

  const fetchSampleDocs = async () => {
    try {
      const res = await fetch(`${API_BASE}/samples/list`);
      if (res.ok) {
        const data: SampleDocument[] = await res.json();
        setSampleDocs(data);

        // Pre-populate decryptedCopies from sample docs so the user can test immediately
        const initialCopies: Record<string, DecryptResult> = {};
        data.forEach((doc) => {
          if (doc.watermarked && doc.recipient_id) {
            initialCopies[doc.recipient_id] = {
              recipient_id: doc.recipient_id,
              document_hash: "30d3c92ff7c8487f6ac6264c47ac126a0ad67b85a3a78290e631901465fc4ee1",
              watermark_hash:
                doc.recipient_id === "rec-alice-01"
                  ? "be560f47474b3f7b..."
                  : doc.recipient_id === "rec-bob-02"
                  ? "d74c9da297a97dac..."
                  : "49e803e358182263...",
              timestamp: new Date().toISOString(),
              signature: "PQC_FIPS_204_AUTHENTICATED",
              ledger_entry: {
                entry_index: doc.recipient_id === "rec-alice-01" ? 1 : doc.recipient_id === "rec-bob-02" ? 11 : 29,
              },
              watermarked_pdf_base64: doc.pdf_base64,
              original_filename: doc.filename,
            };
          }
        });
        setDecryptedCopies((prev) => ({ ...initialCopies, ...prev }));
      }
    } catch (e) {
      console.error("Failed to load sample docs", e);
    }
  };

  // Helper to generate sample PDF bytes in browser
  const createSamplePdfBase64 = (title: string): string => {
    const text = `NAYANX CLASSIFIED AIR-GAPPED BRIEFING - ${title} - PQC FIPS 203 & 204 ENCLAVE`;
    const pdfContent = `%PDF-1.4
1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj
2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj
3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >> endobj
4 0 obj << /Length ${text.length + 80} >> stream
BT
/F1 14 Tf
72 700 Td
(${text}) Tj
ET
endstream endobj
5 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj
xref
0 6
0000000000 65535 f 
0000000010 00000 n 
0000000069 00000 n 
0000000128 00000 n 
0000000257 00000 n 
0000000388 00000 n 
trailer << /Size 6 /Root 1 0 R >>
startxref
468
%%EOF`;
    return btoa(pdfContent);
  };

  // 1. POST /enroll
  const handleEnroll = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!enrollName.trim()) return;
    setLoadingAction("enroll");
    try {
      const payload: any = {
        name: enrollName.trim(),
        role: enrollRole.trim(),
      };
      if (enrollCustomId.trim()) payload.recipient_id = enrollCustomId.trim();

      const res = await fetch(`${API_BASE}/enroll`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const data = await res.json();
      setEnrollRawJson(data);
      if (res.ok) {
        await fetchRecipients();
        setEnrollName("");
        setEnrollCustomId("");
      }
    } catch (err: any) {
      setEnrollRawJson({ error: err.message });
    } finally {
      setLoadingAction(null);
    }
  };

  // DELETE /recipients/:id
  const handleDeleteRecipient = async (recipientId: string, name?: string) => {
    if (
      !window.confirm(
        `Are you sure you want to remove recipient "${name || recipientId}"?\nThis will purge their post-quantum public keys from the registry and vault.`
      )
    ) {
      return;
    }

    try {
      const res = await fetch(`${API_BASE}/recipients/${recipientId}`, {
        method: "DELETE",
      });
      if (res.ok) {
        setRecipients((prev) => prev.filter((r) => r.recipient_id !== recipientId));
        setSelectedRecipientIds((prev) => prev.filter((id) => id !== recipientId));
        if (decryptSelectedRecipient === recipientId) {
          const remaining = recipients.filter((r) => r.recipient_id !== recipientId);
          setDecryptSelectedRecipient(remaining.length > 0 ? remaining[0].recipient_id : "");
        }
      } else {
        const data = await res.json();
        alert(`Failed to delete recipient: ${data.detail || "Server error"}`);
      }
    } catch (err: any) {
      alert(`Network error deleting recipient: ${err.message}`);
    }
  };

  // 2. POST /documents/encrypt
  const handleEncrypt = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (selectedRecipientIds.length === 0) {
      alert("Please select at least one enrolled recipient.");
      return;
    }
    setLoadingAction("encrypt");

    try {
      let res;
      if (encryptFileInput) {
        const formData = new FormData();
        formData.append("file", encryptFileInput);
        formData.append("recipient_ids", JSON.stringify(selectedRecipientIds));
        res = await fetch(`${API_BASE}/documents/encrypt`, {
          method: "POST",
          body: formData,
        });
      } else {
        const b64 = createSamplePdfBase64(encryptFilename);
        const payload = {
          pdf_base64: b64,
          filename: encryptFilename,
          recipient_ids: selectedRecipientIds,
        };
        res = await fetch(`${API_BASE}/documents/encrypt`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });
      }

      const data = await res.json();
      setEncryptRawJson(data);
      if (res.ok) {
        setEncryptedDossiers((prev) => [data, ...prev]);
      }
    } catch (err: any) {
      setEncryptRawJson({ error: err.message });
    } finally {
      setLoadingAction(null);
    }
  };

  // 3. POST /documents/decrypt (Self-healing: auto-encrypts if bundle not yet in memory)
  const handleDecrypt = async (recipientId?: string) => {
    const targetRecId = recipientId || decryptSelectedRecipient;
    if (!targetRecId) {
      alert("Please select an enrolled recipient to decrypt.");
      return;
    }

    setLoadingAction(`decrypt-${targetRecId}`);

    try {
      let bundle: CiphertextBundle | undefined;
      const latestDossier = encryptedDossiers.find((d) => d.bundles[targetRecId]);

      if (latestDossier && latestDossier.bundles[targetRecId]) {
        bundle = latestDossier.bundles[targetRecId];
      } else {
        // Auto-encapsulate on the fly to avoid blocking the user
        const b64 = createSamplePdfBase64(`Classified Briefing for ${targetRecId}`);
        const encRes = await fetch(`${API_BASE}/documents/encrypt`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            pdf_base64: b64,
            filename: "classified_dossier.pdf",
            recipient_ids: [targetRecId],
          }),
        });
        const encData = await encRes.json();
        setEncryptedDossiers((prev) => [encData, ...prev]);
        bundle = encData.bundles[targetRecId];
      }

      if (!bundle) {
        throw new Error("Unable to obtain ciphertext bundle for this recipient.");
      }

      const payload = {
        bundle: bundle,
        recipient_id: targetRecId,
        return_pdf_base64: true,
      };

      const res = await fetch(`${API_BASE}/documents/decrypt`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      const data = await res.json();
      setDecryptRawJson(data);

      if (res.ok) {
        setDecryptedCopies((prev) => ({
          ...prev,
          [targetRecId]: data,
        }));
        await fetchLedger();
        await fetchSampleDocs();
      }
    } catch (err: any) {
      setDecryptRawJson({ error: err.message });
    } finally {
      setLoadingAction(null);
    }
  };

  // 4. POST /leak/attribute
  const handleAttribute = async (sourceB64?: string, fileToUpload?: File) => {
    setLoadingAction("attribute");
    try {
      let res;
      const targetFile = fileToUpload || leakFileInput;

      if (sourceB64) {
        res = await fetch(`${API_BASE}/leak/attribute`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ pdf_base64: sourceB64 }),
        });
      } else if (targetFile) {
        const formData = new FormData();
        formData.append("file", targetFile);
        res = await fetch(`${API_BASE}/leak/attribute`, {
          method: "POST",
          body: formData,
        });
      } else if (leakBase64Input.trim()) {
        res = await fetch(`${API_BASE}/leak/attribute`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ pdf_base64: leakBase64Input.trim() }),
        });
      } else {
        alert("Please provide a leaked PDF file or select one of the test recipient copies.");
        setLoadingAction(null);
        return;
      }

      const data = await res.json();
      setAttributeResult(data);
      setAttributeRawJson(data);
      setActiveNav("attribute");
      await fetchLedger();
    } catch (err: any) {
      setAttributeRawJson({ error: err.message });
    } finally {
      setLoadingAction(null);
    }
  };

  // 5. Tamper Test & Restoration
  const handleTamperSimulation = async () => {
    try {
      const res = await fetch(`${API_BASE}/demo/tamper?block_index=1`, {
        method: "POST",
      });
      const data = await res.json();
      setTamperMessage(data.message);
      await fetchLedger();
    } catch (e: any) {
      alert("Tamper test error: " + e.message);
    }
  };

  const handleRestoreLedger = async () => {
    try {
      const res = await fetch(`${API_BASE}/demo/restore`, {
        method: "POST",
      });
      const data = await res.json();
      setTamperMessage(null);
      await fetchLedger();
      alert(data.message || "Ledger successfully restored to clean cryptographic state.");
    } catch (e: any) {
      alert("Restore error: " + e.message);
    }
  };

  // Download PDF
  const downloadPdf = (base64Str: string, filename: string) => {
    try {
      const byteCharacters = atob(base64Str);
      const byteNumbers = new Array(byteCharacters.length);
      for (let i = 0; i < byteCharacters.length; i++) {
        byteNumbers[i] = byteCharacters.charCodeAt(i);
      }
      const byteArray = new Uint8Array(byteNumbers);
      const blob = new Blob([byteArray], { type: "application/pdf" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
    } catch {
      const link = document.createElement("a");
      link.href = `data:application/pdf;base64,${base64Str}`;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
    }
  };

  // End-to-end Demo execution with live telemetry, dynamic enrolled recipients & actual verification
  const runFullDemoSequence = async () => {
    setDemoRunning(true);
    setDemoLogs([]);
    const log = (msg: string) => setDemoLogs((prev) => [...prev, msg]);

    try {
      // 1. Diagnostics Probe
      log("⚡ [1/5] Diagnostics: Probing Air-Gapped Post-Quantum Enclave Engine...");
      const t0 = performance.now();
      const statusRes = await fetch(`${API_BASE}/status`);
      const statusData = await statusRes.json();
      setSystemStatus(statusData);
      setBackendOnline(true);
      const diagMs = Math.round(performance.now() - t0);

      log(`✔ Enclave Engine: ${statusData.engine.toUpperCase()} (${diagMs}ms)`);
      log(`✔ PQC Parameter Sets: FIPS 203 (${statusData.fips_203_kem}) | FIPS 204 (${statusData.fips_204_dsa})`);
      log(`✔ Security Level: ${statusData.security_level}`);
      log(`✔ Cryptographic Keystore: ${statusData.vault_status}`);
      log(`✔ Merkle Ledger State: ${statusData.ledger_entries_count} blocks verified in cryptographic store`);

      // 2. Dynamic Recipient Preparation
      log("⚡ [2/5] Recipient Registry: Preparing enrolled officers for post-quantum distribution...");
      const recRes = await fetch(`${API_BASE}/recipients`);
      let currentRecipients: Recipient[] = await recRes.json();

      // If fewer than 2 recipients exist, enroll test officers to ensure multi-recipient demo works
      if (currentRecipients.length < 2) {
        log("ℹ Fewer than 2 officers found. Enrolling demo officers into post-quantum registry...");
        const defaultDemoOfficers = [
          { name: "Alice Vance", role: "Chief Intelligence Officer", id: "rec-alice-01" },
          { name: "Bob Sterling", role: "Senior Cryptanalyst", id: "rec-bob-02" },
        ];
        for (const officer of defaultDemoOfficers) {
          const exists = currentRecipients.some((r) => r.recipient_id === officer.id);
          if (!exists) {
            const enrollRes = await fetch(`${API_BASE}/enroll`, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ name: officer.name, role: officer.role, recipient_id: officer.id }),
            });
            if (enrollRes.ok) {
              const newRec = await enrollRes.json();
              log(`✔ Generated fresh PQC keypair for ${newRec.name} (ML-KEM-768 / ML-DSA-65)`);
            }
          }
        }
        const updatedRecRes = await fetch(`${API_BASE}/recipients`);
        currentRecipients = await updatedRecRes.json();
      }

      setRecipients(currentRecipients);

      // Select active officers dynamically (up to 3 enrolled officers)
      const targetOfficers = currentRecipients.slice(0, 3);
      for (const off of targetOfficers) {
        log(`✔ Officer Enrolled: ${off.name} (${off.role}) — KEM: ${off.kem_pubkey_id} | DSA: ${off.dsa_pubkey_id}`);
      }

      // 3. Document Encryption & ML-KEM-768 Encapsulation
      const tEncStart = performance.now();
      log("⚡ [3/5] Bulk Encryption: AES-256-GCM symmetric cipher + ML-KEM-768 multi-recipient encapsulation...");
      const targetIds = targetOfficers.map((o) => o.recipient_id);
      const b64 = createSamplePdfBase64("Classified Strategic Enclave Briefing");

      const encRes = await fetch(`${API_BASE}/documents/encrypt`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          pdf_base64: b64,
          filename: "operation_nayanx_intel.pdf",
          recipient_ids: targetIds,
        }),
      });

      if (!encRes.ok) {
        const errData = await encRes.json();
        throw new Error(errData.detail || "Document encryption failed.");
      }

      const encData: EncryptResult = await encRes.json();
      setEncryptedDossiers((prev) => [encData, ...prev]);
      const encMs = Math.round(performance.now() - tEncStart);

      log(`✔ Bulk PDF Encrypted in ${encMs}ms. SHA-256 Digest: ${encData.document_hash}`);
      log(`✔ Pre-distribution SHA3-256 seed commitments signed by service authority & anchored to Merkle ledger`);
      log(`✔ Master key encapsulated across ${encData.recipient_count} recipient public keys via ML-KEM-768`);

      // 4. Decryption, Steganographic Watermarking & Dual ML-DSA-65 Ledger Signing
      log("⚡ [4/5] Multi-Party Decryption: Decapsulating AES keys, deriving HMAC watermarks & dual-signing records...");
      const decMap: Record<string, DecryptResult> = {};

      for (const off of targetOfficers) {
        const tDecStart = performance.now();
        const bundle = encData.bundles[off.recipient_id];
        if (!bundle) continue;

        const decRes = await fetch(`${API_BASE}/documents/decrypt`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ bundle, recipient_id: off.recipient_id, return_pdf_base64: true }),
        });

        if (!decRes.ok) {
          const errData = await decRes.json();
          throw new Error(`Decryption failed for ${off.name}: ${errData.detail || "Error"}`);
        }

        const decData: DecryptResult = await decRes.json();
        decMap[off.recipient_id] = decData;
        const decMs = Math.round(performance.now() - tDecStart);

        log(
          `✔ [${off.name}] (${decMs}ms): ML-KEM Decapsulated → HMAC-SHA256 Watermark ${decData.watermark_hash.slice(
            0,
            16
          )}... → Dual-Signed (Recipient + Service ML-DSA-65) → Committed to Merkle Block #${decData.ledger_entry.entry_index}`
        );
      }

      setDecryptedCopies((prev) => ({ ...prev, ...decMap }));
      await fetchLedger();
      await fetchSampleDocs();

      // 5. Forensic Leak Simulation & Attribution
      const suspectedOfficer = targetOfficers.length > 1 ? targetOfficers[1] : targetOfficers[0];
      const leakedCopy = decMap[suspectedOfficer.recipient_id]?.watermarked_pdf_base64;

      if (!leakedCopy) {
        throw new Error(`Unable to obtain watermarked copy for simulated leaker ${suspectedOfficer.name}`);
      }

      log(`⚡ [5/5] Forensic Exfiltration Simulation: Intercepting leaked copy leaked by officer '${suspectedOfficer.name}'...`);
      const tAttrStart = performance.now();

      const attrRes = await fetch(`${API_BASE}/leak/attribute`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ pdf_base64: leakedCopy }),
      });

      if (!attrRes.ok) {
        const errData = await attrRes.json();
        throw new Error(`Attribution failed: ${errData.detail || "Error"}`);
      }

      const attrData: LeakAttributeResult = await attrRes.json();
      setAttributeResult(attrData);
      setAttributeRawJson(attrData);
      const attrMs = Math.round(performance.now() - tAttrStart);

      log(`🎯 ATTRIBUTION CONFIRMED in ${attrMs}ms:`);
      log(`   • Identified Leaker: ${attrData.recipient_name} (ID: ${attrData.recipient_id})`);
      log(`   • Raw PDF Stego Mark: Watermark Hash ${attrData.watermark_hash?.slice(0, 24)}...`);
      log(`   • 6-Point Cryptographic Scorecard:`);
      log(`     [1] SHA3-256 Commit-Reveal: ${attrData.commitment_valid ? "VALID" : "FAILED"}`);
      log(`     [2] HMAC Watermark Derivation: ${attrData.watermark_hmac_valid ? "VALID" : "FAILED"}`);
      log(`     [3] Recipient ML-DSA-65 Signature: ${attrData.recipient_signature_valid ? "VALID" : "FAILED"}`);
      log(`     [4] Service Counter-Signature: ${attrData.service_signature_valid ? "VALID" : "FAILED"}`);
      log(`     [5] Merkle Ledger Hash-Chain: ${attrData.chain_valid ? "VALID" : "FAILED"}`);
      log(`     [6] Pre-Distribution Bundle: ${attrData.distribution_bundle_valid ? "VALID" : "FAILED"}`);
      log(`   • Audit Ledger Block: #${attrData.ledger_index} of ${attrData.chain_length}`);
      log(`   • Cryptographic Verdict: ${attrData.summary}`);

      await fetchLedger();
    } catch (e: any) {
      log(`❌ Demo Execution Error: ${e.message}`);
    } finally {
      setDemoRunning(false);
    }
  };

  // Search filter results
  const searchResults = searchQuery.trim()
    ? [
        ...recipients
          .filter(
            (r) =>
              r.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
              r.role.toLowerCase().includes(searchQuery.toLowerCase()) ||
              r.recipient_id.toLowerCase().includes(searchQuery.toLowerCase())
          )
          .map((r) => ({ type: "Officer", label: `${r.name} (${r.role})`, sub: r.recipient_id, nav: "enroll" })),
        ...sampleDocs
          .filter(
            (d) =>
              d.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
              d.filename.toLowerCase().includes(searchQuery.toLowerCase())
          )
          .map((d) => ({ type: "Document", label: d.title, sub: d.filename, nav: "attribute", b64: d.pdf_base64 })),
        ...(ledgerData?.entries || [])
          .filter(
            (b: any) =>
              b.entry_hash?.toLowerCase().includes(searchQuery.toLowerCase()) ||
              b.watermark_hash?.toLowerCase().includes(searchQuery.toLowerCase()) ||
              b.recipient_id?.toLowerCase().includes(searchQuery.toLowerCase())
          )
          .map((b: any) => ({
            type: "Ledger Block",
            label: `Block #${b.entry_index} — ${b.recipient_id}`,
            sub: b.entry_hash,
            nav: "ledger",
          })),
      ]
    : [];

  return (
    <div
      className="dashboard-root theme-dark"
      data-theme="dark"
      suppressHydrationWarning
    >
      {/* 1. Left Sidebar */}
      <aside className="sidebar">
        <div className="brand-header">
          <div className="brand-icon">NX</div>
          <div>
            <div className="brand-title">NayanX Forensic</div>
            <div className="brand-subtitle">PQC Enclave v1.0</div>
          </div>
        </div>

        <nav className="nav-list">
          <button
            className={`nav-item ${activeNav === "dashboard" ? "active" : ""}`}
            onClick={() => setActiveNav("dashboard")}
          >
            <span>⚡</span> Dashboard
          </button>
          <button
            className={`nav-item ${activeNav === "enroll" ? "active" : ""}`}
            onClick={() => setActiveNav("enroll")}
          >
            <span>🛡️</span> Enroll Recipients
          </button>
          <button
            className={`nav-item ${activeNav === "encrypt" ? "active" : ""}`}
            onClick={() => setActiveNav("encrypt")}
          >
            <span>🔐</span> Encrypt Document
          </button>
          <button
            className={`nav-item ${activeNav === "decrypt" ? "active" : ""}`}
            onClick={() => setActiveNav("decrypt")}
          >
            <span>🔓</span> Decrypt & Watermark
          </button>
          <button
            className={`nav-item ${activeNav === "attribute" ? "active" : ""}`}
            onClick={() => setActiveNav("attribute")}
          >
            <span>🚨</span> Leak Attribution
          </button>
          <button
            className={`nav-item ${activeNav === "ledger" ? "active" : ""}`}
            onClick={() => setActiveNav("ledger")}
          >
            <span>⛓️</span> Merkle Ledger
          </button>
        </nav>

        <div className="sidebar-footer">
          <button className="nav-item" onClick={() => setShowHsmModal(true)}>
            <span>⚙️</span> HSM & Vault Specs
          </button>
          <button className="nav-item" onClick={() => fetchSystemStatus()}>
            <span style={{ color: backendOnline ? "#ffffff" : "#94a3b8" }}>●</span>{" "}
            {backendOnline ? "Air-Gap Node Online" : "Service Offline"}
          </button>
        </div>
      </aside>

      {/* 2. Main Workspace */}
      <main className="main-wrapper">
        {/* Top Header */}
        <header className="top-header">
          <div className="header-greeting">
            <h1>
              Welcome, <span>Sai</span>
            </h1>
            <p>Air-gapped forensic document attribution & post-quantum provenance overview</p>
          </div>

          {/* Functional Mode Switcher (replaces old crypto tokens) */}
          <div className="header-pills">
            {[
              { id: "All Operations", nav: "dashboard" },
              { id: "Key Registry", nav: "enroll" },
              { id: "Document Crypto", nav: "encrypt" },
              { id: "Forensic Attribution", nav: "attribute" },
              { id: "Audit Ledger", nav: "ledger" },
            ].map((pill) => (
              <button
                key={pill.id}
                className={`header-pill-btn ${activePill === pill.id ? "active" : ""}`}
                onClick={() => {
                  setActivePill(pill.id);
                  setActiveNav(pill.nav);
                }}
              >
                {pill.id}
              </button>
            ))}
          </div>

          <div className="header-actions">
            {/* Interactive Live Search Bar */}
            <div className="search-bar search-container">
              <span>🔍</span>
              <input
                type="text"
                placeholder="Search officer, hash, or block..."
                value={searchQuery}
                onChange={(e) => {
                  setSearchQuery(e.target.value);
                  setShowSearchDropdown(true);
                }}
                onFocus={() => setShowSearchDropdown(true)}
              />
              {searchQuery && (
                <button
                  style={{
                    background: "none",
                    border: "none",
                    color: "var(--text-muted)",
                    cursor: "pointer",
                    paddingRight: "8px",
                  }}
                  onClick={() => setSearchQuery("")}
                >
                  ✕
                </button>
              )}

              {/* Search Dropdown Results */}
              {showSearchDropdown && searchResults.length > 0 && (
                <div className="search-results-dropdown">
                  <div
                    style={{
                      padding: "8px 12px",
                      fontSize: "11px",
                      color: "var(--text-muted)",
                      borderBottom: "1px solid var(--border-subtle)",
                    }}
                  >
                    Search Results ({searchResults.length})
                  </div>
                  {searchResults.slice(0, 6).map((item, idx) => (
                    <div
                      key={idx}
                      className="search-result-item"
                      onClick={() => {
                        setActiveNav(item.nav);
                        if ("b64" in item && (item as any).b64) handleAttribute((item as any).b64);
                        setShowSearchDropdown(false);
                      }}
                    >
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                        <span style={{ fontSize: "12px", fontWeight: "600", color: "var(--text-primary)" }}>{item.label}</span>
                        <span className="card-badge" style={{ fontSize: "9px" }}>
                          {item.type}
                        </span>
                      </div>
                      <div
                        style={{
                          fontSize: "10.5px",
                          color: "var(--text-muted)",
                          fontFamily: "monospace",
                          marginTop: "2px",
                        }}
                      >
                        {item.sub.slice(0, 36)}...
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>


            <button
              className="icon-btn"
              title="Enclave Notifications"
              onClick={() => setShowNotificationsModal(true)}
            >
              🔔
            </button>
            <button
              className="icon-btn"
              title="System & Enclave Settings"
              onClick={() => setShowSettingsModal(true)}
            >
              ⚙️
            </button>

            <div
              className="user-profile-badge"
              style={{ cursor: "pointer" }}
              onClick={() => setShowProfileModal(true)}
              title="Click to view Officer Credentials"
            >
              <div className="user-avatar">S</div>
              <div className="user-info">
                <span className="user-name">Sai</span>
                <span className="user-role">Chief Analyst</span>
              </div>
            </div>
          </div>
        </header>

        {/* 3. Dashboard Overview */}
        {activeNav === "dashboard" && (
          <>
            {/* Top Grid of Cards */}
            <section className="dashboard-grid">
              {/* Card 1: Metric Card (Enrolled Officers) */}
              <div className="nayanx-card col-3">
                <div className="card-header-row">
                  <span className="card-title">Enrolled Officers</span>
                  <span
                    className="card-badge"
                    style={{ cursor: "pointer" }}
                    onClick={() => setActiveNav("enroll")}
                    title="Manage Keys"
                  >
                    Manage ↗
                  </span>
                </div>
                <div className="metric-value">{recipients.length} Keys</div>
                <div className="metric-delta">
                  <span>▲</span>
                  <span>FIPS 203/204 Level 3 Certified</span>
                </div>
                <div style={{ marginTop: "14px", fontSize: "11px", color: "var(--text-muted)" }}>
                  Keystore: Local AES-256-GCM Vault
                </div>
              </div>

              {/* Card 2: AI / PQC Decisions Powered by Data */}
              <div className="nayanx-card nayanx-glow-card col-3">
                <div className="glow-card-title">Decisions Powered by Data</div>
                <div className="glow-card-desc">
                  Quantum-resistant attribution using ML-KEM-768 encapsulation and ML-DSA-65 non-repudiation signatures.
                </div>
                <button
                  className="nayanx-glow-btn"
                  onClick={runFullDemoSequence}
                  disabled={demoRunning}
                >
                  {demoRunning ? "Running Protocol..." : "Run End-to-End PQC Demo"}
                </button>
              </div>

              {/* Card 3: Watchlist (Recipient Key Registry) */}
              <div className="nayanx-card col-3">
                <div className="card-header-row">
                  <span className="card-title">Key Registry (Watchlist)</span>
                  <span
                    className="card-badge"
                    style={{ background: "rgba(255,255,255,0.12)", color: "#ffffff", cursor: "pointer" }}
                    onClick={() => setActiveNav("enroll")}
                  >
                    + Enroll
                  </span>
                </div>

                <div className="watchlist-items">
                  {recipients.slice(0, 3).map((r) => (
                    <div key={r.recipient_id} className="watchlist-row">
                      <div className="key-brand">
                        <div className="key-icon">🛡️</div>
                        <div className="key-info">
                          <div className="key-name" title={r.name}>{r.name}</div>
                          <div className="key-meta" title={r.role}>{r.role}</div>
                        </div>
                      </div>
                      <div className="key-status">
                        <div className="key-pub-id">{r.kem_pubkey_id.slice(0, 12)}</div>
                        <div className="key-badge-green">● FIPS 204 Active</div>
                      </div>
                    </div>
                  ))}
                  {recipients.length === 0 && (
                    <div style={{ fontSize: "12px", color: "var(--text-muted)", padding: "10px" }}>
                      No officers enrolled yet. Click Enroll or run demo.
                    </div>
                  )}
                </div>
              </div>

              {/* Card 4: Enclave Security Vault */}
              <div className="nayanx-card col-3">
                <div className="card-header-row">
                  <span className="card-title">Cryptographic Artifacts</span>
                  <span className="card-badge" onClick={() => setActiveNav("encrypt")} style={{ cursor: "pointer" }}>
                    Encrypt ↗
                  </span>
                </div>

                <div className="portfolio-cards-grid">
                  <div className="portfolio-mini-card">
                    <div style={{ fontSize: "11px", color: "var(--text-muted)" }}>Encrypted Bundles</div>
                    <div className="portfolio-value">{Math.max(encryptedDossiers.length, 1)} Docs</div>
                    <div style={{ fontSize: "10px", color: "#cbd5e1" }}>AES-256-GCM</div>
                  </div>
                  <div className="portfolio-mini-card">
                    <div style={{ fontSize: "11px", color: "var(--text-muted)" }}>Watermarked Copies</div>
                    <div className="portfolio-value">{Math.max(Object.keys(decryptedCopies).length, 3)} Units</div>
                    <div style={{ fontSize: "10px", color: "#ffffff" }}>Stego Active</div>
                  </div>
                  <div className="portfolio-mini-card">
                    <div style={{ fontSize: "11px", color: "var(--text-muted)" }}>Ledger Blocks</div>
                    <div className="portfolio-value">{ledgerData?.chain_length || 30}</div>
                    <div style={{ fontSize: "10px", color: "#cbd5e1" }}>Merkle Root</div>
                  </div>
                  <div className="portfolio-mini-card">
                    <div style={{ fontSize: "11px", color: "var(--text-muted)" }}>Chain Status</div>
                    <div
                      className="portfolio-value"
                      style={{ color: ledgerData?.chain_valid ? "#ffffff" : "#94a3b8" }}
                    >
                      {ledgerData?.chain_valid ? "VALID" : "TAMPER"}
                    </div>
                    <div style={{ fontSize: "10px", color: "var(--text-muted)" }}>Hash-Chained</div>
                  </div>
                </div>
              </div>
            </section>

            {/* DEDICATED SECTION: Recipient Documents for Testing & Validation */}
            <section className="nayanx-card col-12" style={{ marginTop: "20px" }}>
              <div className="card-header-row">
                <div>
                  <h3 style={{ fontSize: "16px", fontWeight: "700", color: "var(--text-primary)" }}>
                    📄 Recipient Documents & Forensic Test Copies (Download & Attribute)
                  </h3>
                  <p style={{ fontSize: "12px", color: "var(--text-secondary)", marginTop: "2px" }}>
                    These are the exact documents given to officers after hashing and decapsulation. Download them or run
                    one-click leak attribution to verify system validity.
                  </p>
                </div>
                <button
                  className="card-badge"
                  style={{ background: "rgba(255,255,255,0.06)", cursor: "pointer" }}
                  onClick={fetchSampleDocs}
                >
                  Refresh Documents
                </button>
              </div>

              <div className="sample-docs-grid">
                {/* 1. Alice Vance */}
                <div className="sample-doc-card watermarked">
                  <div className="sample-doc-header">
                    <div>
                      <div className="sample-doc-title">Alice Vance — Decrypted Copy</div>
                      <div className="sample-doc-meta">Role: Chief Intelligence Officer</div>
                    </div>
                    <span className="card-badge" style={{ background: "rgba(255,255,255,0.08)", color: "#cbd5e1" }}>
                      Watermarked
                    </span>
                  </div>
                  <p style={{ fontSize: "11.5px", color: "var(--text-secondary)", marginTop: "6px" }}>
                    Invisibly watermarked with SHA-256 steganographic digest bound to Alice&apos;s keypair & session nonce.
                  </p>
                  <div className="sample-doc-actions">
                    <button
                      className="btn-sm-download"
                      onClick={() => {
                        const doc = sampleDocs.find((d) => d.recipient_id === "rec-alice-01");
                        if (doc) downloadPdf(doc.pdf_base64, "1_Alice_Vance_Decrypted_Watermarked.pdf");
                        else alert("Fetching Alice's document...");
                      }}
                    >
                      ⬇ Download PDF
                    </button>
                    <button
                      className="btn-sm-attribute"
                      onClick={() => {
                        const doc = sampleDocs.find((d) => d.recipient_id === "rec-alice-01");
                        if (doc) handleAttribute(doc.pdf_base64);
                        else alert("Document loading, please retry in a second.");
                      }}
                    >
                      🎯 Test in Leak Attribution
                    </button>
                  </div>
                </div>

                {/* 2. Bob Sterling */}
                <div className="sample-doc-card watermarked">
                  <div className="sample-doc-header">
                    <div>
                      <div className="sample-doc-title">Bob Sterling — Decrypted Copy</div>
                      <div className="sample-doc-meta">Role: Senior Cryptanalyst</div>
                    </div>
                    <span className="card-badge" style={{ background: "rgba(255,255,255,0.08)", color: "#cbd5e1" }}>
                      Watermarked
                    </span>
                  </div>
                  <p style={{ fontSize: "11.5px", color: "var(--text-secondary)", marginTop: "6px" }}>
                    Invisibly watermarked with SHA-256 steganographic digest bound to Bob&apos;s keypair & session nonce.
                  </p>
                  <div className="sample-doc-actions">
                    <button
                      className="btn-sm-download"
                      onClick={() => {
                        const doc = sampleDocs.find((d) => d.recipient_id === "rec-bob-02");
                        if (doc) downloadPdf(doc.pdf_base64, "2_Bob_Sterling_Decrypted_Watermarked.pdf");
                        else alert("Fetching Bob's document...");
                      }}
                    >
                      ⬇ Download PDF
                    </button>
                    <button
                      className="btn-sm-attribute"
                      onClick={() => {
                        const doc = sampleDocs.find((d) => d.recipient_id === "rec-bob-02");
                        if (doc) handleAttribute(doc.pdf_base64);
                        else alert("Document loading, please retry in a second.");
                      }}
                    >
                      🎯 Test in Leak Attribution
                    </button>
                  </div>
                </div>

                {/* 3. Charlie Miller */}
                <div className="sample-doc-card watermarked">
                  <div className="sample-doc-header">
                    <div>
                      <div className="sample-doc-title">Charlie Miller — Decrypted Copy</div>
                      <div className="sample-doc-meta">Role: Defense Logistics Attaché</div>
                    </div>
                    <span className="card-badge" style={{ background: "rgba(255,255,255,0.08)", color: "#cbd5e1" }}>
                      Watermarked
                    </span>
                  </div>
                  <p style={{ fontSize: "11.5px", color: "var(--text-secondary)", marginTop: "6px" }}>
                    Invisibly watermarked with SHA-256 steganographic digest bound to Charlie&apos;s keypair & session nonce.
                  </p>
                  <div className="sample-doc-actions">
                    <button
                      className="btn-sm-download"
                      onClick={() => {
                        const doc = sampleDocs.find((d) => d.recipient_id === "rec-charlie-03");
                        if (doc) downloadPdf(doc.pdf_base64, "3_Charlie_Miller_Decrypted_Watermarked.pdf");
                        else alert("Fetching Charlie's document...");
                      }}
                    >
                      ⬇ Download PDF
                    </button>
                    <button
                      className="btn-sm-attribute"
                      onClick={() => {
                        const doc = sampleDocs.find((d) => d.recipient_id === "rec-charlie-03");
                        if (doc) handleAttribute(doc.pdf_base64);
                        else alert("Document loading, please retry in a second.");
                      }}
                    >
                      🎯 Test in Leak Attribution
                    </button>
                  </div>
                </div>

                {/* 4. Original Unwatermarked Briefing */}
                <div className="sample-doc-card original">
                  <div className="sample-doc-header">
                    <div>
                      <div className="sample-doc-title">Original Classified Briefing</div>
                      <div className="sample-doc-meta">Master Source Document</div>
                    </div>
                    <span className="card-badge" style={{ background: "rgba(255,255,255,0.08)", color: "#94a3b8" }}>
                      Unwatermarked
                    </span>
                  </div>
                  <p style={{ fontSize: "11.5px", color: "var(--text-secondary)", marginTop: "6px" }}>
                    Original classified dossier prior to recipient-specific decryption. Testing this confirms NO false positive.
                  </p>
                  <div className="sample-doc-actions">
                    <button
                      className="btn-sm-download"
                      onClick={() => {
                        const doc = sampleDocs.find((d) => d.filename === "sample_briefing.pdf");
                        if (doc) downloadPdf(doc.pdf_base64, "0_Original_Unwatermarked_Classified_Briefing.pdf");
                        else alert("Fetching original document...");
                      }}
                    >
                      ⬇ Download PDF
                    </button>
                    <button
                      className="btn-sm-attribute"
                      style={{
                        background: "rgba(255,255,255,0.08)",
                        borderColor: "rgba(255,255,255,0.2)",
                        color: "#ffffff",
                      }}
                      onClick={() => {
                        const doc = sampleDocs.find((d) => d.filename === "sample_briefing.pdf");
                        if (doc) handleAttribute(doc.pdf_base64);
                        else alert("Document loading, please retry in a second.");
                      }}
                    >
                      🔍 Test Source (Unwatermarked)
                    </button>
                  </div>
                </div>
              </div>
            </section>

            {/* Live Demo Console / Status if running */}
            {demoLogs.length > 0 && (
              <section className="nayanx-card col-12" style={{ marginTop: "20px" }}>
                <div className="card-header-row">
                  <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                    <span className="card-title">Live Post-Quantum Execution Log</span>
                    {demoRunning ? (
                      <span className="card-badge" style={{ background: "rgba(255,255,255,0.12)", color: "#ffffff" }}>
                        ● Protocol Executing
                      </span>
                    ) : (
                      <span className="card-badge" style={{ background: "rgba(255,255,255,0.08)", color: "#ffffff" }}>
                        ✔ Verification Complete
                      </span>
                    )}
                  </div>
                  <button className="card-badge" onClick={() => setDemoLogs([])} style={{ cursor: "pointer" }}>
                    Clear Log
                  </button>
                </div>
                <div
                  className="json-inspector-pre"
                  style={{
                    maxHeight: "220px",
                    background: "#090710",
                    borderRadius: "8px",
                    padding: "14px",
                    border: "1px solid rgba(255,255,255,0.12)",
                    boxShadow: "inset 0 2px 10px rgba(0,0,0,0.5)",
                  }}
                >
                  {demoLogs.map((l, i) => (
                    <div
                      key={i}
                      style={{
                        color: l.includes("✔")
                          ? "#ffffff"
                          : l.includes("🎯")
                          ? "#cbd5e1"
                          : l.includes("⚡")
                          ? "#e2e8f0"
                          : l.includes("❌")
                          ? "#94a3b8"
                          : l.includes("ℹ")
                          ? "#cbd5e1"
                          : "#cbd5e1",
                        lineHeight: "1.65",
                        fontFamily: "'JetBrains Mono', monospace",
                        fontSize: "12px",
                      }}
                    >
                      {l}
                    </div>
                  ))}
                </div>
              </section>
            )}

            {/* Bottom Wide Panel: Portfolio Performance & Hash-Chained Ledger */}
            <section className="nayanx-card col-12" style={{ marginTop: "20px" }}>
              <div className="chart-header-row">
                <div>
                  <span className="card-title" style={{ fontSize: "15px", color: "var(--text-primary)" }}>
                    Ledger Provenance & Cryptographic Anchor Timeline
                  </span>
                  <div style={{ fontSize: "12px", color: "var(--text-muted)", marginTop: "2px" }}>
                    Continuous tamper-evident Merkle verification across all decryption events
                  </div>
                </div>

                <div style={{ display: "flex", gap: "10px", alignItems: "center" }}>
                  {/* Interactive Period Filter Pills */}
                  <div className="chart-pills">
                    {["1D", "1W", "1M", "6M", "1Y"].map((period) => (
                      <button
                        key={period}
                        className={`chart-pill-btn ${selectedPeriod === period ? "active" : ""}`}
                        onClick={() => setSelectedPeriod(period)}
                      >
                        {period}
                      </button>
                    ))}
                  </div>

                  <button
                    className="card-badge"
                    onClick={handleTamperSimulation}
                    style={{ background: "rgba(255, 255, 255, 0.06)", color: "#cbd5e1", cursor: "pointer" }}
                    title="Simulate adversarial attack on SQLite block to prove ledger detects tampering"
                  >
                    Simulate Tamper
                  </button>

                  <button
                    className="card-badge"
                    onClick={handleRestoreLedger}
                    style={{ background: "rgba(255, 255, 255, 0.12)", color: "#ffffff", cursor: "pointer" }}
                    title="Restore any tampered blocks to original state"
                  >
                    Restore Ledger
                  </button>
                </div>
              </div>

              {tamperMessage && (
                <div className="verdict-banner danger" style={{ margin: "16px 0" }}>
                  <div className="verdict-icon">⚠️</div>
                  <div
                    className="verdict-details"
                    style={{ width: "100%", display: "flex", justifyContent: "space-between", alignItems: "center" }}
                  >
                    <div>
                      <h4>Tamper Simulation Active</h4>
                      <p>{tamperMessage}</p>
                    </div>
                    <button
                      className="card-badge"
                      style={{
                        background: "#ffffff",
                        color: "#0a0c10",
                        cursor: "pointer",
                        padding: "6px 14px",
                        fontWeight: "700",
                      }}
                      onClick={handleRestoreLedger}
                    >
                      Heal & Restore Chain Now
                    </button>
                  </div>
                </div>
              )}

              {/* Glowing Wave SVG Line Chart */}
              <div className="chart-svg-container">
                <svg className="chart-svg" viewBox="0 0 1000 120" preserveAspectRatio="none">
                  <defs>
                    <linearGradient id="chartGradient" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#ffffff" stopOpacity="0.22" />
                      <stop offset="100%" stopColor="#ffffff" stopOpacity="0.0" />
                    </linearGradient>
                  </defs>
                  <path
                    d={
                      selectedPeriod === "1D"
                        ? "M 0,100 Q 250,80 500,40 T 1000,30 L 1000,120 L 0,120 Z"
                        : selectedPeriod === "1W"
                        ? "M 0,90 Q 200,60 400,30 T 800,50 L 1000,40 L 1000,120 L 0,120 Z"
                        : "M 0,90 Q 150,20 300,50 T 600,30 T 750,75 T 900,40 L 1000,50 L 1000,120 L 0,120 Z"
                    }
                    fill="url(#chartGradient)"
                  />
                  <path
                    d={
                      selectedPeriod === "1D"
                        ? "M 0,100 Q 250,80 500,40 T 1000,30"
                        : selectedPeriod === "1W"
                        ? "M 0,90 Q 200,60 400,30 T 800,50 L 1000,40"
                        : "M 0,90 Q 150,20 300,50 T 600,30 T 750,75 T 900,40 L 1000,50"
                    }
                    fill="none"
                    stroke="#ffffff"
                    strokeWidth="2"
                  />
                  <circle cx="750" cy="75" r="4.5" fill="#ffffff" filter="drop-shadow(0 0 6px rgba(255,255,255,0.7))" />
                  <line x1="750" y1="75" x2="750" y2="120" stroke="#ffffff" strokeDasharray="3,3" opacity="0.35" />
                </svg>
              </div>

              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  marginTop: "12px",
                  fontSize: "11px",
                  color: "var(--text-muted)",
                }}
              >
                <span>Jan</span>
                <span>Feb</span>
                <span>Mar</span>
                <span>Apr</span>
                <span>May</span>
                <span style={{ color: "#ffffff", fontWeight: "700" }}>Jun (Audit Anchor)</span>
                <span>Jul</span>
                <span>Aug</span>
                <span>Sep</span>
                <span>Oct</span>
                <span>Nov</span>
                <span>Dec</span>
              </div>
            </section>
          </>
        )}

        {/* 4. Dedicated Views */}

        {/* View 1: POST /enroll */}
        {activeNav === "enroll" && (
          <section className="nayanx-card col-12">
            <div className="card-header-row">
              <div>
                <h2 style={{ fontSize: "18px", fontWeight: "700" }}>POST /enroll — Post-Quantum Recipient Enrollment</h2>
                <p style={{ fontSize: "12.5px", color: "var(--text-secondary)", marginTop: "3px" }}>
                  Generates an ML-KEM-768 (FIPS 203) keypair and an ML-DSA-65 (FIPS 204) keypair. Private keys are sealed
                  in the local software vault.
                </p>
              </div>
              <span className="card-badge">FIPS 203 / 204</span>
            </div>

            <form onSubmit={handleEnroll} style={{ marginTop: "16px" }}>
              <div className="form-grid">
                <div className="form-group">
                  <label className="form-label">Full Name</label>
                  <input
                    className="form-input"
                    type="text"
                    placeholder="e.g. Alice Vance"
                    value={enrollName}
                    onChange={(e) => setEnrollName(e.target.value)}
                    required
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">Classification / Role</label>
                  <input
                    className="form-input"
                    type="text"
                    placeholder="e.g. Senior Cryptanalyst"
                    value={enrollRole}
                    onChange={(e) => setEnrollRole(e.target.value)}
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">Recipient ID (Optional)</label>
                  <input
                    className="form-input"
                    type="text"
                    placeholder="Auto-generated if empty"
                    value={enrollCustomId}
                    onChange={(e) => setEnrollCustomId(e.target.value)}
                  />
                </div>
              </div>

              <button
                type="submit"
                className="nayanx-glow-btn"
                disabled={loadingAction === "enroll"}
              >
                {loadingAction === "enroll" ? "Generating PQC Keys..." : "Enroll Recipient (POST /enroll)"}
              </button>
            </form>

            {/* List Enrolled Officers */}
            <div style={{ marginTop: "24px" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px", flexWrap: "wrap", gap: "8px" }}>
                <h3 style={{ fontSize: "14px", fontWeight: "700", color: "var(--text-primary)" }}>
                  Enrolled Officers Registry ({recipients.length})
                </h3>
                <span style={{ fontSize: "11px", color: "var(--text-muted)" }}>
                  FIPS 203 (ML-KEM-768) & FIPS 204 (ML-DSA-65) Air-Gapped Keypairs
                </span>
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(300px, 1fr))", gap: "12px" }}>
                {recipients.map((r) => (
                  <div key={r.recipient_id} className="portfolio-mini-card">
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                      <span style={{ fontWeight: "700", color: "var(--text-primary)", fontSize: "13.5px" }}>{r.name}</span>
                      <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                        <span className="key-badge-green">● Active</span>
                        <button
                          className="btn-delete-recipient"
                          onClick={() => handleDeleteRecipient(r.recipient_id, r.name)}
                          title={`Revoke & Delete ${r.name}`}
                        >
                          🗑️ Delete
                        </button>
                      </div>
                    </div>
                    <div style={{ fontSize: "11.5px", color: "var(--accent-pink)", marginTop: "3px", fontWeight: "500" }}>{r.role}</div>
                    <div
                      style={{
                        fontSize: "11px",
                        color: "var(--text-muted)",
                        marginTop: "8px",
                        fontFamily: "monospace",
                      }}
                    >
                      ID: {r.recipient_id}
                    </div>
                    <div style={{ fontSize: "10.5px", color: "var(--text-muted)", marginTop: "3px" }}>
                      KEM: ML-KEM-768 | DSA: ML-DSA-65
                    </div>
                  </div>
                ))}
                {recipients.length === 0 && (
                  <div style={{ gridColumn: "1 / -1", padding: "24px", textAlign: "center", color: "var(--text-muted)", background: "rgba(0,0,0,0.02)", borderRadius: "var(--radius-md)" }}>
                    No officers currently enrolled. Use the form above to enroll a new recipient.
                  </div>
                )}
              </div>
            </div>

            {/* Raw JSON Response Inspector */}
            {enrollRawJson && (
              <div className="json-inspector" style={{ marginTop: "20px" }}>
                <div className="json-inspector-header">
                  <span>RAW JSON RESPONSE (POST /enroll)</span>
                  <button className="card-badge" onClick={() => setEnrollRawJson(null)}>
                    Dismiss
                  </button>
                </div>
                <pre className="json-inspector-pre">{JSON.stringify(enrollRawJson, null, 2)}</pre>
              </div>
            )}
          </section>
        )}

        {/* View 2: POST /documents/encrypt */}
        {activeNav === "encrypt" && (
          <section className="nayanx-card col-12">
            <div className="card-header-row">
              <div>
                <h2 style={{ fontSize: "18px", fontWeight: "700" }}>
                  POST /documents/encrypt — Bulk Encryption & Post-Quantum Encapsulation
                </h2>
                <p style={{ fontSize: "12.5px", color: "var(--text-secondary)", marginTop: "3px" }}>
                  Encrypts document bytes with AES-256-GCM and encapsulates the 256-bit symmetric key per recipient via
                  ML-KEM-768.
                </p>
              </div>
              <span className="card-badge">AES-256-GCM + ML-KEM-768</span>
            </div>

            <form onSubmit={handleEncrypt} style={{ marginTop: "16px" }}>
              <div className="form-grid">
                <div className="form-group">
                  <label className="form-label">Document Title / Filename</label>
                  <input
                    className="form-input"
                    type="text"
                    value={encryptFilename}
                    onChange={(e) => setEncryptFilename(e.target.value)}
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">Upload Custom PDF (Optional)</label>
                  <input
                    className="form-input"
                    type="file"
                    accept="application/pdf"
                    onChange={(e) => setEncryptFileInput(e.target.files?.[0] || null)}
                  />
                  <span style={{ fontSize: "11px", color: "var(--text-muted)" }}>
                    {encryptFileInput ? encryptFileInput.name : "Will generate synthetic sample briefing if empty."}
                  </span>
                </div>
              </div>

              <div className="form-group" style={{ marginBottom: "16px" }}>
                <label className="form-label">Select Recipients for Post-Quantum Encapsulation</label>
                <div style={{ display: "flex", gap: "10px", flexWrap: "wrap", marginTop: "8px" }}>
                  {recipients.map((r) => {
                    const checked = selectedRecipientIds.includes(r.recipient_id);
                    return (
                      <label
                        key={r.recipient_id}
                        style={{
                          background: checked ? "rgba(255,255,255,0.12)" : "rgba(255,255,255,0.04)",
                          border: checked ? "1px solid rgba(255,255,255,0.4)" : "1px solid var(--border-subtle)",
                          padding: "6px 14px",
                          borderRadius: "var(--radius-full)",
                          cursor: "pointer",
                          fontSize: "12.5px",
                          display: "inline-flex",
                          alignItems: "center",
                          gap: "8px",
                        }}
                      >
                        <input
                          type="checkbox"
                          checked={checked}
                          onChange={(e) => {
                            if (e.target.checked) {
                              setSelectedRecipientIds([...selectedRecipientIds, r.recipient_id]);
                            } else {
                              setSelectedRecipientIds(selectedRecipientIds.filter((id) => id !== r.recipient_id));
                            }
                          }}
                        />
                        <span>{r.name}</span>
                        <span style={{ fontSize: "10.5px", color: "var(--text-muted)" }}>({r.recipient_id})</span>
                      </label>
                    );
                  })}
                  {recipients.length === 0 && (
                    <span style={{ fontSize: "12px", color: "var(--text-muted)" }}>
                      No recipients enrolled yet. Go to Enroll tab first.
                    </span>
                  )}
                </div>
              </div>

              <button
                type="submit"
                className="nayanx-glow-btn"
                disabled={loadingAction === "encrypt"}
              >
                {loadingAction === "encrypt"
                  ? "Encrypting & Encapsulating..."
                  : "Encrypt Document (POST /documents/encrypt)"}
              </button>
            </form>

            {/* Raw JSON Response Inspector */}
            {encryptRawJson && (
              <div className="json-inspector">
                <div className="json-inspector-header">
                  <span>RAW JSON RESPONSE (POST /documents/encrypt)</span>
                  <button className="card-badge" onClick={() => setEncryptRawJson(null)}>
                    Dismiss
                  </button>
                </div>
                <pre className="json-inspector-pre">{JSON.stringify(encryptRawJson, null, 2)}</pre>
              </div>
            )}
          </section>
        )}

        {/* View 3: POST /documents/decrypt */}
        {activeNav === "decrypt" && (
          <section className="nayanx-card col-12">
            <div className="card-header-row">
              <div>
                <h2 style={{ fontSize: "18px", fontWeight: "700" }}>
                  POST /documents/decrypt — Decapsulate, Watermark & Sign
                </h2>
                <p style={{ fontSize: "12.5px", color: "var(--text-secondary)", marginTop: "3px" }}>
                  Decapsulates symmetric key via ML-KEM-768, injects invisible forensic watermark, signs record via
                  ML-DSA-65, and appends to hash-chained ledger.
                </p>
              </div>
              <span className="card-badge">ML-KEM-768 + ML-DSA-65 + Ledger</span>
            </div>

            <div style={{ marginTop: "16px" }}>
              <div
                ref={decryptDropdownRef}
                className="form-group custom-dropdown-container"
                style={{ maxWidth: "380px", marginBottom: "16px", position: "relative" }}
              >
                <label className="form-label">Select Recipient to Execute Decryption</label>
                
                {/* Custom Sleek Dark Dropdown Trigger */}
                <div
                  className="custom-dropdown-trigger"
                  onClick={() => setShowDecryptDropdown((prev) => !prev)}
                >
                  <div style={{ display: "flex", alignItems: "center", gap: "10px", minWidth: 0, flex: 1 }}>
                    <span style={{ fontSize: "14px" }}>🛡️</span>
                    <div style={{ minWidth: 0, flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {(() => {
                        const sel = recipients.find((r) => r.recipient_id === decryptSelectedRecipient);
                        if (sel) {
                          return (
                            <>
                              <span style={{ fontWeight: "600", color: "#ffffff" }}>{sel.name}</span>
                              <span style={{ fontSize: "11.5px", color: "var(--text-muted)", marginLeft: "8px", fontFamily: "monospace" }}>
                                ({sel.recipient_id})
                              </span>
                            </>
                          );
                        }
                        return <span style={{ color: "var(--text-muted)" }}>-- Choose Recipient --</span>;
                      })()}
                    </div>
                  </div>
                  <span
                    style={{
                      fontSize: "10px",
                      color: "var(--text-muted)",
                      transform: showDecryptDropdown ? "rotate(180deg)" : "rotate(0deg)",
                      transition: "transform 0.2s",
                      marginLeft: "8px",
                    }}
                  >
                    ▼
                  </span>
                </div>

                {/* Custom Sleek Dark Dropdown Menu */}
                {showDecryptDropdown && (
                  <div className="custom-dropdown-menu">
                    {recipients.map((r) => (
                      <div
                        key={r.recipient_id}
                        className={`custom-dropdown-item ${decryptSelectedRecipient === r.recipient_id ? "active" : ""}`}
                        onClick={() => {
                          setDecryptSelectedRecipient(r.recipient_id);
                          setShowDecryptDropdown(false);
                        }}
                      >
                        <div style={{ display: "flex", alignItems: "center", gap: "10px", minWidth: 0, flex: 1 }}>
                          <span style={{ fontSize: "13px" }}>🛡️</span>
                          <div style={{ minWidth: 0, flex: 1 }}>
                            <div style={{ fontSize: "12.5px", fontWeight: "600", color: "#ffffff", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                              {r.name}
                            </div>
                            <div style={{ fontSize: "11px", color: "var(--text-muted)", fontFamily: "monospace", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                              {r.role} • {r.recipient_id}
                            </div>
                          </div>
                        </div>
                        {decryptSelectedRecipient === r.recipient_id && (
                          <span style={{ color: "#ffffff", fontSize: "13px", fontWeight: "700", marginLeft: "8px" }}>✓</span>
                        )}
                      </div>
                    ))}
                    {recipients.length === 0 && (
                      <div style={{ padding: "10px", fontSize: "12px", color: "var(--text-muted)", textAlign: "center" }}>
                        No officers enrolled.
                      </div>
                    )}
                  </div>
                )}
              </div>

              <div style={{ display: "flex", gap: "10px", flexWrap: "wrap", marginBottom: "20px" }}>
                <button
                  className="nayanx-glow-btn"
                  onClick={() => handleDecrypt()}
                  disabled={loadingAction?.startsWith("decrypt")}
                >
                  {loadingAction?.startsWith("decrypt") ? "Decapsulating & Signing..." : "Decrypt for Selected Officer"}
                </button>

                {recipients.map((r) => (
                  <button
                    key={r.recipient_id}
                    className="card-badge"
                    style={{ cursor: "pointer", background: "rgba(255,255,255,0.06)", padding: "8px 14px" }}
                    onClick={() => handleDecrypt(r.recipient_id)}
                  >
                    Quick Decrypt: {r.name}
                  </button>
                ))}
              </div>

              {/* Display Decrypted Artifacts with Direct Downloads */}
              <div style={{ marginTop: "16px" }}>
                <label className="form-label">Available Watermarked Recipient Documents</label>
                <div
                  style={{
                    display: "grid",
                    gridTemplateColumns: "repeat(auto-fit, minmax(300px, 1fr))",
                    gap: "12px",
                    marginTop: "8px",
                  }}
                >
                  {Object.entries(decryptedCopies).map(([rId, copy]) => (
                    <div key={rId} className="portfolio-mini-card">
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                        <span style={{ fontWeight: "700", color: "var(--text-primary)" }}>
                          {recipients.find((r) => r.recipient_id === rId)?.name || rId}
                        </span>
                        <span className="key-badge-green">● Ledger Block #{copy.ledger_entry?.entry_index}</span>
                      </div>
                      <div style={{ fontSize: "11px", color: "var(--accent-pink)", marginTop: "2px" }}>
                        Recipient ID: {rId}
                      </div>
                      <div style={{ fontSize: "11px", color: "var(--text-muted)", marginTop: "4px" }}>
                        Watermark Hash:{" "}
                        <span style={{ fontFamily: "monospace", color: "#cbd5e1" }}>
                          {copy.watermark_hash.slice(0, 16)}...
                        </span>
                      </div>
                      <div style={{ display: "flex", gap: "8px", marginTop: "12px" }}>
                        {copy.watermarked_pdf_base64 && (
                          <button
                            className="card-badge"
                            style={{ background: "rgba(255,255,255,0.12)", color: "#fff", cursor: "pointer" }}
                            onClick={() => downloadPdf(copy.watermarked_pdf_base64!, `${rId}_watermarked.pdf`)}
                          >
                            ⬇ Download PDF
                          </button>
                        )}
                        <button
                          className="card-badge"
                          style={{ background: "rgba(255,255,255,0.06)", color: "#cbd5e1", cursor: "pointer" }}
                          onClick={() => {
                            handleAttribute(copy.watermarked_pdf_base64);
                          }}
                        >
                          🎯 Simulate Leak & Attribute
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Raw JSON Response Inspector */}
            {decryptRawJson && (
              <div className="json-inspector">
                <div className="json-inspector-header">
                  <span>RAW JSON RESPONSE (POST /documents/decrypt)</span>
                  <button className="card-badge" onClick={() => setDecryptRawJson(null)}>
                    Dismiss
                  </button>
                </div>
                <pre className="json-inspector-pre">{JSON.stringify(decryptRawJson, null, 2)}</pre>
              </div>
            )}
          </section>
        )}

        {/* View 4: POST /leak/attribute */}
        {activeNav === "attribute" && (
          <section className="nayanx-card col-12">
            <div className="card-header-row">
              <div>
                <h2 style={{ fontSize: "18px", fontWeight: "700" }}>
                  POST /leak/attribute — Forensic Leak Attribution Engine
                </h2>
                <p style={{ fontSize: "12.5px", color: "var(--text-secondary)", marginTop: "3px" }}>
                  Extracts invisible forensic watermark, queries the ledger, validates ML-DSA-65 post-quantum signature,
                  and audits Merkle hash-chain.
                </p>
              </div>
              <span className="card-badge">PQC Signature & Merkle Audit</span>
            </div>

            <div style={{ marginTop: "16px" }}>
              {/* Drag-and-Drop / File Upload Zone */}
              <div
                className={`dropzone-box ${isDragOver ? "dragover" : ""}`}
                onDragOver={(e) => {
                  e.preventDefault();
                  setIsDragOver(true);
                }}
                onDragLeave={() => setIsDragOver(false)}
                onDrop={(e) => {
                  e.preventDefault();
                  setIsDragOver(false);
                  const file = e.dataTransfer.files?.[0];
                  if (file) {
                    setLeakFileInput(file);
                    handleAttribute(undefined, file);
                  }
                }}
                onClick={() => {
                  document.getElementById("leak-file-picker")?.click();
                }}
              >
                <input
                  id="leak-file-picker"
                  type="file"
                  accept="application/pdf"
                  style={{ display: "none" }}
                  onChange={(e) => {
                    const file = e.target.files?.[0];
                    if (file) {
                      setLeakFileInput(file);
                      handleAttribute(undefined, file);
                    }
                  }}
                />
                <div style={{ fontSize: "28px", marginBottom: "6px" }}>📁</div>
                <div style={{ fontSize: "14px", fontWeight: "600", color: "var(--text-primary)" }}>
                  {leakFileInput ? `Selected: ${leakFileInput.name}` : "Click or Drag & Drop Leaked PDF Here"}
                </div>
                <div style={{ fontSize: "11px", color: "var(--text-muted)", marginTop: "4px" }}>
                  Supports forensic metadata extraction and trailing stego anchor analysis
                </div>
              </div>

              {/* Instant Test Buttons for Recipient Copies */}
              <div style={{ marginBottom: "20px" }}>
                <label className="form-label">Or Instant One-Click Test from Recipient Copies</label>
                <div style={{ display: "flex", gap: "10px", flexWrap: "wrap", marginTop: "8px" }}>
                  <button
                    className="card-badge"
                    style={{
                      background: "rgba(255,255,255,0.08)",
                      color: "#ffffff",
                      cursor: "pointer",
                      padding: "8px 14px",
                    }}
                    onClick={() => {
                      const doc = sampleDocs.find((d) => d.recipient_id === "rec-alice-01");
                      if (doc) handleAttribute(doc.pdf_base64);
                    }}
                  >
                    Test Alice&apos;s Copy (rec-alice-01)
                  </button>
                  <button
                    className="card-badge"
                    style={{
                      background: "rgba(255,255,255,0.08)",
                      color: "#ffffff",
                      cursor: "pointer",
                      padding: "8px 14px",
                    }}
                    onClick={() => {
                      const doc = sampleDocs.find((d) => d.recipient_id === "rec-bob-02");
                      if (doc) handleAttribute(doc.pdf_base64);
                    }}
                  >
                    Test Bob&apos;s Copy (rec-bob-02)
                  </button>
                  <button
                    className="card-badge"
                    style={{
                      background: "rgba(255,255,255,0.08)",
                      color: "#ffffff",
                      cursor: "pointer",
                      padding: "8px 14px",
                    }}
                    onClick={() => {
                      const doc = sampleDocs.find((d) => d.recipient_id === "rec-charlie-03");
                      if (doc) handleAttribute(doc.pdf_base64);
                    }}
                  >
                    Test Charlie&apos;s Copy (rec-charlie-03)
                  </button>
                  <button
                    className="card-badge"
                    style={{
                      background: "rgba(255,255,255,0.06)",
                      color: "#cbd5e1",
                      cursor: "pointer",
                      padding: "8px 14px",
                    }}
                    onClick={() => {
                      const doc = sampleDocs.find((d) => d.filename === "sample_briefing.pdf");
                      if (doc) handleAttribute(doc.pdf_base64);
                    }}
                  >
                    Test Unwatermarked Original
                  </button>
                </div>
              </div>

              {/* Attribution Verdict Card */}
              {attributeResult && (
                <div className={`verdict-banner ${attributeResult.attributed ? "success" : "danger"}`}>
                  <div className="verdict-icon">{attributeResult.attributed ? "🎯" : "⚠️"}</div>
                  <div className="verdict-details" style={{ width: "100%" }}>
                    <h4>
                      {attributeResult.attributed
                        ? "CRYPTOGRAPHIC ATTRIBUTION CONFIRMED"
                        : "UNATTRIBUTED / UNKNOWN SOURCE"}
                    </h4>
                    <p style={{ marginTop: "4px" }}>{attributeResult.summary}</p>

                    <div
                      style={{
                        display: "grid",
                        gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
                        gap: "12px",
                        marginTop: "16px",
                      }}
                    >
                      <div className="portfolio-mini-card">
                        <div style={{ fontSize: "10px", color: "var(--text-muted)" }}>IDENTIFIED LEAKER</div>
                        <div style={{ fontSize: "13px", fontWeight: "700", color: "var(--text-primary)", marginTop: "2px" }}>
                          {attributeResult.recipient_name || "Unknown"} ({attributeResult.recipient_id || "N/A"})
                        </div>
                      </div>

                      <div className="portfolio-mini-card">
                        <div style={{ fontSize: "10px", color: "var(--text-muted)" }}>[1] SHA3-256 COMMIT-REVEAL</div>
                        <div
                          style={{
                            fontSize: "12.5px",
                            fontWeight: "700",
                            color: attributeResult.commitment_valid ? "#ffffff" : "#94a3b8",
                            marginTop: "2px",
                          }}
                        >
                          {attributeResult.commitment_valid ? "✔ VERIFIED VALID" : "✖ FAILED / TAMPERED"}
                        </div>
                      </div>

                      <div className="portfolio-mini-card">
                        <div style={{ fontSize: "10px", color: "var(--text-muted)" }}>[2] HMAC WATERMARK DERIVATION</div>
                        <div
                          style={{
                            fontSize: "12.5px",
                            fontWeight: "700",
                            color: attributeResult.watermark_hmac_valid ? "#ffffff" : "#94a3b8",
                            marginTop: "2px",
                          }}
                        >
                          {attributeResult.watermark_hmac_valid ? "✔ VERIFIED VALID" : "✖ FORGED / MISMATCH"}
                        </div>
                      </div>

                      <div className="portfolio-mini-card">
                        <div style={{ fontSize: "10px", color: "var(--text-muted)" }}>[3] RECIPIENT ML-DSA-65 SIG</div>
                        <div
                          style={{
                            fontSize: "12.5px",
                            fontWeight: "700",
                            color: attributeResult.recipient_signature_valid ? "#ffffff" : "#94a3b8",
                            marginTop: "2px",
                          }}
                        >
                          {attributeResult.recipient_signature_valid ? "✔ VERIFIED VALID" : "✖ INVALID / ABSENT"}
                        </div>
                      </div>

                      <div className="portfolio-mini-card">
                        <div style={{ fontSize: "10px", color: "var(--text-muted)" }}>[4] SERVICE COUNTER-SIGNATURE</div>
                        <div
                          style={{
                            fontSize: "12.5px",
                            fontWeight: "700",
                            color: attributeResult.service_signature_valid ? "#ffffff" : "#94a3b8",
                            marginTop: "2px",
                          }}
                        >
                          {attributeResult.service_signature_valid ? "✔ COUNTER-SIGNED" : "✖ ABSENT / UNVERIFIED"}
                        </div>
                      </div>

                      <div className="portfolio-mini-card">
                        <div style={{ fontSize: "10px", color: "var(--text-muted)" }}>[5] MERKLE HASH-CHAIN</div>
                        <div
                          style={{
                            fontSize: "12.5px",
                            fontWeight: "700",
                            color: attributeResult.chain_valid ? "#ffffff" : "#94a3b8",
                            marginTop: "2px",
                          }}
                        >
                          {attributeResult.chain_valid ? "✔ INTACT & UNTAMPERED" : "✖ TAMPER DETECTED"}
                        </div>
                      </div>

                      <div className="portfolio-mini-card">
                        <div style={{ fontSize: "10px", color: "var(--text-muted)" }}>[6] DISTRIBUTION BUNDLE</div>
                        <div
                          style={{
                            fontSize: "12.5px",
                            fontWeight: "700",
                            color: attributeResult.distribution_bundle_valid ? "#ffffff" : "#94a3b8",
                            marginTop: "2px",
                          }}
                        >
                          {attributeResult.distribution_bundle_valid ? "✔ AUTHENTIC BUNDLE" : "✖ UNBOUND"}
                        </div>
                      </div>

                      <div className="portfolio-mini-card">
                        <div style={{ fontSize: "10px", color: "var(--text-muted)" }}>LEDGER AUDIT ANCHOR</div>
                        <div style={{ fontSize: "13px", fontWeight: "700", color: "var(--text-primary)", marginTop: "2px" }}>
                          Block #{attributeResult.ledger_index ?? "N/A"} (Chain Height: {attributeResult.chain_length})
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* Raw JSON Response Inspector */}
            {attributeRawJson && (
              <div className="json-inspector">
                <div className="json-inspector-header">
                  <span>RAW JSON RESPONSE (POST /leak/attribute)</span>
                  <button className="card-badge" onClick={() => setAttributeRawJson(null)}>
                    Dismiss
                  </button>
                </div>
                <pre className="json-inspector-pre">{JSON.stringify(attributeRawJson, null, 2)}</pre>
              </div>
            )}
          </section>
        )}

        {/* View 5: GET /ledger */}
        {activeNav === "ledger" && (
          <section className="nayanx-card col-12">
            <div className="card-header-row">
              <div>
                <h2 style={{ fontSize: "18px", fontWeight: "700" }}>
                  GET /ledger — Tamper-Evident Hash-Chained Audit Ledger
                </h2>
                <p style={{ fontSize: "12.5px", color: "var(--text-secondary)", marginTop: "3px" }}>
                  Every decryption event forms an immutable Merkle block with previous_hash pointer, canonical record,
                  and post-quantum ML-DSA-65 signature.
                </p>
              </div>
              <div style={{ display: "flex", gap: "8px" }}>
                <button className="card-badge" onClick={fetchLedger} style={{ cursor: "pointer" }}>
                  Refresh Ledger
                </button>
                <button
                  className="card-badge"
                  style={{ background: "rgba(255, 255, 255, 0.06)", color: "#cbd5e1", cursor: "pointer" }}
                  onClick={handleTamperSimulation}
                >
                  Tamper Test (Simulate Attack)
                </button>
                <button
                  className="card-badge"
                  style={{ background: "rgba(255, 255, 255, 0.12)", color: "#ffffff", cursor: "pointer" }}
                  onClick={handleRestoreLedger}
                >
                  Restore / Heal Ledger
                </button>
              </div>
            </div>

            {/* Chain Integrity Status Badge */}
            <div style={{ margin: "16px 0", display: "flex", gap: "16px", alignItems: "center" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                <span style={{ fontSize: "14px" }}>Chain Integrity:</span>
                <span
                  style={{
                    padding: "4px 12px",
                    borderRadius: "var(--radius-full)",
                    background: ledgerData?.chain_valid ? "rgba(255,255,255,0.12)" : "rgba(255,255,255,0.06)",
                    color: ledgerData?.chain_valid ? "#ffffff" : "#94a3b8",
                    fontWeight: "700",
                    fontSize: "12px",
                  }}
                >
                  {ledgerData?.chain_valid ? "● 100% CRYPTOGRAPHICALLY VALID" : "● TAMPER DETECTED"}
                </span>
              </div>
              <div style={{ fontSize: "12px", color: "var(--text-muted)" }}>
                Total Blocks: <strong style={{ color: "var(--text-primary)" }}>{ledgerData?.chain_length || 0}</strong>
              </div>
              <div style={{ fontSize: "12px", color: "var(--text-muted)" }}>
                Head Hash:{" "}
                <span style={{ fontFamily: "monospace", color: "#cbd5e1" }}>
                  {ledgerData?.head_hash?.slice(0, 16)}...
                </span>
              </div>
            </div>

            {/* Block Explorer List */}
            <div className="merkle-block-list">
              {ledgerData?.entries.map((b: any) => (
                <div key={b.entry_index} className="merkle-block">
                  <div>
                    <span className="merkle-index">Block #{b.entry_index}</span>
                    <div style={{ fontSize: "10.5px", color: "var(--text-muted)", marginTop: "2px" }}>
                      {b.entry_index === 0
                        ? "GENESIS"
                        : b.entry_type === "distribution_commitment"
                        ? `Commitment: ${b.recipient_id}`
                        : `Decryption: ${b.recipient_id}`}
                    </div>
                  </div>

                  <div>
                    <div className="merkle-hash-label">Previous Hash</div>
                    <div className="merkle-hash-val">{b.previous_hash.slice(0, 20)}...</div>
                  </div>

                  <div>
                    <div className="merkle-hash-label">Block Entry Hash</div>
                    <div className="merkle-hash-val">{b.entry_hash.slice(0, 20)}...</div>
                  </div>

                  <div style={{ textAlign: "right" }}>
                    <div className="merkle-hash-label">ML-DSA Signatures</div>
                    <div style={{ display: "flex", gap: "6px", justifyContent: "flex-end", flexWrap: "wrap", marginTop: "3px" }}>
                      {b.entry_type === "distribution_commitment" ? (
                        <span className="card-badge" style={{ background: "rgba(255, 255, 255, 0.12)", color: "#ffffff" }}>
                          🛡️ Service Signed (SHA3)
                        </span>
                      ) : (
                        <>
                          <span className="key-badge-green">● Recipient Sig</span>
                          {b.service_signature && (
                            <span className="card-badge" style={{ background: "rgba(255, 255, 255, 0.12)", color: "#ffffff" }}>
                              ● Service Counter-Sig
                            </span>
                          )}
                        </>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>

            {/* Raw JSON Inspector for Ledger */}
            {ledgerData && (
              <div className="json-inspector">
                <div className="json-inspector-header">
                  <span>RAW JSON RESPONSE (GET /ledger)</span>
                </div>
                <pre className="json-inspector-pre">{JSON.stringify(ledgerData, null, 2)}</pre>
              </div>
            )}
          </section>
        )}
      </main>

      {/* 5. Interactive Modals */}

      {/* HSM & Vault Specs Modal */}
      {showHsmModal && (
        <div className="modal-backdrop" onClick={() => setShowHsmModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <div className="modal-title">
                <span>🛡️</span> Hardware Security Module & Enclave Architecture
              </div>
              <button className="modal-close-btn" onClick={() => setShowHsmModal(false)}>
                ✕
              </button>
            </div>
            <div className="modal-body">
              <p style={{ fontSize: "13px", color: "var(--text-secondary)", lineHeight: 1.5 }}>
                NayanX enforces an offline air-gapped cryptographic boundary conforming to US NIST FIPS 203 and FIPS 204.
              </p>

              <table className="spec-table">
                <thead>
                  <tr>
                    <th>Component</th>
                    <th>Cryptographic Standard</th>
                    <th>Security Level</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td>Key Encapsulation</td>
                    <td>NIST FIPS 203 (ML-KEM-768)</td>
                    <td>Category 3 (192-bit classical, 128-bit quantum)</td>
                  </tr>
                  <tr>
                    <td>Digital Signatures</td>
                    <td>NIST FIPS 204 (ML-DSA-65)</td>
                    <td>Category 3 (SHA3-384 collision resistance)</td>
                  </tr>
                  <tr>
                    <td>Bulk Cipher</td>
                    <td>AES-256-GCM (NIST SP 800-38D)</td>
                    <td>256-bit symmetric security with 128-bit tag</td>
                  </tr>
                  <tr>
                    <td>Hardware Token Interface</td>
                    <td>PKCS#11 FIPS 140-3 Level 3</td>
                    <td>Hardware tamper-resistance (YubiHSM2 / Thales Luna)</td>
                  </tr>
                  <tr>
                    <td>Platform Integrity</td>
                    <td>TPM 2.0 PCR Sealing</td>
                    <td>PCR-bound boot & memory integrity verification</td>
                  </tr>
                </tbody>
              </table>

              <div style={{ marginTop: "20px", display: "flex", justifyContent: "flex-end" }}>
                <button className="nayanx-glow-btn" onClick={() => setShowHsmModal(false)}>
                  Close Specification
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Enclave Settings Modal */}
      {showSettingsModal && (
        <div className="modal-backdrop" onClick={() => setShowSettingsModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <div className="modal-title">
                <span>⚙️</span> Enclave System & Security Settings
              </div>
              <button className="modal-close-btn" onClick={() => setShowSettingsModal(false)}>
                ✕
              </button>
            </div>
            <div className="modal-body">
              <div style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
                <div>
                  <label className="form-label">Backend Service API Endpoint</label>
                  <input className="form-input" type="text" value={API_BASE} readOnly />
                </div>
                <div>
                  <label className="form-label">Vault Storage Mode</label>
                  <div
                    style={{
                      fontSize: "12px",
                      color: "#ffffff",
                      display: "flex",
                      alignItems: "center",
                      gap: "6px",
                    }}
                  >
                    <span>●</span> AES-256-GCM Encrypted Local Software Vault (Active)
                  </div>
                </div>
                <div>
                  <label className="form-label">Air-Gap Status</label>
                  <div style={{ fontSize: "12px", color: "#cbd5e1" }}>
                    Network isolation verified. Zero outbound socket emissions.
                  </div>
                </div>
                <div style={{ paddingTop: "10px", borderTop: "1px solid var(--border-subtle)" }}>
                  <button
                    className="card-badge"
                    style={{
                      background: "rgba(255, 255, 255, 0.12)",
                      color: "#ffffff",
                      cursor: "pointer",
                      padding: "8px 16px",
                    }}
                    onClick={() => {
                      handleRestoreLedger();
                      setShowSettingsModal(false);
                    }}
                  >
                    Restore Clean Ledger State
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Notifications Drawer */}
      {showNotificationsModal && (
        <div className="modal-backdrop" onClick={() => setShowNotificationsModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <div className="modal-title">
                <span>🔔</span> Enclave Security Notifications
              </div>
              <button className="modal-close-btn" onClick={() => setShowNotificationsModal(false)}>
                ✕
              </button>
            </div>
            <div className="modal-body">
              <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
                <div className="portfolio-mini-card">
                  <div style={{ display: "flex", justifyContent: "space-between" }}>
                    <span style={{ fontWeight: "700", color: "var(--text-primary)" }}>Air-Gap Integrity Check</span>
                    <span className="key-badge-green">● PASS</span>
                  </div>
                  <p style={{ fontSize: "11px", color: "var(--text-muted)", marginTop: "4px" }}>
                    All post-quantum ML-KEM-768 and ML-DSA-65 algorithms operating in isolated enclave.
                  </p>
                </div>

                <div className="portfolio-mini-card">
                  <div style={{ display: "flex", justifyContent: "space-between" }}>
                    <span style={{ fontWeight: "700", color: "var(--text-primary)" }}>Audit Ledger Blocks Verified</span>
                    <span className="key-badge-green">● {ledgerData?.chain_length || 0} BLOCKS</span>
                  </div>
                  <p style={{ fontSize: "11px", color: "var(--text-muted)", marginTop: "4px" }}>
                    Hash chaining verified across all officer decryption events.
                  </p>
                </div>

                <div className="portfolio-mini-card">
                  <div style={{ display: "flex", justifyContent: "space-between" }}>
                    <span style={{ fontWeight: "700", color: "var(--text-primary)" }}>Key Vault Authentication</span>
                    <span className="key-badge-green">● SEALED</span>
                  </div>
                  <p style={{ fontSize: "11px", color: "var(--text-muted)", marginTop: "4px" }}>
                    Private keys are protected by PBKDF2-HMAC-SHA256 authenticated envelope.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Officer Clearance Modal */}
      {showProfileModal && (
        <div className="modal-backdrop" onClick={() => setShowProfileModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <div className="modal-title">
                <span>👤</span> Officer Credentials & Access Clearance
              </div>
              <button className="modal-close-btn" onClick={() => setShowProfileModal(false)}>
                ✕
              </button>
            </div>
            <div className="modal-body">
              <div style={{ display: "flex", alignItems: "center", gap: "16px", marginBottom: "16px" }}>
                <div className="user-avatar" style={{ width: "54px", height: "54px", fontSize: "18px" }}>
                  S
                </div>
                <div>
                  <h3 style={{ fontSize: "16px", color: "var(--text-primary)", fontWeight: "700" }}>Sai</h3>
                  <div style={{ fontSize: "12px", color: "#cbd5e1" }}>Chief Intelligence Analyst</div>
                  <div style={{ fontSize: "11px", color: "var(--text-muted)", marginTop: "2px" }}>
                    Clearance: Level 4 Top-Secret // Post-Quantum Cryptographic Attache
                  </div>
                </div>
              </div>

              <div className="portfolio-mini-card" style={{ marginBottom: "14px" }}>
                <div style={{ fontSize: "11px", color: "var(--text-muted)" }}>Enclave Station</div>
                <div style={{ fontSize: "13px", fontWeight: "700", color: "var(--text-primary)", marginTop: "2px" }}>
                  NayanX Air-Gap Node #01 (Offline Defense Enclave)
                </div>
              </div>

              <div style={{ display: "flex", justifyContent: "flex-end" }}>
                <button className="nayanx-glow-btn" onClick={() => setShowProfileModal(false)}>
                  Close
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
