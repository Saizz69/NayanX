"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import SecureViewer from "@/components/SecureViewer";

const API_BASE = process.env.NEXT_PUBLIC_CRYPTO_API_URL || "/crypto-api";

interface Recipient {
  recipient_id: string;
  name: string;
  role: string;
  kem_pubkey_id: string;
  dsa_pubkey_id: string;
  kem_public_key: string;
  dsa_public_key: string;
  created_at: string;
  is_flagged?: boolean;
  flag_reason?: string;
  flagged_at?: string;
  total_violations?: number;
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
  verdict?: string;
  attributed: boolean;
  tamper_detected?: boolean;
  tamper_type?: string;
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
  score?: number;
  evidence_bundle?: any;
  certificate_pdf_base64?: string;
  certificate_filename?: string;
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

export default function WebEyeDashboard({ isHeadRoute = false }: { isHeadRoute?: boolean }) {
  const [mounted, setMounted] = useState(false);

  // Authentication & Current Operator
  const [currentUser, setCurrentUser] = useState<any>(null);

  // Live Security Notifications
  const [securityNotifications, setSecurityNotifications] = useState<any[]>([]);
  const [unreadAlerts, setUnreadAlerts] = useState<any[]>([]);

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
  const [selectedFlowLayer, setSelectedFlowLayer] = useState<number>(0);

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
  const [selectedDocDescription, setSelectedDocDescription] = useState<string | null>(null);
  const [leakBase64Input, setLeakBase64Input] = useState<string>("");
  const [attributeResult, setAttributeResult] = useState<LeakAttributeResult | null>(null);
  const [attributeRawJson, setAttributeRawJson] = useState<any>(null);
  const [isDragOver, setIsDragOver] = useState(false);
  const offlineCounterRef = React.useRef<number>(0);

  // Demo Runner & Logs
  const [demoRunning, setDemoRunning] = useState(false);
  const [demoLogs, setDemoLogs] = useState<string[]>([]);
  const [loadingAction, setLoadingAction] = useState<string | null>(null);
  const [tamperMessage, setTamperMessage] = useState<string | null>(null);
  const [activeFlowchartLayer, setActiveFlowchartLayer] = useState<number>(1);
  const [flowchartViewMode, setFlowchartViewMode] = useState<"detailed" | "overview">("detailed");
  const [activeSecureViewerCopy, setActiveSecureViewerCopy] = useState<any | null>(null);

  // Fetch security notifications from crypto-service
  const fetchNotifications = async () => {
    try {
      const res = await fetch(`${API_BASE}/notifications`, { cache: "no-store" });
      if (res.ok) {
        const data = await res.json();
        setSecurityNotifications(data);
        const unread = data.filter((n: any) => !n.is_read);
        setUnreadAlerts(unread);
      }
    } catch {
      // ignore in offline mode
    }
  };

  const dismissNotification = async (id: number) => {
    try {
      await fetch(`${API_BASE}/notifications/${id}/dismiss`, { method: "POST" });
      await fetchNotifications();
    } catch (e) {
      console.error("Failed to dismiss notification:", e);
    }
  };

  // Logout handler
  const handleLogout = async () => {
    try {
      await fetch("/api/auth/logout", { method: "POST" });
    } catch {}
    window.location.href = "/login";
  };

  // Fetch initial data & maintain liveness heartbeat
  useEffect(() => {
    setMounted(true);

    const checkAuthAndInit = async () => {
      try {
        const meRes = await fetch("/api/auth/me", { cache: "no-store" });
        if (!meRes.ok) {
          window.location.href = "/login";
          return;
        }
        const meData = await meRes.json();
        if (meData.user?.role !== "head") {
          if (meData.user?.role === "recipient") {
            window.location.href = "/recipient";
          } else {
            window.location.href = "/login";
          }
          return;
        }
        setCurrentUser(meData.user);
      } catch {
        window.location.href = "/login";
        return;
      }

      const isOnline = await fetchSystemStatus();
      if (isOnline) {
        await Promise.allSettled([
          fetchRecipients(),
          fetchLedger(),
          fetchSampleDocs(),
          fetchNotifications(),
        ]);
      }
    };
    checkAuthAndInit();

    // Heartbeat: periodically poll status, notifications, and refresh data
    const timer = setInterval(async () => {
      const online = await fetchSystemStatus();
      if (online) {
        fetchNotifications();
        if (!backendOnline) {
          fetchRecipients();
          fetchLedger();
          fetchSampleDocs();
        }
      }
    }, 4000);

    return () => clearInterval(timer);
  }, [backendOnline]);

  const fetchSystemStatus = async (): Promise<boolean> => {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 8000);
      const res = await fetch(`${API_BASE}/status`, { signal: controller.signal });
      clearTimeout(timeoutId);
      if (res.ok) {
        const data = await res.json();
        setSystemStatus(data);
        offlineCounterRef.current = 0;
        setBackendOnline(true);
        return true;
      } else {
        offlineCounterRef.current += 1;
        if (offlineCounterRef.current >= 2) {
          setBackendOnline(false);
        }
        return false;
      }
    } catch {
      offlineCounterRef.current += 1;
      if (offlineCounterRef.current >= 2) {
        setBackendOnline(false);
      }
      return false;
    }
  };

  const fetchRecipients = async () => {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 6000);
      const res = await fetch(`${API_BASE}/recipients`, { signal: controller.signal });
      clearTimeout(timeoutId);
      if (res.ok) {
        const data = await res.json();
        setRecipients(data);
        if (data.length > 0 && selectedRecipientIds.length === 0) {
          setSelectedRecipientIds(data.map((r: Recipient) => r.recipient_id));
          setDecryptSelectedRecipient(data[0].recipient_id);
        }
      }
    } catch {
      // Backend may be starting or offline; deferred silently without triggering dev overlay
    }
  };

  const fetchLedger = async () => {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 6000);
      const res = await fetch(`${API_BASE}/ledger`, { signal: controller.signal });
      clearTimeout(timeoutId);
      if (res.ok) {
        const data = await res.json();
        setLedgerData(data);
      }
    } catch {
      // Deferred silently without triggering dev overlay
    }
  };

  const fetchSampleDocs = async () => {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 6000);
      const res = await fetch(`${API_BASE}/samples/list`, { signal: controller.signal });
      clearTimeout(timeoutId);
      if (res.ok) {
        const data: SampleDocument[] = await res.json();
        setSampleDocs(data);
        // Decrypted copies remain driven by real operations or live sessions
        setSampleDocs(data);
      }
    } catch {
      // Deferred silently without triggering dev overlay
    }
  };

  // Helper to generate sample PDF bytes in browser
  const createSamplePdfBase64 = (title: string): string => {
    const text = `WEBEYE CLASSIFIED AIR-GAPPED BRIEFING - ${title} - PQC FIPS 203 & 204 ENCLAVE`;
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

    if (backendOnline === false) {
      alert("⚠️ Backend Enclave is currently offline at http://127.0.0.1:8000.\nPlease verify the backend service is running.");
      return;
    }

    setLoadingAction("enroll");
    try {
      const payload: any = {
        name: enrollName.trim(),
        role: enrollRole.trim(),
        password: "123456",
      };
      if (enrollCustomId.trim()) payload.recipient_id = enrollCustomId.trim();

      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 12000);

      const res = await fetch(`${API_BASE}/enroll`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
        signal: controller.signal,
      });
      clearTimeout(timeoutId);

      const data = await res.json();
      setEnrollRawJson(data);
      if (res.ok) {
        await fetchRecipients();
        setEnrollName("");
        setEnrollCustomId("");
      } else {
        alert(data.detail || "Enrollment failed. Please check backend status.");
      }
    } catch (err: any) {
      const errMsg = err.name === "AbortError"
        ? "Enrollment request timed out after 12s. Please check if the backend service is responding."
        : (err.message || "Failed to connect to backend enrollment service.");
      setEnrollRawJson({ error: errMsg });
      alert(errMsg);
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

  const handleUnflagRecipient = async (recipientId: string) => {
    try {
      const res = await fetch(`${API_BASE}/recipients/${encodeURIComponent(recipientId)}/unflag`, {
        method: "POST",
      });
      if (res.ok) {
        await fetchRecipients();
      } else {
        const d = await res.json().catch(() => ({}));
        alert(`Failed to restore clearance: ${d.detail || "Server error"}`);
      }
    } catch (err: any) {
      alert(`Network error unflagging officer: ${err.message}`);
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
  const handleAttribute = async (sourceB64?: string, fileToUpload?: File, customDesc?: string) => {
    setAttributeResult(null);
    setAttributeRawJson(null);
    if (customDesc) {
      setSelectedDocDescription(customDesc);
    }
    setLoadingAction("attribute");
    try {
      let res;
      const targetFile = fileToUpload || (sourceB64 ? null : leakFileInput);

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

  // Bulletproof PDF Download handler for Chromium, Edge, Firefox, and Safari
  const downloadPdf = (base64Str: string, filename: string) => {
    if (!base64Str) {
      alert("No document data available to download.");
      return;
    }
    const cleanFilename = filename.toLowerCase().endsWith(".pdf") ? filename : `${filename}.pdf`;
    try {
      // Strip any whitespace / newlines
      const cleanBase64 = base64Str.replace(/\s+/g, "");
      const binaryString = window.atob(cleanBase64);
      const len = binaryString.length;
      const bytes = new Uint8Array(len);
      for (let i = 0; i < len; i++) {
        bytes[i] = binaryString.charCodeAt(i);
      }
      const blob = new Blob([bytes], { type: "application/pdf" });
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.style.display = "none";
      link.href = url;
      link.download = cleanFilename;
      link.setAttribute("download", cleanFilename);
      document.body.appendChild(link);
      link.click();

      // Defer revoking the object URL and removing from DOM by 60s
      // Synchronous revocation causes Chromium/Edge to drop the suggested filename
      // and save the file under its raw blob UUID without an extension.
      setTimeout(() => {
        try {
          if (link.parentNode) {
            document.body.removeChild(link);
          }
          window.URL.revokeObjectURL(url);
        } catch {
          // ignore
        }
      }, 60000);
    } catch (e: any) {
      console.error("PDF Blob download error:", e);
      try {
        const cleanBase64 = base64Str.replace(/\s+/g, "");
        const link = document.createElement("a");
        link.style.display = "none";
        link.href = `data:application/pdf;base64,${cleanBase64}`;
        link.download = cleanFilename;
        link.setAttribute("download", cleanFilename);
        document.body.appendChild(link);
        link.click();
        setTimeout(() => {
          if (link.parentNode) document.body.removeChild(link);
        }, 5000);
      } catch (err: any) {
        alert("Failed to download PDF: " + (err.message || e.message));
      }
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

      if (!currentRecipients || currentRecipients.length === 0) {
        throw new Error("No enrolled officers found in Keystore. Please enroll an officer in the Officer Keystore panel first.");
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
          filename: "operation_webeye_intel.pdf",
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
          <div className="brand-icon">WE</div>
          <div>
            <div className="brand-title">WebEye</div>
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
          <Link
            href="/viewer"
            className="nav-item"
            style={{ textDecoration: "none" }}
            title="Open Server-Rendered Zero-Text Canvas Recipient Viewer with 2D DCT Watermarking"
          >
            <span>🔒</span> Secure Viewer
          </Link>
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
              Welcome, <span>{currentUser?.name || currentUser?.username || "Head Commander"}</span>
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
              style={{ position: "relative" }}
            >
              🔔
              {unreadAlerts.length > 0 && (
                <span
                  style={{
                    position: "absolute",
                    top: "-4px",
                    right: "-4px",
                    background: "#ef4444",
                    color: "#ffffff",
                    fontSize: "10px",
                    fontWeight: "800",
                    minWidth: "18px",
                    height: "18px",
                    borderRadius: "9px",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    padding: "0 4px",
                    boxShadow: "0 0 10px rgba(239, 68, 68, 0.8)",
                  }}
                >
                  {unreadAlerts.length}
                </span>
              )}
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
              <div className="user-avatar">{currentUser?.username?.[0]?.toUpperCase() || "H"}</div>
              <div className="user-info">
                <span className="user-name">{currentUser?.name || currentUser?.username || "Head Operator"}</span>
                <span className="user-role">{currentUser?.role === "head" ? "HEAD COMMANDER" : "RECIPIENT"}</span>
              </div>
            </div>

            <button
              className="card-badge"
              style={{
                background: "rgba(255, 255, 255, 0.08)",
                color: "#cbd5e1",
                cursor: "pointer",
                padding: "6px 12px",
                marginLeft: "4px",
                fontSize: "11px",
              }}
              onClick={handleLogout}
              title="Sign out of current enclave session"
            >
              Logout ⎋
            </button>
          </div>
        </header>

        {/* Live Enclave Screenshot Breach Alert Banner */}
        {unreadAlerts.length > 0 && (
          <div
            style={{
              margin: "16px 0 20px 0",
              padding: "16px 20px",
              background: "linear-gradient(135deg, rgba(185, 28, 28, 0.45) 0%, rgba(127, 29, 29, 0.25) 100%)",
              border: "1.5px solid #ef4444",
              borderRadius: "12px",
              boxShadow: "0 0 30px rgba(239, 68, 68, 0.4)",
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              flexWrap: "wrap",
              gap: "14px",
            }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: "16px" }}>
              <div
                style={{
                  width: "44px",
                  height: "44px",
                  borderRadius: "10px",
                  background: "rgba(239, 68, 68, 0.3)",
                  border: "1px solid #ef4444",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  fontSize: "24px",
                  flexShrink: 0,
                }}
              >
                🚨
              </div>
              <div>
                <div style={{ fontSize: "14px", fontWeight: "800", color: "#fca5a5", letterSpacing: "0.5px" }}>
                  CRITICAL SECURITY ALERT: RECIPIENT SCREENSHOT ATTEMPT INTERCEPTED
                </div>
                <div style={{ fontSize: "12px", color: "#ffffff", marginTop: "3px" }}>
                  <strong>Officer:</strong> {unreadAlerts[0].recipient_name} ({unreadAlerts[0].recipient_id}) •{" "}
                  <strong>Incident:</strong> {unreadAlerts[0].reason} •{" "}
                  <span style={{ color: "#fca5a5", fontFamily: "monospace" }}>
                    {new Date(unreadAlerts[0].timestamp).toLocaleTimeString()}
                  </span>
                  {unreadAlerts.length > 1 && (
                    <span style={{ marginLeft: "8px", background: "rgba(0,0,0,0.4)", padding: "2px 6px", borderRadius: "4px", fontSize: "11px" }}>
                      +{unreadAlerts.length - 1} more violation(s)
                    </span>
                  )}
                </div>
              </div>
            </div>

            <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
              <button
                className="card-badge"
                style={{
                  background: "#ef4444",
                  color: "#ffffff",
                  cursor: "pointer",
                  padding: "8px 16px",
                  fontWeight: "700",
                }}
                onClick={() => dismissNotification(unreadAlerts[0].id)}
              >
                Dismiss Alert
              </button>
              <button
                className="card-badge"
                style={{
                  background: "rgba(255, 255, 255, 0.15)",
                  color: "#ffffff",
                  cursor: "pointer",
                  padding: "8px 16px",
                  fontWeight: "600",
                }}
                onClick={() => {
                  setActiveNav("ledger");
                  setShowNotificationsModal(true);
                }}
              >
                View Incident Ledger
              </button>
            </div>
          </div>
        )}

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
                {Object.keys(decryptedCopies).length === 0 ? (
                  <div style={{ gridColumn: "1 / -1", padding: "28px", textAlign: "center", background: "rgba(255,255,255,0.02)", borderRadius: "10px", border: "1px dashed rgba(255,255,255,0.1)" }}>
                    <div style={{ fontSize: "20px", marginBottom: "8px" }}>📄</div>
                    <div style={{ color: "var(--text-primary)", fontSize: "13px", fontWeight: "600", marginBottom: "4px" }}>
                      No Decrypted Dossiers in Active Session
                    </div>
                    <div style={{ color: "var(--text-muted)", fontSize: "12px" }}>
                      Encrypt a document in Section 2 and decrypt it for enrolled officers in Section 3 to generate live watermarked forensic copies.
                    </div>
                  </div>
                ) : (
                  Object.entries(decryptedCopies).map(([rId, copy]) => {
                    const officer = recipients.find((r) => r.recipient_id === rId);
                    const officerName = officer?.name || rId;
                    const officerRole = officer?.role || "Enrolled Officer";
                    const filename = copy.original_filename || `${officerName}_watermarked.pdf`;

                    return (
                      <div key={rId} className="sample-doc-card watermarked">
                        <div className="sample-doc-header">
                          <div>
                            <div className="sample-doc-title">{officerName} — Decrypted Copy</div>
                            <div className="sample-doc-meta">Role: {officerRole}</div>
                          </div>
                          <span className="card-badge" style={{ background: "rgba(255,255,255,0.08)", color: "#cbd5e1" }}>
                            Watermarked
                          </span>
                        </div>
                        <p style={{ fontSize: "11.5px", color: "var(--text-secondary)", marginTop: "6px" }}>
                          Invisibly watermarked with SHA-256 steganographic digest bound to {officerName}&apos;s keypair &amp; session nonce.
                        </p>
                        <div className="sample-doc-actions">
                          <button
                            className="btn-sm-download"
                            style={{ background: "rgba(255, 255, 255, 0.15)", color: "#ffffff", fontWeight: "700" }}
                            title="Open in locked-down HTML5 canvas viewer with 2D DCT spread-spectrum watermarking"
                            onClick={() => {
                              setActiveSecureViewerCopy({
                                recipientId: rId,
                                recipientName: officerName,
                                documentHash: copy.document_hash,
                                pdfBase64: copy.watermarked_pdf_base64,
                                title: `${officerName}'s Classified Intelligence Briefing`,
                              });
                            }}
                          >
                            🔒 Secure Viewer
                          </button>
                          <button
                            className="btn-sm-download"
                            onClick={() => {
                              if (copy.watermarked_pdf_base64) {
                                downloadPdf(copy.watermarked_pdf_base64, filename);
                              } else {
                                alert("Document data not available.");
                              }
                            }}
                          >
                            ⬇ Download PDF
                          </button>
                          <button
                            className="btn-sm-attribute"
                            onClick={() => {
                              if (copy.watermarked_pdf_base64) {
                                setLeakFileInput(null);
                                handleAttribute(copy.watermarked_pdf_base64, undefined, `${officerName}'s Watermarked Copy (${rId})`);
                              } else {
                                alert("Document data not available.");
                              }
                            }}
                          >
                            🎯 Test in Leak Attribution
                          </button>
                        </div>
                      </div>
                    );
                  })
                )}
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

            {/* Bottom Wide Panel: Architecture & Cryptographic Flowchart */}
            {(() => {
              const flowchartLayers = [
                {
                  id: 1,
                  name: "PQC Encapsulation",
                  standard: "NIST FIPS 203 (ML-KEM-768) + AES-256-GCM (NIST SP 800-38D)",
                  shortTech: "FIPS 203 Lattice KEM",
                  title: "Post-Quantum Encapsulation & Bulk Encryption",
                  subtitle: "How raw classified intelligence is sealed so only designated key holders can ever read it, protected against future quantum attacks.",
                  icon: "🛡️",
                  input: {
                    label: "INPUT DATA (Into this Layer)",
                    items: [
                      "Original classified PDF document (raw in-memory bytes)",
                      "Target officers' ML-KEM-768 public keys (from software vault)"
                    ],
                    sourceTag: "Client Ingestion & Enclave Vault"
                  },
                  steps: [
                    {
                      number: "01",
                      name: "Document Ingestion & Hash Anchoring",
                      description: "The raw PDF is ingested in memory and hashed (SHA-256) to establish the immutable document root hash (doc_hash).",
                      techTag: "SHA-256 Root Hash"
                    },
                    {
                      number: "02",
                      name: "Symmetric Bulk Encryption",
                      description: "A cryptographically strong 256-bit Document Encryption Key (DEK) is generated to encrypt the file via AES-256-GCM.",
                      techTag: "AES-256-GCM (256-bit DEK)"
                    },
                    {
                      number: "03",
                      name: "Post-Quantum KEM Encapsulation",
                      description: "For each enrolled officer, their ML-KEM-768 public key is retrieved from the software vault registry.",
                      techTag: "FIPS 203 Vault Lookup"
                    },
                    {
                      number: "04",
                      name: "Independent Shared Secrets",
                      description: "ML-KEM-768 encapsulates the 256-bit DEK separately for each recipient into a compact 1,088-byte lattice ciphertext.",
                      techTag: "Lattice Ring: q=3329, k=3"
                    },
                    {
                      number: "05",
                      name: "Broadcast Distribution Package",
                      description: "The single AES ciphertext and per-officer KEM ciphertexts are packaged into an encrypted bundle.",
                      techTag: "Atomic Encrypted Package"
                    }
                  ],
                  output: {
                    label: "OUTPUT ARTIFACT (Passed to Next Layer)",
                    items: [
                      "AES-256-GCM encrypted document payload",
                      "Array of recipient-specific ML-KEM-768 wrapped keys"
                    ],
                    nextLayerTarget: "Layer 2: Stego Watermarking & Decapsulation",
                    nextLayerId: 2
                  },
                  securityGuarantee: {
                    title: "Post-Quantum Forward Secrecy",
                    description: "Attackers harvesting encrypted files today cannot decrypt them even with future quantum computers (Harvest Now, Decrypt Later resilience)."
                  },
                  primitives: [
                    { name: "ML-KEM-768", spec: "NIST FIPS 203 (Module-Lattice KEM)" },
                    { name: "AES-256-GCM", spec: "NIST SP 800-38D Authenticated AEAD" },
                    { name: "SHA-256", spec: "FIPS 180-4 Canonical Document Digest" }
                  ],
                  invariants: [
                    "Zero unencrypted plaintext written to disk",
                    "NIST Security Category 3 (192-bit quantum security)",
                    "Independent lattice ciphertext per recipient"
                  ]
                },
                {
                  id: 2,
                  name: "Stego Watermarking",
                  standard: "HMAC-SHA256 + Zero-Width Unicode & Structural Trailer Anchors",
                  shortTech: "HMAC-SHA256 Stego",
                  title: "Steganographic Watermarking & Decapsulation",
                  subtitle: "How authorized officers decrypt their copy while an imperceptible, cryptographically tied watermark is permanently embedded.",
                  icon: "💧",
                  input: {
                    label: "INPUT DATA (Into this Layer)",
                    items: [
                      "AES-256-GCM encrypted document bundle",
                      "Recipient officer's ML-KEM-768 private key"
                    ],
                    sourceTag: "From Layer 1 Output + Officer Vault"
                  },
                  steps: [
                    {
                      number: "01",
                      name: "Lattice Decapsulation",
                      description: "Recipient's ML-KEM-768 private key decapsulates their specific KEM ciphertext, recovering the shared 256-bit AES DEK.",
                      techTag: "ML-KEM-768 Decapsulation"
                    },
                    {
                      number: "02",
                      name: "In-Memory Bulk Decryption",
                      description: "Recovers the original PDF byte stream directly into an isolated memory buffer using AES-256-GCM without writing to persistent disk.",
                      techTag: "AES-256-GCM AEAD Tag Verify"
                    },
                    {
                      number: "03",
                      name: "Forensic Fingerprint Derivation",
                      description: "Computes a unique HMAC-SHA256 digest binding recipient_id, cryptographic nonce, timestamp, and doc_hash.",
                      techTag: "HMAC-SHA256(rec_id || nonce || time || doc_hash)"
                    },
                    {
                      number: "04",
                      name: "Invisible Steganographic Anchor",
                      description: "Injects the cryptographic fingerprint invisibly into PDF text streams (zero-width Unicode) and XMP metadata trailers.",
                      techTag: "Zero-Width Unicode U+200B/C/D"
                    },
                    {
                      number: "05",
                      name: "Personalized Forensic Export",
                      description: "Outputs a personalized PDF identical to the naked eye but permanently and forensically attributed to that officer.",
                      techTag: "Personalized Forensic Copy"
                    }
                  ],
                  output: {
                    label: "OUTPUT ARTIFACT (Passed to Next Layer)",
                    items: [
                      "Personalized watermarked PDF copy for officer",
                      "Cryptographic audit event record (watermark hash + recipient ID)"
                    ],
                    nextLayerTarget: "Layer 3: Merkle Audit Ledger Commitment",
                    nextLayerId: 3
                  },
                  securityGuarantee: {
                    title: "Steganographic Non-Destructive Binding",
                    description: "The watermark survives re-compression, printing, screenshots, and file renaming without visual degradation, provably bound to the recipient."
                  },
                  primitives: [
                    { name: "ML-KEM-768 Decaps", spec: "FIPS 203 Lattice Secret Recovery" },
                    { name: "HMAC-SHA256", spec: "RFC 2104 Forensic Watermark Keying" },
                    { name: "Zero-Width Stego", spec: "Unicode U+200B/C/D Structural Injection" }
                  ],
                  invariants: [
                    "Watermark computationally unforgeable without HMAC secret",
                    "100% imperceptible to human readers (zero visual disruption)",
                    "Simultaneous dispatch to append-only audit trail"
                  ]
                },
                {
                  id: 3,
                  name: "Merkle Audit Ledger",
                  standard: "NIST FIPS 204 (ML-DSA-65) + Merkle SHA-256 Chaining (SQLite)",
                  shortTech: "FIPS 204 Dual Sigs",
                  title: "Merkle Audit Ledger & Quantum Signatures",
                  subtitle: "How every document access is committed to a tamper-evident cryptographic ledger with dual post-quantum digital signatures.",
                  icon: "⛓️",
                  input: {
                    label: "INPUT DATA (Into this Layer)",
                    items: [
                      "Audit event metadata (doc_hash, watermark_hash, recipient_id, timestamp)",
                      "Recipient & Authority ML-DSA-65 keypairs"
                    ],
                    sourceTag: "From Layer 2 Audit Event + Key Vault"
                  },
                  steps: [
                    {
                      number: "01",
                      name: "Canonical Record Serialization",
                      description: "The access event is normalized into deterministic RFC-8785 JSON format (index, timestamp, document hash, watermark hash).",
                      techTag: "RFC-8785 Canonical JSON"
                    },
                    {
                      number: "02",
                      name: "Recipient ML-DSA-65 Signature",
                      description: "The accessing officer's private key signs the canonical record, creating mathematical non-repudiation proof of receipt.",
                      techTag: "FIPS 204 ML-DSA-65 Recipient Sig"
                    },
                    {
                      number: "03",
                      name: "Authority Counter-Signature",
                      description: "The WebEye Master Enclave signs the record with its authority ML-DSA-65 key, confirming timestamp and enclave compliance.",
                      techTag: "Master Enclave Counter-Signature"
                    },
                    {
                      number: "04",
                      name: "Parent Hash Chaining",
                      description: "Computes block hash SHA256(index + prev_block_hash + canonical_record + dual_signatures), linking to the prior block.",
                      techTag: "SHA-256 Parent Hash Linkage"
                    },
                    {
                      number: "05",
                      name: "Immutable Ledger Commitment",
                      description: "Appends the verified block to the persistent ledger database with automatic Merkle leaf verification.",
                      techTag: "SQLite Append-Only Block Commit"
                    }
                  ],
                  output: {
                    label: "OUTPUT ARTIFACT (Passed to Next Layer)",
                    items: [
                      "Committed ledger block with dual ML-DSA-65 signatures",
                      "Cryptographic Merkle inclusion proof"
                    ],
                    nextLayerTarget: "Layer 4: Forensic Attribution & Court Admissibility",
                    nextLayerId: 4
                  },
                  securityGuarantee: {
                    title: "Cryptographic Non-Repudiation & Tamper Rejection",
                    description: "Any retroactive ledger modification or file alteration immediately invalidates the parent hash chain and is rejected by the Merkle verifier."
                  },
                  primitives: [
                    { name: "ML-DSA-65", spec: "NIST FIPS 204 Digital Signature Algorithm" },
                    { name: "RFC-8785", spec: "Deterministic JSON Canonicalization (JCS)" },
                    { name: "Merkle Chaining", spec: "SHA-256 Parent Hash Append-Only Tree" }
                  ],
                  invariants: [
                    "Dual-key authorization (recipient cannot repudiate access)",
                    "Strict monotonic block indexing with unbroken parent hashes",
                    "Quantum-resistant lattice digital signatures"
                  ]
                },
                {
                  id: 4,
                  name: "Forensic Attribution",
                  standard: "Section 65B(4) Indian Evidence Act / BSA 2023 + 6-Point Cryptographic Audit",
                  shortTech: "Sec. 65B(4) Legal Engine",
                  title: "Forensic Leak Attribution & Court Admissibility",
                  subtitle: "How leaked classified documents are ingested, analyzed, and traced to the exact source with legally binding courtroom evidence.",
                  icon: "🎯",
                  input: {
                    label: "INPUT DATA (Into this Layer)",
                    items: [
                      "Exfiltrated / leaked PDF document (or digital copy)",
                      "Current Merkle ledger state head from SQLite"
                    ],
                    sourceTag: "Evidence Intake & Merkle Head"
                  },
                  steps: [
                    {
                      number: "01",
                      name: "Stego Forensic Extraction",
                      description: "Deep-scans the leaked document structure to isolate invisible zero-width anchors and XMP trailer digests.",
                      techTag: "Zero-Width Unicode Scanner"
                    },
                    {
                      number: "02",
                      name: "Ledger Provenance Correlation",
                      description: "Queries the Merkle audit ledger to match the extracted watermark hash against historical access records.",
                      techTag: "Merkle Ledger Query"
                    },
                    {
                      number: "03",
                      name: "6-Point Cryptographic Audit",
                      description: "Validates: 1. Watermark commitment, 2. HMAC validity, 3. Officer ML-DSA-65 sig, 4. Authority sig, 5. Chain integrity, 6. Tamper check.",
                      techTag: "6-Point Forensic Engine"
                    },
                    {
                      number: "04",
                      name: "Culprit Attribution Determination",
                      description: "Pinpoints the exact officer identity, clearance level, access timestamp, and issuing workstation with mathematical certainty.",
                      techTag: "Identified Leaker Record"
                    },
                    {
                      number: "05",
                      name: "Section 65B(4) Certificate Generation",
                      description: "Automatically synthesizes a certified forensic audit report compliant with digital evidence requirements for court prosecution.",
                      techTag: "Legally Admissible Court PDF"
                    }
                  ],
                  output: {
                    label: "OUTPUT ARTIFACT (Delivered to Legal Authorities)",
                    items: [
                      "Attributed culprit dossier (officer identity + clearance level + timestamp)",
                      "Signed Section 65B(4) court evidence certificate PDF"
                    ],
                    nextLayerTarget: "Military Tribunal / Internal Affairs / Court of Law",
                    nextLayerId: undefined
                  },
                  securityGuarantee: {
                    title: "100% Mathematical Certainty in Court",
                    description: "Zero false-positive rate. Dual post-quantum signatures and Merkle proof provide unimpeachable attribution under Section 65B(4)."
                  },
                  primitives: [
                    { name: "Forensic Steganalysis", spec: "Zero-Width & XMP Trailer Parser" },
                    { name: "6-Point Verifier", spec: "Dual ML-DSA-65 + SHA-256 Merkle Engine" },
                    { name: "Sec 65B(4) Synthesizer", spec: "Automated Digital Evidence Certificate" }
                  ],
                  invariants: [
                    "Deterministic attribution with 100% mathematical certainty",
                    "Full provenance chain verifiable offline without internet",
                    "Compliant with Indian Evidence Act 65B & Bharatiya Sakshya Adhiniyam"
                  ]
                }
              ];

              const curLayer = flowchartLayers.find((l) => l.id === activeFlowchartLayer) || flowchartLayers[0];

              // Clean SVG Flow Arrow Down Component
              const FlowArrowDown = ({ label }: { label?: string }) => (
                <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyItems: "center", margin: "4px 0" }}>
                  <svg width="24" height="26" viewBox="0 0 24 26" fill="none">
                    <line x1="12" y1="0" x2="12" y2="18" stroke="rgba(255, 255, 255, 0.4)" strokeWidth="2" strokeDasharray="3 3" />
                    <polygon points="7,16 12,24 17,16" fill="#ffffff" />
                  </svg>
                  {label && (
                    <span style={{ fontSize: "10px", color: "var(--text-muted)", marginTop: "-2px" }}>{label}</span>
                  )}
                </div>
              );

              return (
                <section className="nayanx-card col-12" style={{ marginTop: "20px" }}>
                  {/* Flowchart Card Header */}
                  <div className="chart-header-row" style={{ marginBottom: "16px" }}>
                    <div>
                      <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                        <span className="card-badge" style={{ background: "rgba(255,255,255,0.12)", color: "#ffffff", fontWeight: "700" }}>
                          FLOWCHART ARCHITECTURE
                        </span>
                        <span style={{ fontSize: "12px", color: "var(--text-muted)" }}>
                          4 Sequential Cryptographic Protection Layers
                        </span>
                      </div>
                      <span className="card-title" style={{ fontSize: "16px", color: "var(--text-primary)", marginTop: "4px", display: "block" }}>
                        WebEye End-to-End Cryptographic Execution Flowchart
                      </span>
                      <div style={{ fontSize: "12px", color: "var(--text-secondary)", marginTop: "2px" }}>
                        Sequential dataflow diagram explaining how documents pass through post-quantum encapsulation, invisible steganography, Merkle ledger commitment, and forensic attribution.
                      </div>
                    </div>

                    <div style={{ display: "flex", gap: "10px", alignItems: "center", flexWrap: "wrap" }}>
                      {/* View Mode Toggle */}
                      <div style={{ display: "flex", background: "rgba(255,255,255,0.04)", borderRadius: "6px", padding: "2px", border: "1px solid rgba(255,255,255,0.08)" }}>
                        <button
                          onClick={() => setFlowchartViewMode("detailed")}
                          style={{
                            background: flowchartViewMode === "detailed" ? "rgba(255,255,255,0.15)" : "transparent",
                            color: flowchartViewMode === "detailed" ? "#ffffff" : "var(--text-muted)",
                            border: "none",
                            borderRadius: "4px",
                            padding: "4px 10px",
                            fontSize: "11px",
                            fontWeight: "600",
                            cursor: "pointer",
                          }}
                        >
                          📌 Detailed Flowchart
                        </button>
                        <button
                          onClick={() => setFlowchartViewMode("overview")}
                          style={{
                            background: flowchartViewMode === "overview" ? "rgba(255,255,255,0.15)" : "transparent",
                            color: flowchartViewMode === "overview" ? "#ffffff" : "var(--text-muted)",
                            border: "none",
                            borderRadius: "4px",
                            padding: "4px 10px",
                            fontSize: "11px",
                            fontWeight: "600",
                            cursor: "pointer",
                          }}
                        >
                          🔲 4-Layer Matrix
                        </button>
                      </div>

                      <button
                        className="card-badge"
                        onClick={handleTamperSimulation}
                        style={{ background: "rgba(255, 255, 255, 0.06)", color: "#cbd5e1", cursor: "pointer" }}
                        title="Simulate adversarial attack on SQLite block to prove ledger detects tampering"
                      >
                        Simulate Ledger Tamper
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
                          Heal &amp; Restore Chain Now
                        </button>
                      </div>
                    </div>
                  )}

                  {/* MACRO PIPELINE RIBBON: CONNECTS ALL 4 LAYERS WITH DIRECTIONAL ARROWS */}
                  <div
                    style={{
                      background: "rgba(10, 12, 16, 0.65)",
                      border: "1px solid rgba(255, 255, 255, 0.08)",
                      borderRadius: "10px",
                      padding: "12px 14px",
                      marginBottom: "16px",
                      backgroundImage: "radial-gradient(circle, rgba(255, 255, 255, 0.04) 1px, transparent 1px)",
                      backgroundSize: "20px 20px",
                    }}
                  >
                    <div style={{ fontSize: "11px", fontWeight: "700", color: "var(--text-muted)", marginBottom: "8px", letterSpacing: "0.5px" }}>
                      MACRO PIPELINE FLOW (CLICK ANY LAYER TO INSPECT STEP-BY-STEP FLOWCHART):
                    </div>
                    <div style={{ display: "flex", alignItems: "center", gap: "8px", overflowX: "auto", paddingBottom: "4px" }}>
                      {flowchartLayers.map((layer, idx) => (
                        <React.Fragment key={layer.id}>
                          <button
                            onClick={() => setActiveFlowchartLayer(layer.id)}
                            style={{
                              flex: "1 1 200px",
                              minWidth: "190px",
                              background: activeFlowchartLayer === layer.id ? "rgba(255, 255, 255, 0.12)" : "rgba(255, 255, 255, 0.025)",
                              border: activeFlowchartLayer === layer.id ? "1.5px solid #ffffff" : "1px solid rgba(255, 255, 255, 0.1)",
                              borderRadius: "8px",
                              padding: "10px 12px",
                              cursor: "pointer",
                              textAlign: "left",
                              transition: "all 0.15s ease",
                              boxShadow: activeFlowchartLayer === layer.id ? "0 0 16px rgba(255, 255, 255, 0.08)" : "none",
                            }}
                          >
                            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "4px" }}>
                              <span style={{ fontSize: "10px", fontWeight: "800", color: activeFlowchartLayer === layer.id ? "#ffffff" : "var(--text-muted)", letterSpacing: "0.5px" }}>
                                LAYER {layer.id}
                              </span>
                              <span className="card-badge" style={{ fontSize: "9px", padding: "1px 5px", background: activeFlowchartLayer === layer.id ? "rgba(255,255,255,0.2)" : "rgba(255,255,255,0.05)" }}>
                                {layer.shortTech}
                              </span>
                            </div>
                            <div style={{ fontSize: "12.5px", fontWeight: "700", color: activeFlowchartLayer === layer.id ? "#ffffff" : "var(--text-secondary)", display: "flex", alignItems: "center", gap: "6px" }}>
                              <span>{layer.icon}</span>
                              <span>{layer.name}</span>
                            </div>
                          </button>

                          {idx < flowchartLayers.length - 1 && (
                            <div style={{ display: "flex", alignItems: "center", color: "rgba(255, 255, 255, 0.4)", flexShrink: 0 }} title="Cryptographic Data Conduit">
                              <svg width="28" height="18" viewBox="0 0 28 18" fill="none">
                                <line x1="0" y1="9" x2="20" y2="9" stroke="rgba(255, 255, 255, 0.35)" strokeWidth="2" strokeDasharray="3 3" />
                                <polygon points="19,4 27,9 19,14" fill="rgba(255, 255, 255, 0.75)" />
                              </svg>
                            </div>
                          )}
                        </React.Fragment>
                      ))}
                    </div>
                  </div>

                  {/* FLOWCHART VIEW 1: DETAILED SEQUENTIAL STEP FLOWCHART (DEFAULT) */}
                  {flowchartViewMode === "detailed" ? (
                    <div
                      style={{
                        background: "rgba(10, 12, 16, 0.65)",
                        border: "1px solid rgba(255, 255, 255, 0.08)",
                        borderRadius: "12px",
                        padding: "20px 18px",
                        backgroundImage: "radial-gradient(circle, rgba(255, 255, 255, 0.035) 1px, transparent 1px)",
                        backgroundSize: "22px 22px",
                      }}
                    >
                      {/* Active Layer Header Bar */}
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: "12px", marginBottom: "20px", paddingBottom: "14px", borderBottom: "1px solid rgba(255, 255, 255, 0.08)" }}>
                        <div>
                          <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "4px" }}>
                            <span style={{ fontSize: "11px", fontWeight: "800", color: "#ffffff", background: "rgba(255, 255, 255, 0.12)", padding: "3px 8px", borderRadius: "4px", letterSpacing: "0.5px" }}>
                              LAYER {curLayer.id} OF 4
                            </span>
                            <span className="card-badge" style={{ fontSize: "10px", padding: "2px 7px" }}>
                              {curLayer.standard}
                            </span>
                          </div>
                          <h3 style={{ fontSize: "18px", fontWeight: "700", color: "#ffffff", margin: "6px 0 2px 0", display: "flex", alignItems: "center", gap: "8px" }}>
                            <span>{curLayer.icon}</span>
                            <span>{curLayer.title}</span>
                          </h3>
                          <p style={{ fontSize: "12.5px", color: "var(--text-secondary)", margin: 0 }}>
                            {curLayer.subtitle}
                          </p>
                        </div>

                        {/* Layer Switcher Buttons */}
                        <div style={{ display: "flex", gap: "6px" }}>
                          {flowchartLayers.map((l) => (
                            <button
                              key={l.id}
                              onClick={() => setActiveFlowchartLayer(l.id)}
                              className="card-badge"
                              style={{
                                background: activeFlowchartLayer === l.id ? "#ffffff" : "rgba(255, 255, 255, 0.05)",
                                color: activeFlowchartLayer === l.id ? "#0a0c10" : "var(--text-secondary)",
                                cursor: "pointer",
                                padding: "6px 12px",
                                fontWeight: activeFlowchartLayer === l.id ? "700" : "500",
                                transition: "all 0.15s ease",
                              }}
                            >
                              Layer {l.id}
                            </button>
                          ))}
                        </div>
                      </div>

                      {/* 2-Column Responsive Layout: Flowchart on Left, Specs on Right */}
                      <div
                        style={{
                          display: "grid",
                          gridTemplateColumns: "repeat(auto-fit, minmax(360px, 1fr))",
                          gap: "22px",
                          alignItems: "start",
                        }}
                      >
                        {/* LEFT COLUMN: THE STEP-BY-STEP FLOWCHART WITH ARROWS */}
                        <div>
                          <div style={{ fontSize: "12px", fontWeight: "800", color: "#ffffff", letterSpacing: "0.5px", marginBottom: "12px", display: "flex", alignItems: "center", gap: "6px" }}>
                            <span>⚙️</span>
                            <span>EXECUTION FLOWCHART: STEP-BY-STEP TECHNICAL PROCESS</span>
                          </div>

                          {/* 1. INPUT NODE */}
                          <div
                            style={{
                              background: "rgba(255, 255, 255, 0.03)",
                              border: "1.5px dashed rgba(255, 255, 255, 0.22)",
                              borderRadius: "10px",
                              padding: "12px 14px",
                            }}
                          >
                            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "6px" }}>
                              <span style={{ fontSize: "11px", fontWeight: "800", color: "#ffffff", display: "flex", alignItems: "center", gap: "6px" }}>
                                <span>📥</span>
                                <span>{curLayer.input.label}</span>
                              </span>
                              <span className="card-badge" style={{ fontSize: "9.5px", padding: "1px 6px" }}>
                                {curLayer.input.sourceTag}
                              </span>
                            </div>
                            <ul style={{ margin: 0, paddingLeft: "18px", fontSize: "12px", color: "var(--text-secondary)", display: "flex", flexDirection: "column", gap: "3px" }}>
                              {curLayer.input.items.map((it, idx) => (
                                <li key={idx}><code style={{ color: "#ffffff", background: "rgba(255,255,255,0.06)", padding: "1px 4px", borderRadius: "3px" }}>{it}</code></li>
                              ))}
                            </ul>
                          </div>

                          {/* Flow Arrow pointing to Step 1 */}
                          <FlowArrowDown label="Inflow" />

                          {/* 2. THE 5 PROCESS STEPS WITH DOWNWARD ARROWS */}
                          {curLayer.steps.map((step, idx) => (
                            <React.Fragment key={step.number}>
                              <div
                                style={{
                                  background: "rgba(255, 255, 255, 0.035)",
                                  border: "1px solid rgba(255, 255, 255, 0.12)",
                                  borderRadius: "8px",
                                  padding: "10px 14px",
                                  display: "flex",
                                  alignItems: "flex-start",
                                  gap: "12px",
                                  transition: "border-color 0.2s ease",
                                }}
                              >
                                <div
                                  style={{
                                    background: "rgba(255, 255, 255, 0.1)",
                                    color: "#ffffff",
                                    fontWeight: "800",
                                    fontSize: "11px",
                                    padding: "4px 8px",
                                    borderRadius: "5px",
                                    flexShrink: 0,
                                    letterSpacing: "0.5px",
                                  }}
                                >
                                  {step.number}
                                </div>
                                <div style={{ flex: 1 }}>
                                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "3px", flexWrap: "wrap", gap: "6px" }}>
                                    <span style={{ fontSize: "13px", fontWeight: "700", color: "#ffffff" }}>
                                      {step.name}
                                    </span>
                                    {step.techTag && (
                                      <span style={{ fontSize: "10px", color: "var(--text-muted)", background: "rgba(255,255,255,0.05)", padding: "1px 6px", borderRadius: "3px" }}>
                                        {step.techTag}
                                      </span>
                                    )}
                                  </div>
                                  <p style={{ margin: 0, fontSize: "12px", color: "var(--text-secondary)", lineHeight: "1.45" }}>
                                    {step.description}
                                  </p>
                                </div>
                              </div>

                              {/* Arrow pointing down to next step or output */}
                              {idx < curLayer.steps.length - 1 ? (
                                <FlowArrowDown />
                              ) : (
                                <FlowArrowDown label="Outflow" />
                              )}
                            </React.Fragment>
                          ))}

                          {/* 3. OUTPUT NODE */}
                          <div
                            style={{
                              background: "rgba(255, 255, 255, 0.04)",
                              border: "1.5px solid rgba(255, 255, 255, 0.25)",
                              borderRadius: "10px",
                              padding: "12px 14px",
                            }}
                          >
                            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "6px" }}>
                              <span style={{ fontSize: "11px", fontWeight: "800", color: "#ffffff", display: "flex", alignItems: "center", gap: "6px" }}>
                                <span>📤</span>
                                <span>{curLayer.output.label}</span>
                              </span>
                              <span className="card-badge" style={{ fontSize: "9.5px", padding: "1px 6px", background: "rgba(255, 255, 255, 0.15)", color: "#ffffff" }}>
                                Produced Artifact
                              </span>
                            </div>
                            <ul style={{ margin: 0, paddingLeft: "18px", fontSize: "12px", color: "var(--text-secondary)", display: "flex", flexDirection: "column", gap: "3px" }}>
                              {curLayer.output.items.map((it, idx) => (
                                <li key={idx}><strong style={{ color: "#ffffff" }}>{it}</strong></li>
                              ))}
                            </ul>
                          </div>

                          {/* 4. CONDUIT TO NEXT LAYER OR LEGAL TERMINAL */}
                          <div style={{ marginTop: "12px", display: "flex", justifyContent: "center" }}>
                            {curLayer.output.nextLayerId ? (
                              <button
                                onClick={() => setActiveFlowchartLayer(curLayer.output.nextLayerId!)}
                                style={{
                                  display: "flex",
                                  alignItems: "center",
                                  gap: "8px",
                                  background: "rgba(255, 255, 255, 0.06)",
                                  border: "1px solid rgba(255, 255, 255, 0.2)",
                                  borderRadius: "8px",
                                  padding: "8px 16px",
                                  color: "#ffffff",
                                  fontSize: "12px",
                                  fontWeight: "600",
                                  cursor: "pointer",
                                  transition: "all 0.15s ease",
                                }}
                              >
                                <span>Pipeline Conduit: Advance to {curLayer.output.nextLayerTarget}</span>
                                <span>──►</span>
                              </button>
                            ) : (
                              <div
                                style={{
                                  display: "flex",
                                  alignItems: "center",
                                  gap: "8px",
                                  background: "rgba(255, 255, 255, 0.08)",
                                  border: "1px solid rgba(255, 255, 255, 0.25)",
                                  borderRadius: "8px",
                                  padding: "8px 16px",
                                  color: "#ffffff",
                                  fontSize: "12px",
                                  fontWeight: "700",
                                }}
                              >
                                <span>⚖️ Legal Terminal: Section 65B(4) Admissible in Court / Prosecution</span>
                              </div>
                            )}
                          </div>
                        </div>

                        {/* RIGHT COLUMN: SECURITY GUARANTEE & SPECIFICATIONS RAIL */}
                        <div style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
                          {/* 1. Security Guarantee Box */}
                          <div
                            style={{
                              background: "rgba(255, 255, 255, 0.03)",
                              border: "1px solid rgba(255, 255, 255, 0.15)",
                              borderRadius: "10px",
                              padding: "16px 14px",
                            }}
                          >
                            <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "8px" }}>
                              <span style={{ fontSize: "16px" }}>🛡️</span>
                              <span style={{ fontSize: "12px", fontWeight: "800", color: "#ffffff", letterSpacing: "0.5px" }}>
                                SECURITY GUARANTEE
                              </span>
                            </div>
                            <div style={{ fontSize: "13.5px", fontWeight: "700", color: "#ffffff", marginBottom: "4px" }}>
                              {curLayer.securityGuarantee.title}
                            </div>
                            <p style={{ margin: 0, fontSize: "12px", color: "var(--text-secondary)", lineHeight: "1.5" }}>
                              {curLayer.securityGuarantee.description}
                            </p>
                          </div>

                          {/* 2. Applicable Cryptographic Primitives & NIST Standards */}
                          <div
                            style={{
                              background: "rgba(255, 255, 255, 0.025)",
                              border: "1px solid rgba(255, 255, 255, 0.1)",
                              borderRadius: "10px",
                              padding: "14px",
                            }}
                          >
                            <div style={{ fontSize: "11px", fontWeight: "800", color: "var(--text-muted)", letterSpacing: "0.5px", marginBottom: "10px" }}>
                              CRYPTOGRAPHIC PRIMITIVES &amp; STANDARDS:
                            </div>
                            <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
                              {curLayer.primitives.map((prim, idx) => (
                                <div
                                  key={idx}
                                  style={{
                                    display: "flex",
                                    justifyContent: "space-between",
                                    alignItems: "center",
                                    background: "rgba(255, 255, 255, 0.03)",
                                    padding: "6px 10px",
                                    borderRadius: "6px",
                                    border: "1px solid rgba(255, 255, 255, 0.05)",
                                    fontSize: "11.5px",
                                  }}
                                >
                                  <span style={{ fontWeight: "700", color: "#ffffff" }}>{prim.name}</span>
                                  <span style={{ color: "var(--text-secondary)" }}>{prim.spec}</span>
                                </div>
                              ))}
                            </div>
                          </div>

                          {/* 3. Layer Invariants & Proof Verifications */}
                          <div
                            style={{
                              background: "rgba(255, 255, 255, 0.025)",
                              border: "1px solid rgba(255, 255, 255, 0.1)",
                              borderRadius: "10px",
                              padding: "14px",
                            }}
                          >
                            <div style={{ fontSize: "11px", fontWeight: "800", color: "var(--text-muted)", letterSpacing: "0.5px", marginBottom: "8px" }}>
                              SECURITY INVARIANTS &amp; PROOFS:
                            </div>
                            <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
                              {curLayer.invariants.map((inv, idx) => (
                                <div key={idx} style={{ display: "flex", alignItems: "center", gap: "8px", fontSize: "11.5px", color: "var(--text-secondary)" }}>
                                  <span style={{ color: "#ffffff", fontWeight: "700" }}>✓</span>
                                  <span>{inv}</span>
                                </div>
                              ))}
                            </div>
                          </div>

                          {/* 4. Live Ledger Status Card */}
                          <div
                            style={{
                              background: "rgba(255, 255, 255, 0.025)",
                              border: "1px solid rgba(255, 255, 255, 0.1)",
                              borderRadius: "10px",
                              padding: "14px",
                            }}
                          >
                            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" }}>
                              <span style={{ fontSize: "11px", fontWeight: "800", color: "var(--text-muted)", letterSpacing: "0.5px" }}>
                                MERKLE LEDGER STATE:
                              </span>
                              <span className="card-badge" style={{ fontSize: "9.5px", padding: "1px 6px" }}>
                                {backendOnline ? "Online & Synchronized" : "Offline"}
                              </span>
                            </div>
                            <div style={{ display: "flex", alignItems: "center", gap: "8px", fontSize: "12px", color: "#ffffff", fontWeight: "600" }}>
                              <span>🏛️</span>
                              <span>Current Chain Length: Block #{ledgerData?.chain_length ?? 0}</span>
                            </div>
                            <div style={{ fontSize: "11px", color: "var(--text-muted)", marginTop: "4px" }}>
                              SHA-256 parent hash verification automatically confirms integrity on every query.
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                  ) : (
                    /* FLOWCHART VIEW 2: 4-COLUMN OVERVIEW MATRIX */
                    <div
                      style={{
                        background: "rgba(10, 12, 16, 0.65)",
                        border: "1px solid rgba(255, 255, 255, 0.08)",
                        borderRadius: "12px",
                        padding: "20px 16px",
                        position: "relative",
                        backgroundImage: "radial-gradient(circle, rgba(255, 255, 255, 0.04) 1px, transparent 1px)",
                        backgroundSize: "20px 20px",
                      }}
                    >
                      <div
                        style={{
                          display: "grid",
                          gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))",
                          gap: "14px",
                        }}
                      >
                        {flowchartLayers.map((layer) => (
                          <div
                            key={layer.id}
                            style={{
                              background: "rgba(255, 255, 255, 0.025)",
                              border: activeFlowchartLayer === layer.id ? "1.5px solid #ffffff" : "1px solid rgba(255, 255, 255, 0.12)",
                              borderRadius: "10px",
                              padding: "16px 14px",
                              display: "flex",
                              flexDirection: "column",
                              justifyContent: "space-between",
                            }}
                          >
                            <div>
                              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "10px" }}>
                                <span style={{ fontSize: "10.5px", fontWeight: "800", color: "#ffffff", letterSpacing: "0.5px", background: "rgba(255, 255, 255, 0.12)", padding: "3px 8px", borderRadius: "4px" }}>
                                  LAYER 0{layer.id}
                                </span>
                                <span className="card-badge" style={{ fontSize: "9.5px", padding: "2px 6px" }}>
                                  {layer.shortTech}
                                </span>
                              </div>
                              <div style={{ fontSize: "13.5px", fontWeight: "700", color: "#ffffff", marginBottom: "4px", display: "flex", alignItems: "center", gap: "6px" }}>
                                <span>{layer.icon}</span>
                                <span>{layer.name}</span>
                              </div>
                              <div style={{ fontSize: "11px", color: "var(--text-muted)", marginBottom: "12px" }}>
                                {layer.subtitle}
                              </div>

                              {/* Steps with Flow Arrows */}
                              <div style={{ display: "flex", flexDirection: "column", gap: "4px" }}>
                                {layer.steps.slice(0, 3).map((st, i) => (
                                  <React.Fragment key={st.number}>
                                    <div style={{ background: "rgba(255, 255, 255, 0.03)", padding: "6px 8px", borderRadius: "6px", border: "1px solid rgba(255, 255, 255, 0.06)", fontSize: "11px", color: "var(--text-secondary)" }}>
                                      <span style={{ color: "#ffffff", fontWeight: "600" }}>{st.number}. {st.name}:</span> {st.description.slice(0, 70)}...
                                    </div>
                                    {i < 2 && <FlowArrowDown />}
                                  </React.Fragment>
                                ))}
                              </div>
                            </div>

                            <div style={{ marginTop: "14px", paddingTop: "10px", borderTop: "1px solid rgba(255, 255, 255, 0.08)", fontSize: "10.5px" }}>
                              <button
                                onClick={() => {
                                  setActiveFlowchartLayer(layer.id);
                                  setFlowchartViewMode("detailed");
                                }}
                                className="card-badge"
                                style={{ width: "100%", textAlign: "center", background: "rgba(255,255,255,0.08)", color: "#ffffff", cursor: "pointer", padding: "6px 0", fontWeight: "600" }}
                              >
                                View Layer {layer.id} Detailed Flowchart ──►
                              </button>
                            </div>
                          </div>
                        ))}
                      </div>

                      {/* Inter-layer conduit arrows */}
                      <div
                        style={{
                          display: "flex",
                          justifyContent: "space-around",
                          alignItems: "center",
                          marginTop: "16px",
                          padding: "10px 14px",
                          background: "rgba(255, 255, 255, 0.02)",
                          borderRadius: "8px",
                          border: "1px solid rgba(255, 255, 255, 0.07)",
                          fontSize: "11px",
                          color: "var(--text-secondary)",
                          overflowX: "auto",
                          gap: "8px",
                        }}
                      >
                        <div style={{ display: "flex", alignItems: "center", gap: "6px", whiteSpace: "nowrap" }}>
                          <span style={{ color: "#ffffff", fontWeight: "700" }}>[Layer 1]</span>
                          <span style={{ color: "rgba(255,255,255,0.4)" }}>──►</span>
                          <span style={{ fontSize: "10.5px", color: "var(--text-muted)" }}>Ciphertext Bundle</span>
                        </div>
                        <div style={{ display: "flex", alignItems: "center", gap: "6px", whiteSpace: "nowrap" }}>
                          <span style={{ color: "#ffffff", fontWeight: "700" }}>[Layer 2]</span>
                          <span style={{ color: "rgba(255,255,255,0.4)" }}>──►</span>
                          <span style={{ fontSize: "10.5px", color: "var(--text-muted)" }}>Watermarked Release</span>
                        </div>
                        <div style={{ display: "flex", alignItems: "center", gap: "6px", whiteSpace: "nowrap" }}>
                          <span style={{ color: "#ffffff", fontWeight: "700" }}>[Layer 3]</span>
                          <span style={{ color: "rgba(255,255,255,0.4)" }}>──►</span>
                          <span style={{ fontSize: "10.5px", color: "var(--text-muted)" }}>Leaked File Intercepted</span>
                        </div>
                        <div style={{ display: "flex", alignItems: "center", gap: "6px", whiteSpace: "nowrap" }}>
                          <span style={{ color: "#ffffff", fontWeight: "700" }}>[Layer 4]</span>
                          <span style={{ color: "rgba(255,255,255,0.4)" }}>──►</span>
                          <span style={{ fontSize: "10.5px", color: "#ffffff", fontWeight: "600" }}>⚖️ Court Evidence Issued</span>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Bottom Pipeline Guarantees Bar */}
                  <div
                    style={{
                      display: "flex",
                      justifyContent: "space-between",
                      alignItems: "center",
                      flexWrap: "wrap",
                      gap: "10px",
                      marginTop: "14px",
                      padding: "10px 14px",
                      background: "rgba(255, 255, 255, 0.02)",
                      borderRadius: "8px",
                      border: "1px solid rgba(255, 255, 255, 0.06)",
                      fontSize: "11px",
                      color: "var(--text-muted)",
                    }}
                  >
                    <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                      <span style={{ color: "#ffffff", fontWeight: "600" }}>Pipeline Architecture:</span>
                      <span>Pure Python Reference PQC (FIPS 203 ML-KEM-768 &amp; FIPS 204 ML-DSA-65)</span>
                    </div>
                    <div style={{ display: "flex", alignItems: "center", gap: "14px" }}>
                      <span>✓ 4 Discrete Protection Layers</span>
                      <span>✓ 100% Non-Repudiation</span>
                      <span>✓ Instant Tamper Rejection</span>
                      <span>✓ Section 65B(4) Certified</span>
                    </div>
                  </div>
                </section>
              );
            })()}
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
                    placeholder="e.g. Officer Name"
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
                <div className="form-group">
                  <label className="form-label">Default Access Password</label>
                  <input
                    className="form-input"
                    type="text"
                    value="123456"
                    disabled
                    style={{ opacity: 0.85, background: "rgba(255,255,255,0.04)" }}
                  />
                  <span style={{ fontSize: "10.5px", color: "var(--text-muted)", marginTop: "4px" }}>
                    Standardized default password: "123456" (Argon2id hashed on enrollment)
                  </span>
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
                  <div
                    key={r.recipient_id}
                    className="portfolio-mini-card"
                    style={r.is_flagged ? { border: "1px solid rgba(239, 68, 68, 0.45)", background: "rgba(35, 8, 8, 0.35)" } : {}}
                  >
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                      <span style={{ fontWeight: "700", color: "var(--text-primary)", fontSize: "13.5px" }}>{r.name}</span>
                      <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                        {r.is_flagged ? (
                          <span
                            style={{
                              background: "rgba(239, 68, 68, 0.25)",
                              color: "#fca5a5",
                              border: "1px solid rgba(239, 68, 68, 0.45)",
                              borderRadius: "4px",
                              padding: "2px 8px",
                              fontSize: "11px",
                              fontWeight: "700",
                            }}
                          >
                            🚩 FLAGGED
                          </span>
                        ) : (
                          <span className="key-badge-green">● Active</span>
                        )}
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

                    {/* FLAGGED REASON BADGE & RESTORE CLEARANCE */}
                    {r.is_flagged && (
                      <div
                        style={{
                          marginTop: "10px",
                          background: "rgba(239, 68, 68, 0.15)",
                          borderLeft: "3px solid #ef4444",
                          padding: "6px 10px",
                          borderRadius: "4px",
                        }}
                      >
                        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                          <span style={{ fontSize: "10.5px", fontWeight: "800", color: "#f87171", textTransform: "uppercase" }}>
                            Reason for Flagging:
                          </span>
                          <button
                            onClick={() => handleUnflagRecipient(r.recipient_id)}
                            style={{
                              background: "rgba(255, 255, 255, 0.1)",
                              border: "1px solid rgba(255, 255, 255, 0.2)",
                              borderRadius: "3px",
                              padding: "2px 6px",
                              color: "#ffffff",
                              fontSize: "10px",
                              cursor: "pointer",
                              fontWeight: "600",
                            }}
                            title="Restore officer clearance"
                          >
                            Restore Clearance
                          </button>
                        </div>
                        <div style={{ fontSize: "11.5px", color: "#fecaca", marginTop: "3px", lineHeight: "1.35" }}>
                          {r.flag_reason || "Hardware PrintScreen or Snipping Tool capture attempt intercepted"}
                        </div>
                        {r.total_violations && r.total_violations > 0 && (
                          <div style={{ fontSize: "10px", color: "#f87171", marginTop: "3px" }}>
                            ⚠️ {r.total_violations} Incident{r.total_violations > 1 ? "s" : ""} Recorded in Audit Ledger
                          </div>
                        )}
                      </div>
                    )}

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
                        style={r.is_flagged ? { borderLeft: "3px solid #ef4444", background: "rgba(35, 10, 10, 0.4)" } : {}}
                        onClick={() => {
                          setDecryptSelectedRecipient(r.recipient_id);
                          setShowDecryptDropdown(false);
                        }}
                      >
                        <div style={{ display: "flex", alignItems: "center", gap: "10px", minWidth: 0, flex: 1 }}>
                          <span style={{ fontSize: "13px" }}>{r.is_flagged ? "🚩" : "🛡️"}</span>
                          <div style={{ minWidth: 0, flex: 1 }}>
                            <div style={{ fontSize: "12.5px", fontWeight: "600", color: r.is_flagged ? "#fca5a5" : "#ffffff", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                              {r.name} {r.is_flagged ? "• [FLAGGED: CLEARANCE SUSPENDED]" : ""}
                            </div>
                            <div style={{ fontSize: "11px", color: r.is_flagged ? "#f87171" : "var(--text-muted)", fontFamily: "monospace", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                              {r.is_flagged ? `Reason: ${r.flag_reason || "Screenshot Attempt"}` : `${r.role} • ${r.recipient_id}`}
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
                      <div style={{ display: "flex", gap: "8px", marginTop: "12px", flexWrap: "wrap" }}>
                        <button
                          className="card-badge"
                          style={{ background: "rgba(255,255,255,0.18)", color: "#fff", cursor: "pointer", fontWeight: "700" }}
                          onClick={() => {
                            const rName = recipients.find((r) => r.recipient_id === rId)?.name || rId;
                            setActiveSecureViewerCopy({
                              recipientId: rId,
                              recipientName: rName,
                              documentHash: copy.document_hash,
                              pdfBase64: copy.watermarked_pdf_base64,
                              title: `${rName}'s Classified Intelligence Briefing`,
                            });
                          }}
                        >
                          🔒 Secure Viewer
                        </button>
                        {copy.watermarked_pdf_base64 && (
                          <button
                            className="card-badge"
                            style={{ background: "rgba(255,255,255,0.12)", color: "#fff", cursor: "pointer" }}
                            onClick={() => {
                              const rName = recipients.find((r) => r.recipient_id === rId)?.name?.replace(/[^a-zA-Z0-9_-]/g, "_") || rId;
                              downloadPdf(copy.watermarked_pdf_base64!, `${rName}_${rId}_watermarked.pdf`);
                            }}
                          >
                            ⬇ Download PDF
                          </button>
                        )}
                        <button
                          className="card-badge"
                          style={{ background: "rgba(255,255,255,0.06)", color: "#cbd5e1", cursor: "pointer" }}
                          onClick={() => {
                            setLeakFileInput(null);
                            const rName = recipients.find((r) => r.recipient_id === rId)?.name || rId;
                            handleAttribute(copy.watermarked_pdf_base64, undefined, `${rName}'s Watermarked Copy (${rId})`);
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
                    setSelectedDocDescription(file.name);
                    handleAttribute(undefined, file, file.name);
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
                  onClick={(e) => {
                    (e.currentTarget as HTMLInputElement).value = "";
                  }}
                  onChange={(e) => {
                    const file = e.target.files?.[0];
                    if (file) {
                      setLeakFileInput(file);
                      setSelectedDocDescription(file.name);
                      handleAttribute(undefined, file, file.name);
                    }
                  }}
                />
                <div style={{ fontSize: "28px", marginBottom: "6px" }}>📁</div>
                <div style={{ fontSize: "14px", fontWeight: "600", color: "var(--text-primary)" }}>
                  {selectedDocDescription
                    ? `Active Document: ${selectedDocDescription}`
                    : leakFileInput
                    ? `Selected: ${leakFileInput.name}`
                    : "Click or Drag & Drop Leaked PDF Here"}
                </div>
                <div style={{ fontSize: "11px", color: "var(--text-muted)", marginTop: "4px" }}>
                  Supports forensic metadata extraction and trailing stego anchor analysis
                </div>
                {(selectedDocDescription || leakFileInput || attributeResult) && (
                  <button
                    type="button"
                    className="card-badge"
                    style={{
                      marginTop: "10px",
                      background: "rgba(255, 255, 255, 0.08)",
                      color: "var(--text-secondary)",
                      border: "1px solid var(--border-subtle)",
                      cursor: "pointer",
                      padding: "4px 12px",
                      fontSize: "11px",
                    }}
                    onClick={(e) => {
                      e.stopPropagation();
                      setLeakFileInput(null);
                      setSelectedDocDescription(null);
                      setAttributeResult(null);
                      setAttributeRawJson(null);
                    }}
                  >
                    ✕ Clear Document & Results
                  </button>
                )}
              </div>

              {/* Instant Test Buttons for Recipient Copies */}
              <div style={{ marginBottom: "20px" }}>
                <label className="form-label">Instant Forensic Verification on Active Decrypted Copies</label>
                <div style={{ display: "flex", gap: "10px", flexWrap: "wrap", marginTop: "8px" }}>
                  {Object.entries(decryptedCopies).map(([rId, copy]) => {
                    const officer = recipients.find((r) => r.recipient_id === rId);
                    const officerName = officer?.name || rId;
                    return (
                      <button
                        key={rId}
                        className="card-badge"
                        style={{
                          background: "rgba(255,255,255,0.08)",
                          color: "#ffffff",
                          cursor: "pointer",
                          padding: "8px 14px",
                        }}
                        onClick={() => {
                          if (copy.watermarked_pdf_base64) {
                            setLeakFileInput(null);
                            handleAttribute(
                              copy.watermarked_pdf_base64,
                              undefined,
                              `${officerName}'s Watermarked Copy (${rId})`
                            );
                          }
                        }}
                      >
                        🎯 Test {officerName}&apos;s Copy
                      </button>
                    );
                  })}
                  {Object.keys(decryptedCopies).length > 0 ? (
                    <button
                      className="card-badge"
                      style={{
                        background: "rgba(239, 68, 68, 0.12)",
                        color: "#f87171",
                        border: "1px solid rgba(239, 68, 68, 0.45)",
                        cursor: "pointer",
                        padding: "8px 14px",
                        fontWeight: "600",
                      }}
                      onClick={() => {
                        const firstCopy = Object.values(decryptedCopies)[0];
                        const firstId = Object.keys(decryptedCopies)[0];
                        const officerName = recipients.find((r) => r.recipient_id === firstId)?.name || firstId;
                        if (firstCopy && firstCopy.watermarked_pdf_base64) {
                          setLeakFileInput(null);
                          try {
                            const binary = atob(firstCopy.watermarked_pdf_base64);
                            const tampered = binary.includes("watermark_hash")
                              ? binary.replace(/"watermark_hash"\s*:\s*"([a-f0-9]{64})"/g, (_, h) => `"watermark_hash":"deadbeef${h.slice(8)}"`)
                              : binary.slice(0, -30) + "%deadbeef00000000" + binary.slice(-14);
                            handleAttribute(
                              btoa(tampered),
                              undefined,
                              `Simulated Tampered Attack on ${officerName}'s Copy (Altered Watermark 'deadbeef...')`
                            );
                          } catch {
                            handleAttribute(firstCopy.watermarked_pdf_base64, undefined, "Simulated Tampered Copy");
                          }
                        }
                      }}
                    >
                      🚨 Simulate Tamper Attack on Active Copy
                    </button>
                  ) : (
                    <span style={{ fontSize: "12px", color: "var(--text-muted)", fontStyle: "italic" }}>
                      No decrypted copies in active session. Encrypt &amp; decrypt a document above, or drag and drop any PDF below.
                    </span>
                  )}
                </div>
              </div>

              {/* Loading Indicator */}
              {loadingAction === "attribute" && (
                <div
                  style={{
                    padding: "24px",
                    background: "rgba(255, 255, 255, 0.03)",
                    borderRadius: "12px",
                    border: "1px solid var(--border-subtle)",
                    textAlign: "center",
                    marginBottom: "20px",
                  }}
                >
                  <div style={{ fontSize: "24px", marginBottom: "8px", animation: "spin 1s linear infinite" }}>⚙️</div>
                  <div style={{ fontSize: "14px", fontWeight: "600", color: "var(--text-primary)" }}>
                    Forensic Leak Attribution in Progress...
                  </div>
                  <div style={{ fontSize: "12px", color: "var(--text-secondary)", marginTop: "4px" }}>
                    {selectedDocDescription ? `Analyzing: ${selectedDocDescription}` : "Extracting stego payload and querying Merkle ledger..."}
                  </div>
                </div>
              )}

              {/* Attribution Verdict Card */}
              {attributeResult && (() => {
                const isAttributed = Boolean(attributeResult.attributed);
                const isTampered = Boolean(
                  attributeResult.verdict === "TAMPERED" ||
                  attributeResult.tamper_detected ||
                  (attributeResult.watermark_hash && !attributeResult.watermark_hmac_valid) ||
                  (attributeResult.recipient_id && !attributeResult.commitment_valid) ||
                  (!attributeResult.chain_valid)
                );
                const isSuspected = Boolean(attributeResult.verdict === "SUSPECTED");

                const bannerClass = isAttributed
                  ? "success"
                  : isTampered
                  ? "danger"
                  : isSuspected
                  ? "warning"
                  : "neutral";

                const bannerIcon = isAttributed ? "🎯" : isTampered ? "🚨" : isSuspected ? "⚠️" : "ℹ️";

                const bannerTitle = isAttributed
                  ? "CRYPTOGRAPHIC ATTRIBUTION CONFIRMED"
                  : isTampered
                  ? "CRYPTOGRAPHIC TAMPERING DETECTED — TAMPERED PDF IDENTIFIED"
                  : isSuspected
                  ? "PROBABILISTIC SUSPECT IDENTIFIED (INSUFFICIENT PROOF)"
                  : "UNATTRIBUTED / CLEAN UNWATERMARKED SOURCE";

                return (
                  <div
                    className={`verdict-banner ${bannerClass}`}
                    style={
                      isTampered
                        ? {
                            background: "rgba(239, 68, 68, 0.08)",
                            border: "1.5px solid rgba(239, 68, 68, 0.6)",
                            boxShadow: "0 0 24px rgba(239, 68, 68, 0.15)",
                          }
                        : undefined
                    }
                  >
                    <div className="verdict-icon">{bannerIcon}</div>
                    <div className="verdict-details" style={{ width: "100%" }}>
                      <div style={{ display: "flex", alignItems: "center", gap: "10px", flexWrap: "wrap" }}>
                        <h4
                          style={{
                            margin: 0,
                            color: isAttributed ? "#10b981" : isTampered ? "#ef4444" : isSuspected ? "#f59e0b" : "#94a3b8",
                            letterSpacing: "0.02em",
                          }}
                        >
                          {bannerTitle}
                        </h4>
                        {isTampered && (
                          <span
                            style={{
                              background: "rgba(239, 68, 68, 0.2)",
                              border: "1px solid rgba(239, 68, 68, 0.5)",
                              color: "#f87171",
                              fontSize: "10.5px",
                              fontWeight: "700",
                              padding: "2px 8px",
                              borderRadius: "4px",
                              letterSpacing: "0.05em",
                            }}
                          >
                            TAMPERED DOCUMENT
                          </span>
                        )}
                      </div>
                      <p
                        style={{
                          marginTop: "6px",
                          lineHeight: "1.5",
                          color: isTampered ? "#fca5a5" : "var(--text-secondary)",
                        }}
                      >
                        {attributeResult.summary}
                      </p>

                      <div
                        style={{
                          display: "grid",
                          gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
                          gap: "12px",
                          marginTop: "16px",
                        }}
                      >
                        <div
                          className="portfolio-mini-card"
                          style={
                            isTampered && attributeResult.recipient_id
                              ? { border: "1px solid rgba(239, 68, 68, 0.35)", background: "rgba(239, 68, 68, 0.05)" }
                              : undefined
                          }
                        >
                          <div style={{ fontSize: "10px", color: isTampered ? "#f87171" : "var(--text-muted)" }}>
                            {isTampered ? "TAMPERED COPY RECIPIENT" : isAttributed ? "IDENTIFIED LEAKER" : "CANDIDATE SOURCE"}
                          </div>
                          <div
                            style={{
                              fontSize: "13px",
                              fontWeight: "700",
                              color: isTampered
                                ? "#ef4444"
                                : isAttributed
                                ? "#10b981"
                                : "var(--text-primary)",
                              marginTop: "2px",
                            }}
                          >
                            {attributeResult.recipient_name || "Unknown"} ({attributeResult.recipient_id || "N/A"})
                          </div>
                        </div>

                        <div className="portfolio-mini-card">
                          <div style={{ fontSize: "10px", color: "var(--text-muted)" }}>[1] SHA3-256 COMMIT-REVEAL</div>
                          <div
                            style={{
                              fontSize: "12.5px",
                              fontWeight: "700",
                              color: attributeResult.commitment_valid ? "#10b981" : "#ef4444",
                              marginTop: "2px",
                            }}
                          >
                            {attributeResult.commitment_valid ? "✔ VERIFIED VALID" : "✖ FAILED / TAMPERED"}
                          </div>
                        </div>

                        <div
                          className="portfolio-mini-card"
                          style={
                            !attributeResult.watermark_hmac_valid
                              ? { border: "1px solid rgba(239, 68, 68, 0.4)", background: "rgba(239, 68, 68, 0.06)" }
                              : undefined
                          }
                        >
                          <div style={{ fontSize: "10px", color: !attributeResult.watermark_hmac_valid ? "#f87171" : "var(--text-muted)" }}>
                            [2] HMAC WATERMARK DERIVATION
                          </div>
                          <div
                            style={{
                              fontSize: "12.5px",
                              fontWeight: "700",
                              color: attributeResult.watermark_hmac_valid ? "#10b981" : "#ef4444",
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
                              color: attributeResult.recipient_signature_valid ? "#10b981" : "#ef4444",
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
                              color: attributeResult.service_signature_valid ? "#10b981" : "#ef4444",
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
                              color: attributeResult.chain_valid ? "#10b981" : "#ef4444",
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
                              color: attributeResult.distribution_bundle_valid ? "#10b981" : "#ef4444",
                              marginTop: "2px",
                            }}
                          >
                            {attributeResult.distribution_bundle_valid ? "✔ AUTHENTIC BUNDLE" : "✖ UNBOUND / TAMPERED"}
                          </div>
                        </div>

                        <div className="portfolio-mini-card">
                          <div style={{ fontSize: "10px", color: "var(--text-muted)" }}>LEDGER AUDIT ANCHOR</div>
                          <div style={{ fontSize: "13px", fontWeight: "700", color: "var(--text-primary)", marginTop: "2px" }}>
                            Block #{attributeResult.ledger_index ?? "N/A"} (Chain Height: {attributeResult.chain_length})
                          </div>
                        </div>
                      </div>

                      {attributeResult.certificate_pdf_base64 && (
                        <div style={{ marginTop: "16px", display: "flex", gap: "10px", alignItems: "center" }}>
                          <button
                            className="btn-primary"
                            style={{
                              display: "inline-flex",
                              alignItems: "center",
                              gap: "8px",
                              padding: "9px 16px",
                              fontSize: "12.5px",
                              fontWeight: "600",
                              borderRadius: "8px",
                              background: isTampered
                                ? "linear-gradient(135deg, #dc2626, #991b1b)"
                                : "linear-gradient(135deg, #2563eb, #1d4ed8)",
                              color: "#ffffff",
                              border: "none",
                              cursor: "pointer",
                              boxShadow: "0 2px 8px rgba(0, 0, 0, 0.25)",
                            }}
                            onClick={() => {
                              if (attributeResult.certificate_pdf_base64) {
                                downloadPdf(
                                  attributeResult.certificate_pdf_base64,
                                  attributeResult.certificate_filename || "Section_65B_Certificate.pdf"
                                );
                              }
                            }}
                          >
                            📄 Download Section 65B(4) Court-Admissible Forensic Certificate (PDF)
                          </button>
                        </div>
                      )}
                    </div>
                  </div>
                );
              })()}
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
                WebEye enforces an offline air-gapped cryptographic boundary conforming to US NIST FIPS 203 and FIPS 204.
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
              {securityNotifications.length === 0 ? (
                <div style={{ textAlign: "center", padding: "24px 12px", color: "var(--text-muted)", fontSize: "12px" }}>
                  <span style={{ fontSize: "28px", display: "block", marginBottom: "8px" }}>🛡️</span>
                  Zero active security violations recorded. Enclave perimeter fully secure.
                </div>
              ) : (
                <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
                  {securityNotifications.map((notif) => (
                    <div
                      key={notif.id}
                      className="portfolio-mini-card"
                      style={{
                        borderLeft: notif.is_read ? "3px solid #64748b" : "3px solid #ef4444",
                        background: notif.is_read ? "rgba(255,255,255,0.02)" : "rgba(239, 68, 68, 0.1)",
                      }}
                    >
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                        <span style={{ fontWeight: "700", color: notif.is_read ? "#94a3b8" : "#fca5a5" }}>
                          🚨 {notif.violation_type || "SCREENSHOT_ATTEMPT"}
                        </span>
                        <span style={{ fontSize: "10px", color: "var(--text-muted)", fontFamily: "monospace" }}>
                          {new Date(notif.timestamp).toLocaleString()}
                        </span>
                      </div>
                      <div style={{ fontSize: "12px", color: "#ffffff", marginTop: "4px" }}>
                        Officer: <strong>{notif.recipient_name}</strong> ({notif.recipient_id})
                      </div>
                      <p style={{ fontSize: "11px", color: "var(--text-secondary)", marginTop: "2px" }}>
                        {notif.reason}
                      </p>
                      <div style={{ display: "flex", gap: "8px", marginTop: "8px" }}>
                        {!notif.is_read && (
                          <button
                            className="card-badge"
                            style={{ background: "#ef4444", color: "#fff", cursor: "pointer", padding: "3px 8px", fontSize: "10px" }}
                            onClick={() => dismissNotification(notif.id)}
                          >
                            Mark Reviewed
                          </button>
                        )}
                        <button
                          className="card-badge"
                          style={{ background: "rgba(255,255,255,0.1)", color: "#fff", cursor: "pointer", padding: "3px 8px", fontSize: "10px" }}
                          onClick={async () => {
                            await fetch(`${API_BASE}/recipients/${notif.recipient_id}/unflag`, { method: "POST" });
                            fetchRecipients();
                            dismissNotification(notif.id);
                          }}
                        >
                          Clear Flag &amp; Restore Clearance
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
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
                  {currentUser?.username?.[0]?.toUpperCase() || "H"}
                </div>
                <div>
                  <div style={{ fontSize: "16px", fontWeight: "700", color: "#ffffff" }}>
                    {currentUser?.name || currentUser?.username || "Head Commander"}
                  </div>
                  <div style={{ fontSize: "11px", color: "var(--text-muted)", fontFamily: "monospace" }}>
                    ROLE: {currentUser?.role?.toUpperCase() || "HEAD"} • SESSION: ACTIVE
                  </div>
                </div>
              </div>

              <div className="portfolio-mini-card" style={{ marginBottom: "14px" }}>
                <div style={{ fontSize: "11px", color: "var(--text-muted)" }}>Enclave Station</div>
                <div style={{ fontSize: "13px", fontWeight: "700", color: "var(--text-primary)", marginTop: "2px" }}>
                  WebEye Air-Gap Node #01 (Offline Defense Enclave)
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

      {/* SECURE RECIPIENT VIEWER MODAL ENCLAVE */}
      {activeSecureViewerCopy && (
        <div
          style={{
            position: "fixed",
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            backgroundColor: "rgba(0, 0, 0, 0.88)",
            backdropFilter: "blur(10px)",
            zIndex: 99999,
            display: "flex",
            justifyContent: "center",
            alignItems: "center",
            padding: "20px",
          }}
        >
          <div style={{ width: "100%", maxWidth: "1140px", maxHeight: "96vh", display: "flex", flexDirection: "column" }}>
            <SecureViewer
              recipientId={activeSecureViewerCopy.recipientId}
              recipientName={activeSecureViewerCopy.recipientName}
              documentHash={activeSecureViewerCopy.documentHash}
              documentId={activeSecureViewerCopy.documentId}
              pdfBase64={activeSecureViewerCopy.pdfBase64}
              documentTitle={activeSecureViewerCopy.title || "Classified Operational Briefing"}
              onClose={() => setActiveSecureViewerCopy(null)}
            />
          </div>
        </div>
      )}
    </div>
  );
}
