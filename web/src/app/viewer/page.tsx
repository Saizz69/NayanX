"use client";

import React, { Suspense, useState, useEffect } from "react";
import { useSearchParams, useRouter } from "next/navigation";
import SecureViewer from "@/components/SecureViewer";
import Link from "next/link";

function SecureViewerContent() {
  const searchParams = useSearchParams();
  const router = useRouter();

  const queryRecipientId = searchParams.get("recipient_id");
  const queryDocumentHash = searchParams.get("document_hash");
  const queryDocumentId = searchParams.get("document_id");

  const [recipientId, setRecipientId] = useState<string>(queryRecipientId || "");
  const [recipientName, setRecipientName] = useState<string>("");
  const [documentHash, setDocumentHash] = useState<string | undefined>(queryDocumentHash || undefined);
  const [recipients, setRecipients] = useState<any[]>([]);

  // Fetch recipients list for selector
  const fetchRecipients = React.useCallback(async () => {
    try {
      const apiUrl = process.env.NEXT_PUBLIC_CRYPTO_API_URL || "/crypto-api";
      const res = await fetch(`${apiUrl}/recipients`);
      if (res.ok) {
        const data = await res.json();
        if (Array.isArray(data) && data.length > 0) {
          setRecipients(data);
          if (!queryRecipientId && !recipientId) {
            const first = data[0];
            const firstId = first.recipient_id || first.id || "";
            setRecipientId(firstId);
            setRecipientName(first.name || firstId);
          }
        }
      }
    } catch (e) {
      console.error("Failed to load recipients in viewer:", e);
    }
  }, [queryRecipientId, recipientId]);

  useEffect(() => {
    fetchRecipients();
  }, [fetchRecipients]);

  const handleSelectRecipient = (id: string) => {
    if (!id) return;
    setRecipientId(id);
    const rec = recipients.find((r) => (r.recipient_id || r.id) === id);
    if (rec) setRecipientName(rec.name || id);
  };

  const handleUnflag = async (targetId: string) => {
    try {
      await fetch("/api/flag-violation", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ recipient_id: targetId, action: "unflag" }),
      });
      await fetchRecipients();
    } catch (e) {
      console.error("Failed to unflag recipient:", e);
    }
  };

  const handleSimulateViolation = async (targetId: string) => {
    try {
      await fetch("/api/flag-violation", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          recipient_id: targetId,
          violation_type: "SCREENSHOT_KEY_PRINTSCREEN",
          reason: "Hardware PrintScreen key pressed while viewing classified document",
          details: "Simulated security test: unauthorized capture attempt logged to ledger.",
        }),
      });
      await fetchRecipients();
    } catch (e) {
      console.error("Failed to flag recipient:", e);
    }
  };

  const activeRecipient = recipients.find((r) => (r.recipient_id || r.id) === recipientId);
  const flaggedOfficers = recipients.filter((r) => r.is_flagged);

  return (
    <div
      style={{
        minHeight: "100vh",
        background: "#05070a",
        color: "#ffffff",
        padding: "24px 32px",
        fontFamily: "var(--font-sans, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif)",
      }}
    >
      {/* TOP NAVIGATION BAR */}
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          marginBottom: "24px",
          paddingBottom: "16px",
          borderBottom: "1px solid rgba(255, 255, 255, 0.1)",
          flexWrap: "wrap",
          gap: "14px",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "16px" }}>
          <Link
            href="/"
            style={{
              display: "flex",
              alignItems: "center",
              gap: "6px",
              color: "#cbd5e1",
              textDecoration: "none",
              fontSize: "12px",
              background: "rgba(255, 255, 255, 0.06)",
              padding: "6px 12px",
              borderRadius: "6px",
              border: "1px solid rgba(255, 255, 255, 0.12)",
              fontWeight: "600",
            }}
          >
            <span>←</span>
            <span>Dashboard</span>
          </Link>

          <div>
            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <span
                style={{
                  background: "rgba(239, 68, 68, 0.2)",
                  color: "#f87171",
                  border: "1px solid rgba(239, 68, 68, 0.4)",
                  borderRadius: "4px",
                  padding: "2px 6px",
                  fontSize: "10px",
                  fontWeight: "800",
                  letterSpacing: "0.5px",
                }}
              >
                AIR-GAPPED PROTOCOL
              </span>
              <span style={{ fontSize: "12px", color: "var(--text-muted)" }}>
                Zero-Text Server-Rendered Canvas
              </span>
            </div>
            <h1 style={{ fontSize: "18px", fontWeight: "700", margin: "4px 0 0 0" }}>
              Secure Recipient Viewer Environment
            </h1>
          </div>
        </div>

        {/* OFFICER RECIPIENT SELECTOR & SECURITY FLAG STATUS */}
        <div style={{ display: "flex", alignItems: "center", gap: "10px", flexWrap: "wrap" }}>
          {activeRecipient?.is_flagged && (
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: "8px",
                background: "rgba(239, 68, 68, 0.18)",
                border: "1px solid rgba(239, 68, 68, 0.45)",
                borderRadius: "6px",
                padding: "4px 10px",
                color: "#fca5a5",
                fontSize: "11.5px",
                fontWeight: "700",
              }}
            >
              <span>🚩</span>
              <span>FLAGGED: {activeRecipient.flag_reason || "Unauthorized Screen Capture Attempt"}</span>
              <button
                onClick={() => handleUnflag(recipientId)}
                style={{
                  background: "rgba(255, 255, 255, 0.12)",
                  border: "1px solid rgba(255, 255, 255, 0.25)",
                  borderRadius: "4px",
                  padding: "2px 6px",
                  color: "#ffffff",
                  fontSize: "10.5px",
                  cursor: "pointer",
                  fontWeight: "600",
                }}
                title="Review incident and restore officer clearance"
              >
                Restore Clearance
              </button>
            </div>
          )}

          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <span style={{ fontSize: "12px", color: "var(--text-secondary)" }}>Viewing as Officer:</span>
            <select
              value={recipientId}
              onChange={(e) => handleSelectRecipient(e.target.value)}
              style={{
                background: activeRecipient?.is_flagged ? "rgba(45, 10, 10, 0.9)" : "rgba(255, 255, 255, 0.08)",
                border: activeRecipient?.is_flagged ? "1px solid #ef4444" : "1px solid rgba(255, 255, 255, 0.2)",
                borderRadius: "6px",
                padding: "6px 12px",
                color: "#ffffff",
                fontSize: "12px",
                cursor: "pointer",
              }}
            >
              {recipients.length > 0 ? (
                recipients.map((r, idx) => {
                  const rId = r.recipient_id || r.id || `rec-${idx}`;
                  return (
                    <option
                      key={`${rId}-${idx}`}
                      value={rId}
                      style={{ background: r.is_flagged ? "#1e0808" : "#0a0c10", color: r.is_flagged ? "#f87171" : "#ffffff" }}
                    >
                      {r.is_flagged ? "🚩 [FLAGGED] " : ""}{r.name} ({rId}) — {r.is_flagged ? `REASON: ${r.flag_reason}` : (r.role || r.clearance_level || "Classified")}
                    </option>
                  );
                })
              ) : (
                <option key="none" value="" style={{ background: "#0a0c10", color: "#64748b" }}>
                  No Enrolled Recipients
                </option>
              )}
            </select>
          </div>
        </div>
      </div>

      {/* MAIN SECURE VIEWER INSTANCE */}
      <SecureViewer
        recipientId={recipientId}
        recipientName={recipientName}
        documentHash={documentHash}
        documentId={queryDocumentId || undefined}
        documentTitle="Operation Deep Blue — Top Secret Operational Dossier"
        onFlagViolation={() => {
          fetchRecipients();
        }}
      />

      {/* FLAGGED RECIPIENTS & INCIDENT LEDGER PANEL */}
      <div
        style={{
          marginTop: "24px",
          background: "rgba(239, 68, 68, 0.05)",
          border: "1px solid rgba(239, 68, 68, 0.25)",
          borderRadius: "10px",
          padding: "18px 20px",
        }}
      >
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "14px", flexWrap: "wrap", gap: "10px" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
            <span style={{ fontSize: "18px" }}>🚩</span>
            <div>
              <div style={{ fontSize: "14px", fontWeight: "700", color: "#f87171" }}>
                Enclave Security Audit: Flagged Personnel Roster ({flaggedOfficers.length})
              </div>
              <div style={{ fontSize: "11.5px", color: "var(--text-secondary)" }}>
                Recipients flagged for unauthorized screenshot capture, window blur exfiltration, or print attempts.
              </div>
            </div>
          </div>
          <button
            onClick={() => handleSimulateViolation(recipientId)}
            style={{
              background: "rgba(239, 68, 68, 0.2)",
              border: "1px solid rgba(239, 68, 68, 0.4)",
              borderRadius: "6px",
              padding: "6px 12px",
              color: "#fca5a5",
              fontSize: "11px",
              fontWeight: "700",
              cursor: "pointer",
            }}
            title="Flag current viewing officer with a test screenshot violation"
          >
            ⚡ Test Flag Current Officer ({recipientName || recipientId})
          </button>
        </div>

        {flaggedOfficers.length === 0 ? (
          <div style={{ padding: "16px", textAlign: "center", color: "var(--text-muted)", fontSize: "12px", background: "rgba(0,0,0,0.2)", borderRadius: "6px" }}>
            ✓ No officers are currently flagged. All active viewing sessions conform to enclave security policy.
          </div>
        ) : (
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))", gap: "12px" }}>
            {flaggedOfficers.map((fRec, fIdx) => (
              <div
                key={fRec.recipient_id || fIdx}
                style={{
                  background: "rgba(10, 12, 16, 0.8)",
                  border: "1px solid rgba(239, 68, 68, 0.3)",
                  borderRadius: "8px",
                  padding: "14px",
                }}
              >
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: "8px" }}>
                  <div>
                    <div style={{ fontSize: "13.5px", fontWeight: "700", color: "#ffffff" }}>
                      {fRec.name} <code style={{ color: "#fca5a5", fontSize: "11px" }}>({fRec.recipient_id})</code>
                    </div>
                    <div style={{ fontSize: "11px", color: "var(--accent-pink)", marginTop: "2px" }}>
                      {fRec.role}
                    </div>
                  </div>
                  <button
                    onClick={() => handleUnflag(fRec.recipient_id)}
                    style={{
                      background: "rgba(255, 255, 255, 0.08)",
                      border: "1px solid rgba(255, 255, 255, 0.15)",
                      borderRadius: "4px",
                      padding: "3px 8px",
                      color: "#cbd5e1",
                      fontSize: "10.5px",
                      cursor: "pointer",
                    }}
                    title="Restore officer clearance"
                  >
                    Restore
                  </button>
                </div>

                <div
                  style={{
                    marginTop: "10px",
                    background: "rgba(239, 68, 68, 0.12)",
                    borderLeft: "3px solid #ef4444",
                    padding: "8px 10px",
                    borderRadius: "2px",
                  }}
                >
                  <div style={{ fontSize: "10.5px", fontWeight: "800", color: "#f87171", textTransform: "uppercase", letterSpacing: "0.5px" }}>
                    Reason for Flagging:
                  </div>
                  <div style={{ fontSize: "12px", color: "#fecaca", marginTop: "2px", lineHeight: "1.4" }}>
                    {fRec.flag_reason || "Hardware PrintScreen or Snipping Tool capture attempt intercepted"}
                  </div>
                </div>

                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: "10px", fontSize: "10.5px", color: "var(--text-muted)" }}>
                  <span>Status: <strong style={{ color: "#f87171" }}>CLEARANCE SUSPENDED</strong></span>
                  <span>Incidents: <strong style={{ color: "#ffffff" }}>{fRec.total_violations || 1}</strong></span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* SECURITY EXPLANATION & ARCHITECTURAL INVARIANTS FOOTER */}
      <div
        style={{
          marginTop: "24px",
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))",
          gap: "14px",
        }}
      >
        <div
          style={{
            background: "rgba(255, 255, 255, 0.02)",
            border: "1px solid rgba(255, 255, 255, 0.08)",
            borderRadius: "8px",
            padding: "14px",
          }}
        >
          <div style={{ fontSize: "11px", fontWeight: "800", color: "#ffffff", marginBottom: "6px" }}>
            🛡️ ZERO DOM TEXT LAYER
          </div>
          <div style={{ fontSize: "12px", color: "var(--text-secondary)", lineHeight: "1.4" }}>
            The raw PDF is never transmitted to the browser. The document is converted server-side into a pure raster image buffer and drawn exclusively onto an HTML5 canvas element with zero selectable DOM spans.
          </div>
        </div>

        <div
          style={{
            background: "rgba(255, 255, 255, 0.02)",
            border: "1px solid rgba(255, 255, 255, 0.08)",
            borderRadius: "8px",
            padding: "14px",
          }}
        >
          <div style={{ fontSize: "11px", fontWeight: "800", color: "#ffffff", marginBottom: "6px" }}>
            🌊 2D DCT SPREAD-SPECTRUM
          </div>
          <div style={{ fontSize: "12px", color: "var(--text-secondary)", lineHeight: "1.4" }}>
            Each page passes through an 8x8 2D Discrete Cosine Transform. Pseudo-random noise derived from the officer&apos;s seed (<code style={{ color: "#fff" }}>seed_r</code>) is embedded into mid-frequency coefficients (<code style={{ color: "#fff" }}>3 ≤ u+v ≤ 7</code>), surviving screenshot recompression.
          </div>
        </div>

        <div
          style={{
            background: "rgba(255, 255, 255, 0.02)",
            border: "1px solid rgba(255, 255, 255, 0.08)",
            borderRadius: "8px",
            padding: "14px",
          }}
        >
          <div style={{ fontSize: "11px", fontWeight: "800", color: "#ffffff", marginBottom: "6px" }}>
            🚫 STRICT CLIENT LOCKDOWN
          </div>
          <div style={{ fontSize: "12px", color: "var(--text-secondary)", lineHeight: "1.4" }}>
            Window-level event listeners intercept keyboard shortcuts (<code style={{ color: "#fff" }}>Ctrl+S</code>, <code style={{ color: "#fff" }}>Ctrl+P</code>, <code style={{ color: "#fff" }}>F12</code>, DevTools), disable context menus, block clipboard operations, and enforce print-blanking styles.
          </div>
        </div>

        <div
          style={{
            background: "rgba(255, 255, 255, 0.02)",
            border: "1px solid rgba(255, 255, 255, 0.08)",
            borderRadius: "8px",
            padding: "14px",
          }}
        >
          <div style={{ fontSize: "11px", fontWeight: "800", color: "#ffffff", marginBottom: "6px" }}>
            📹 DEFOCUS &amp; CAPTURE TOTAL BLACKOUT
          </div>
          <div style={{ fontSize: "12px", color: "var(--text-secondary)", lineHeight: "1.4" }}>
            Enforces a mandatory 100% solid pitch-black screen whenever window focus is lost (WhatsApp call, app switching, screen capture) or PrintScreen is detected. Security enforcement is strictly system-controlled with zero recipient override or disable controls.
          </div>
        </div>
      </div>
    </div>
  );
}

export default function SecureViewerPage() {
  return (
    <Suspense fallback={<div style={{ padding: "40px", color: "#ffffff", textAlign: "center" }}>Initializing Secure Enclave...</div>}>
      <SecureViewerContent />
    </Suspense>
  );
}
