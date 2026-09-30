"use client";

import React, { useState, useEffect, useCallback, useMemo } from "react";
import { useRouter } from "next/navigation";
import SecureViewer from "@/components/SecureViewer";

interface AssignedDocument {
  document_hash: string;
  original_filename: string;
  recipient_id: string;
  kem_pubkey_id: string;
  encrypted_at?: string;
  file_size?: number;
  pdf_base64?: string;
  description?: string;
}

interface UserProfile {
  id: string;
  username: string;
  role: "head" | "recipient";
  recipient_id: string | null;
  name?: string | null;
}

export default function RecipientDashboard() {
  const router = useRouter();
  const [user, setUser] = useState<UserProfile | null>(null);
  const [documents, setDocuments] = useState<AssignedDocument[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [activeDoc, setActiveDoc] = useState<AssignedDocument | null>(null);
  const [securityToast, setSecurityToast] = useState<string | null>(null);
  const [isSimulatingViolation, setIsSimulatingViolation] = useState(false);

  const fetchSessionAndDocs = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);

      const meRes = await fetch("/api/auth/me", { cache: "no-store" });
      if (!meRes.ok) {
        router.push("/login");
        return;
      }
      const meData = await meRes.json();
      if (meData.user?.role !== "recipient") {
        if (meData.user?.role === "head") {
          router.push("/head");
          return;
        }
        router.push("/login");
        return;
      }
      setUser(meData.user);

      const docsRes = await fetch("/crypto-api/recipient/documents", { cache: "no-store" });
      if (!docsRes.ok) {
        const errJson = await docsRes.json().catch(() => ({}));
        throw new Error(errJson.detail || `Failed to fetch documents (${docsRes.status})`);
      }

      const docsData = await docsRes.json();
      setDocuments(docsData);
    } catch (err: any) {
      setError(err.message || "Failed to load assigned classified dossiers.");
    } finally {
      setLoading(false);
    }
  }, [router]);

  useEffect(() => {
    fetchSessionAndDocs();
  }, [fetchSessionAndDocs]);

  const handleLogout = async () => {
    try {
      await fetch("/api/auth/logout", { method: "POST" });
    } catch {}
    router.push("/login");
  };

  const handleFlagViolation = (recipientId: string, reason: string) => {
    setSecurityToast(
      `ENCLAVE VIOLATION INTERCEPTED: Unauthorized screen capture attempt logged to audit ledger. Head Commander notified.`
    );
    setTimeout(() => setSecurityToast(null), 8000);
  };

  const handleSimulateScreenshot = async () => {
    if (!user?.recipient_id) return;
    setIsSimulatingViolation(true);
    try {
      const res = await fetch("/api/flag-violation", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          recipient_id: user.recipient_id,
          violation_type: "SCREENSHOT_ATTEMPT",
          reason: "Hardware PrintScreen interception drill triggered by recipient",
          details: "Operator initiated defense validation drill",
        }),
      });

      if (res.ok) {
        setSecurityToast(
          "ENCLAVE VIOLATION LOGGED: Screenshot attempt intercepted. Alert sent to Head dashboard."
        );
      }
    } catch (e) {
      console.error("Simulation error:", e);
    } finally {
      setIsSimulatingViolation(false);
      setTimeout(() => setSecurityToast(null), 7000);
    }
  };

  const filteredDocs = useMemo(() => {
    return documents.filter((doc) => {
      const q = searchQuery.toLowerCase().trim();
      return (
        !q ||
        doc.original_filename?.toLowerCase().includes(q) ||
        doc.document_hash?.toLowerCase().includes(q) ||
        doc.description?.toLowerCase().includes(q)
      );
    });
  }, [documents, searchQuery]);

  return (
    <div
      style={{
        minHeight: "100vh",
        width: "100%",
        background: "#0a0c10",
        color: "#ffffff",
        fontFamily: "'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
        display: "flex",
        flexDirection: "column",
        boxSizing: "border-box",
      }}
    >
      {/* Security Toast Notification */}
      {securityToast && (
        <div
          style={{
            position: "fixed",
            top: "16px",
            left: "50%",
            transform: "translateX(-50%)",
            zIndex: 9999,
            width: "90%",
            maxWidth: "600px",
            background: "rgba(185, 28, 28, 0.95)",
            border: "1px solid #ef4444",
            borderRadius: "8px",
            padding: "14px 18px",
            boxShadow: "0 10px 30px rgba(0, 0, 0, 0.7)",
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            fontSize: "12px",
            fontFamily: "monospace",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
            <span style={{ fontSize: "16px" }}>🚨</span>
            <span>{securityToast}</span>
          </div>
          <button
            onClick={() => setSecurityToast(null)}
            style={{
              background: "transparent",
              border: "none",
              color: "#ffffff",
              cursor: "pointer",
              fontSize: "14px",
              paddingLeft: "10px",
            }}
          >
            ✕
          </button>
        </div>
      )}

      {/* Top Navbar */}
      <header
        style={{
          width: "100%",
          padding: "16px 28px",
          borderBottom: "1px solid rgba(255, 255, 255, 0.1)",
          background: "rgba(13, 16, 22, 0.95)",
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          flexWrap: "wrap",
          gap: "14px",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
          <div
            style={{
              width: "32px",
              height: "32px",
              borderRadius: "6px",
              background: "rgba(255, 255, 255, 0.1)",
              border: "1px solid rgba(255, 255, 255, 0.2)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              fontWeight: 700,
              fontSize: "13px",
              letterSpacing: "1px",
            }}
          >
            WE
          </div>
          <div>
            <div style={{ fontSize: "14px", fontWeight: 600, letterSpacing: "1px" }}>
              WEBEYE RECIPIENT ENCLAVE
            </div>
            <div style={{ fontSize: "11px", color: "#94a3b8", fontFamily: "monospace" }}>
              AIR-GAP FORENSIC ATTRIBUTION • ZERO-CLIENT-STORAGE
            </div>
          </div>
        </div>

        {/* Officer info & logout */}
        <div style={{ display: "flex", alignItems: "center", gap: "16px" }}>
          <div style={{ textAlign: "right", fontFamily: "monospace", fontSize: "11px" }}>
            <div style={{ color: "#ffffff", fontWeight: 600 }}>
              {user?.name || user?.username || "Recipient Officer"}
            </div>
            <div style={{ color: "#10b981" }}>ID: {user?.recipient_id || user?.username}</div>
          </div>

          <button
            onClick={handleLogout}
            style={{
              background: "transparent",
              border: "1px solid rgba(255, 255, 255, 0.25)",
              color: "#ffffff",
              padding: "6px 14px",
              fontSize: "11px",
              fontFamily: "monospace",
              letterSpacing: "1px",
              cursor: "pointer",
              borderRadius: "4px",
              transition: "all 0.2s ease",
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.background = "rgba(255, 255, 255, 0.1)";
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.background = "transparent";
            }}
          >
            EXIT ENCLAVE
          </button>
        </div>
      </header>

      {/* Main Container */}
      <main
        style={{
          width: "100%",
          maxWidth: "1180px",
          margin: "0 auto",
          padding: "32px 20px",
          display: "flex",
          flexDirection: "column",
          gap: "24px",
          boxSizing: "border-box",
        }}
      >
        {/* Officer Dossier Hero Card */}
        <div
          style={{
            background: "rgba(18, 22, 29, 0.85)",
            border: "1px solid rgba(255, 255, 255, 0.12)",
            borderRadius: "10px",
            padding: "24px",
            display: "flex",
            flexDirection: "column",
            gap: "18px",
          }}
        >
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              flexWrap: "wrap",
              gap: "12px",
              borderBottom: "1px solid rgba(255, 255, 255, 0.08)",
              paddingBottom: "16px",
            }}
          >
            <div>
              <div style={{ fontSize: "16px", fontWeight: 600, color: "#ffffff" }}>
                Operational Security Clearance
              </div>
              <div style={{ fontSize: "12px", color: "#94a3b8", marginTop: "3px" }}>
                Clearance Level: TOP SECRET // LEVEL 4 CLASSIFIED ACCESS
              </div>
            </div>

            <div
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: "6px",
                padding: "4px 10px",
                borderRadius: "4px",
                background: "rgba(16, 185, 129, 0.15)",
                border: "1px solid rgba(16, 185, 129, 0.4)",
                color: "#10b981",
                fontSize: "11px",
                fontFamily: "monospace",
                fontWeight: 600,
              }}
            >
              <span
                style={{
                  width: "6px",
                  height: "6px",
                  borderRadius: "50%",
                  background: "#10b981",
                  display: "inline-block",
                }}
              />
              ENCLAVE INTEGRITY: ACTIVE
            </div>
          </div>

          {/* Cryptographic Badges Grid */}
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
              gap: "12px",
            }}
          >
            <div
              style={{
                background: "rgba(255, 255, 255, 0.03)",
                border: "1px solid rgba(255, 255, 255, 0.08)",
                borderRadius: "6px",
                padding: "12px 14px",
              }}
            >
              <div style={{ fontSize: "10px", fontFamily: "monospace", color: "#94a3b8" }}>
                FIPS 203 ML-KEM
              </div>
              <div style={{ fontSize: "13px", fontWeight: 600, color: "#ffffff", marginTop: "4px" }}>
                ML-KEM-768 Lattice
              </div>
              <div style={{ fontSize: "11px", color: "#64748b", marginTop: "2px" }}>
                1,088-byte lattice ciphertexts
              </div>
            </div>

            <div
              style={{
                background: "rgba(255, 255, 255, 0.03)",
                border: "1px solid rgba(255, 255, 255, 0.08)",
                borderRadius: "6px",
                padding: "12px 14px",
              }}
            >
              <div style={{ fontSize: "10px", fontFamily: "monospace", color: "#94a3b8" }}>
                FIPS 204 ML-DSA
              </div>
              <div style={{ fontSize: "13px", fontWeight: 600, color: "#ffffff", marginTop: "4px" }}>
                Dilithium-3 Provenance
              </div>
              <div style={{ fontSize: "11px", color: "#64748b", marginTop: "2px" }}>
                3,309-byte quantum signature
              </div>
            </div>

            <div
              style={{
                background: "rgba(255, 255, 255, 0.03)",
                border: "1px solid rgba(255, 255, 255, 0.08)",
                borderRadius: "6px",
                padding: "12px 14px",
              }}
            >
              <div style={{ fontSize: "10px", fontFamily: "monospace", color: "#94a3b8" }}>
                TARDOS WATERMARK
              </div>
              <div style={{ fontSize: "13px", fontWeight: 600, color: "#ffffff", marginTop: "4px" }}>
                2D DCT Spread-Spectrum
              </div>
              <div style={{ fontSize: "11px", color: "#64748b", marginTop: "2px" }}>
                Bound to secret recipient seed
              </div>
            </div>
          </div>

          {/* Anti-Exfiltration Telemetry & Screenshot Simulation Drill */}
          <div
            style={{
              paddingTop: "14px",
              borderTop: "1px solid rgba(255, 255, 255, 0.08)",
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              flexWrap: "wrap",
              gap: "12px",
            }}
          >
            <div style={{ fontSize: "11.5px", color: "#94a3b8" }}>
              <span style={{ color: "#ffffff", fontWeight: 600 }}>Anti-Screenshot Guard Active: </span>
              Hardware screen capture attempts are intercepted and alerted to Head Command.
            </div>

            <button
              onClick={handleSimulateScreenshot}
              disabled={isSimulatingViolation}
              style={{
                background: "rgba(239, 68, 68, 0.15)",
                border: "1px solid rgba(239, 68, 68, 0.45)",
                color: "#fca5a5",
                padding: "6px 14px",
                fontSize: "11px",
                fontFamily: "monospace",
                fontWeight: 600,
                cursor: isSimulatingViolation ? "not-allowed" : "pointer",
                borderRadius: "4px",
                transition: "all 0.2s ease",
              }}
              title="Test screen capture interception and send alert to Head Commander"
            >
              {isSimulatingViolation ? "Dispatching Alert..." : "⚡ Simulate Screenshot Violation Drill"}
            </button>
          </div>
        </div>

        {/* Assigned Classified Dossiers Section */}
        <div
          style={{
            background: "rgba(18, 22, 29, 0.85)",
            border: "1px solid rgba(255, 255, 255, 0.12)",
            borderRadius: "10px",
            padding: "24px",
            display: "flex",
            flexDirection: "column",
            gap: "20px",
          }}
        >
          {/* Header Row */}
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              flexWrap: "wrap",
              gap: "14px",
            }}
          >
            <div>
              <div style={{ fontSize: "16px", fontWeight: 600, color: "#ffffff" }}>
                Classified Dossiers Dispatched to You ({documents.length})
              </div>
              <div style={{ fontSize: "12px", color: "#94a3b8", marginTop: "3px" }}>
                Rendered strictly via server-side DCT watermarking. Raw PDF bytes are blocked from client storage.
              </div>
            </div>

            {/* Search Input */}
            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search dossiers..."
                style={{
                  background: "rgba(255, 255, 255, 0.05)",
                  border: "1px solid rgba(255, 255, 255, 0.15)",
                  borderRadius: "4px",
                  padding: "6px 12px",
                  color: "#ffffff",
                  fontSize: "12px",
                  outline: "none",
                  width: "200px",
                  fontFamily: "inherit",
                }}
              />
              <button
                onClick={fetchSessionAndDocs}
                style={{
                  background: "rgba(255, 255, 255, 0.05)",
                  border: "1px solid rgba(255, 255, 255, 0.15)",
                  color: "#ffffff",
                  padding: "6px 10px",
                  fontSize: "12px",
                  borderRadius: "4px",
                  cursor: "pointer",
                }}
                title="Refresh Dossiers"
              >
                ↻
              </button>
            </div>
          </div>

          {/* Dossiers Grid */}
          {loading ? (
            <div style={{ textAlign: "center", padding: "40px", color: "#94a3b8", fontSize: "13px" }}>
              Decrypting session manifest & resolving recipient ledger...
            </div>
          ) : error ? (
            <div
              style={{
                padding: "20px",
                background: "rgba(239, 68, 68, 0.15)",
                border: "1px solid rgba(239, 68, 68, 0.4)",
                borderRadius: "6px",
                color: "#fca5a5",
                fontSize: "12px",
                textAlign: "center",
              }}
            >
              {error}
            </div>
          ) : filteredDocs.length === 0 ? (
            <div
              style={{
                textAlign: "center",
                padding: "50px 20px",
                border: "1px dashed rgba(255, 255, 255, 0.1)",
                borderRadius: "8px",
                color: "#94a3b8",
                fontSize: "13px",
              }}
            >
              {searchQuery
                ? "No matching classified dossiers found."
                : "No dossiers currently dispatched to this recipient ID."}
            </div>
          ) : (
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))",
                gap: "16px",
              }}
            >
              {filteredDocs.map((doc, idx) => (
                <div
                  key={doc.document_hash + idx}
                  style={{
                    background: "rgba(10, 12, 16, 0.6)",
                    border: "1px solid rgba(255, 255, 255, 0.1)",
                    borderRadius: "8px",
                    padding: "18px",
                    display: "flex",
                    flexDirection: "column",
                    justifyContent: "space-between",
                    gap: "14px",
                  }}
                >
                  <div>
                    <div
                      style={{
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "flex-start",
                        marginBottom: "10px",
                      }}
                    >
                      <div>
                        <div style={{ fontSize: "14px", fontWeight: 600, color: "#ffffff" }}>
                          {doc.original_filename || "classified_dossier.pdf"}
                        </div>
                        <div style={{ fontSize: "11px", color: "#64748b", marginTop: "2px" }}>
                          {doc.description || "Forensic Encrypted Dossier"}
                        </div>
                      </div>

                      <span
                        style={{
                          fontSize: "9.5px",
                          fontFamily: "monospace",
                          padding: "2px 6px",
                          borderRadius: "3px",
                          background: "rgba(239, 68, 68, 0.2)",
                          color: "#fca5a5",
                          border: "1px solid rgba(239, 68, 68, 0.4)",
                          textTransform: "uppercase",
                        }}
                      >
                        RESTRICTED
                      </span>
                    </div>

                    {/* Metadata */}
                    <div
                      style={{
                        background: "rgba(255, 255, 255, 0.02)",
                        border: "1px solid rgba(255, 255, 255, 0.05)",
                        borderRadius: "4px",
                        padding: "10px 12px",
                        fontSize: "11px",
                        fontFamily: "monospace",
                        color: "#94a3b8",
                        display: "flex",
                        flexDirection: "column",
                        gap: "4px",
                      }}
                    >
                      <div style={{ display: "flex", justifyContent: "space-between" }}>
                        <span>SHA-256:</span>
                        <span style={{ color: "#ffffff" }}>
                          {doc.document_hash ? doc.document_hash.substring(0, 14) + "..." : "N/A"}
                        </span>
                      </div>
                      <div style={{ display: "flex", justifyContent: "space-between" }}>
                        <span>Recipient ID:</span>
                        <span style={{ color: "#10b981" }}>{doc.recipient_id}</span>
                      </div>
                      <div style={{ display: "flex", justifyContent: "space-between" }}>
                        <span>KEM Key:</span>
                        <span style={{ color: "#ffffff" }}>{doc.kem_pubkey_id || "ML-KEM-768"}</span>
                      </div>
                    </div>
                  </div>

                  {/* Open in Secure Viewer button */}
                  <button
                    onClick={() => setActiveDoc(doc)}
                    style={{
                      width: "100%",
                      padding: "10px",
                      background: "#ffffff",
                      color: "#0a0c10",
                      border: "none",
                      borderRadius: "6px",
                      fontSize: "12px",
                      fontWeight: 600,
                      letterSpacing: "0.5px",
                      cursor: "pointer",
                      transition: "opacity 0.2s ease",
                    }}
                    onMouseEnter={(e) => (e.currentTarget.style.opacity = "0.9")}
                    onMouseLeave={(e) => (e.currentTarget.style.opacity = "1")}
                  >
                    Open in Secure Enclave Viewer ↗
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      </main>

      {/* Modal SecureViewer Canvas Enclave */}
      {activeDoc && (
        <div
          style={{
            position: "fixed",
            inset: 0,
            zIndex: 9999,
            background: "rgba(0, 0, 0, 0.85)",
            backdropFilter: "blur(8px)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            padding: "16px",
          }}
        >
          <div
            style={{
              position: "relative",
              width: "100%",
              maxWidth: "1020px",
              height: "92vh",
              background: "#0a0c10",
              border: "1px solid rgba(255, 255, 255, 0.15)",
              borderRadius: "12px",
              overflow: "hidden",
              boxShadow: "0 20px 60px rgba(0, 0, 0, 0.9)",
              display: "flex",
              flexDirection: "column",
            }}
          >
            <SecureViewer
              recipientId={activeDoc.recipient_id || user?.recipient_id || user?.username || ""}
              recipientName={user?.name || user?.username || "Authenticated Recipient"}
              documentHash={activeDoc.document_hash}
              documentTitle={activeDoc.original_filename}
              pdfBase64={activeDoc.pdf_base64}
              onClose={() => setActiveDoc(null)}
              onFlagViolation={handleFlagViolation}
            />
          </div>
        </div>
      )}
    </div>
  );
}
