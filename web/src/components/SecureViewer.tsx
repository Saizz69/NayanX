"use client";

import React, { useEffect, useRef, useState, useCallback } from "react";

export interface SecureViewerProps {
  recipientId: string;
  recipientName?: string;
  documentHash?: string;
  documentId?: string;
  pdfBase64?: string;
  documentTitle?: string;
  onClose?: () => void;
  onFlagViolation?: (recipientId: string, reason: string) => void;
}

interface PageData {
  page_index: number;
  total_pages: number;
  width: number;
  height: number;
  watermarked_image_data: string;
  watermark_algorithm: string;
  recipient_id: string;
  seed_commitment: string;
  security_lockdown: boolean;
  metadata?: {
    psnr_db?: number;
    blocks_modulated?: number;
    coeffs_per_block?: number;
    alpha?: number;
    mid_freq_band?: string;
  };
}

export default function SecureViewer({
  recipientId,
  recipientName,
  documentHash,
  documentId,
  pdfBase64,
  documentTitle = "Classified Forensic Intelligence Briefing",
  onClose,
  onFlagViolation,
}: SecureViewerProps) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const containerRef = useRef<HTMLDivElement | null>(null);
  const scrollContainerRef = useRef<HTMLDivElement | null>(null);

  const [pageIndex, setPageIndex] = useState<number>(0);
  const [totalPages, setTotalPages] = useState<number>(1);
  const [pageData, setPageData] = useState<PageData | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [securityAlert, setSecurityAlert] = useState<string | null>(null);
  const [viewMode, setViewMode] = useState<"fit-page" | "fit-width" | "custom">("fit-page");
  const [zoomFactor, setZoomFactor] = useState<number>(1.0);
  const [verificationResult, setVerificationResult] = useState<any | null>(null);
  const [verifying, setVerifying] = useState<boolean>(false);

  // Compute neat whole-page display dimensions with zero top/bottom cropping
  const getDisplayDimensions = useCallback(() => {
    if (!pageData || !pageData.width || !pageData.height) {
      return { width: 448, height: 580 };
    }
    const aspect = pageData.width / pageData.height; // e.g. 1224 / 1584 = 0.7727

    if (viewMode === "fit-page") {
      // Comfortably fits the WHOLE page inside the viewer height with zero vertical overflow
      const targetHeight = 580;
      const targetWidth = Math.round(targetHeight * aspect);
      return { width: targetWidth, height: targetHeight };
    } else if (viewMode === "fit-width") {
      // Expands to readable width for text reading with smooth vertical scrolling
      const targetWidth = 820;
      const targetHeight = Math.round(targetWidth / aspect);
      return { width: targetWidth, height: targetHeight };
    } else {
      // Custom zoom scaled relative to base whole-page fit
      const baseHeight = 580;
      const targetHeight = Math.round(baseHeight * zoomFactor);
      const targetWidth = Math.round(targetHeight * aspect);
      return { width: targetWidth, height: targetHeight };
    }
  }, [pageData, viewMode, zoomFactor]);

  const displayDims = getDisplayDimensions();

  // Scroll to top immediately when page or view mode changes
  useEffect(() => {
    if (scrollContainerRef.current) {
      scrollContainerRef.current.scrollTop = 0;
    }
  }, [pageIndex, viewMode]);

  // Anti-Screenshot & Screen Capture Protection States
  const [isWindowBlurred, setIsWindowBlurred] = useState<boolean>(false);
  const [canvasBlackout, setCanvasBlackout] = useState<boolean>(false);
  const [interceptedScreenshots, setInterceptedScreenshots] = useState<number>(0);

  // Multi-Display / Extended Display Detection
  const [isMultiScreen, setIsMultiScreen] = useState<boolean>(false);

  useEffect(() => {
    if (typeof window !== "undefined" && window.screen) {
      if (
        (window.screen as any).isExtended ||
        (window.screen.availWidth && window.screen.availWidth > window.screen.width)
      ) {
        setIsMultiScreen(true);
      }
    }
  }, []);

  // Trigger security toast with auto-dismiss
  const triggerAlert = useCallback((msg: string) => {
    setSecurityAlert(msg);
    setTimeout(() => {
      setSecurityAlert((prev) => (prev === msg ? null : prev));
    }, 4500);
  }, []);

  // Report Security Violation to backend and flag recipient with reason
  const reportSecurityViolation = useCallback(
    async (violationType: string, reason: string, details?: string) => {
      const effectiveId = recipientId || "";
      try {
        await fetch("/api/flag-violation", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            recipient_id: effectiveId,
            violation_type: violationType,
            reason: reason,
            details: details || `Security violation intercepted during live session on page ${pageIndex + 1}.`,
          }),
        });
        if (onFlagViolation) {
          onFlagViolation(effectiveId, reason);
        }
      } catch (err) {
        console.error("Failed to report security violation:", err);
      }
    },
    [recipientId, pageIndex, onFlagViolation]
  );

  // 1. Fetch server-side rasterized & DCT-watermarked page payload
  const fetchPage = useCallback(
    async (targetPage: number) => {
      // Safety check: ensure recipientId is non-empty
      const effectiveRecipientId = recipientId || "";

      setLoading(true);
      setErrorMessage(null);
      setVerificationResult(null);

      try {
        const res = await fetch("/api/secure-render", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            recipient_id: effectiveRecipientId,
            document_hash: documentHash || undefined,
            document_id: documentId || undefined,
            pdf_base64: pdfBase64 || undefined,
            page_index: targetPage,
            dpi_scale: 2.0,
            alpha: 3.5,
          }),
        });

        if (!res.ok) {
          const errData = await res.json().catch(() => ({}));
          throw new Error(errData.error || `Server responded with HTTP ${res.status}`);
        }

        const data: PageData = await res.json();
        setPageData(data);
        setTotalPages(data.total_pages || 1);
        setPageIndex(data.page_index ?? targetPage);
      } catch (err: any) {
        console.error("Failed to fetch secure raster page:", err);
        setErrorMessage(err.message || "Failed to load rasterized page.");
      } finally {
        setLoading(false);
      }
    },
    [recipientId, documentHash, documentId, pdfBase64]
  );

  useEffect(() => {
    fetchPage(pageIndex);
  }, [fetchPage, pageIndex]);

  // 2. Render strictly onto HTML5 <canvas> (Zero selectable text spans or PDF.js DOM text layers)
  useEffect(() => {
    if (!pageData || !canvasRef.current) return;

    const canvas = canvasRef.current;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const img = new Image();
    img.crossOrigin = "anonymous";
    img.onload = () => {
      // Set high-DPI canvas dimensions
      canvas.width = img.width;
      canvas.height = img.height;

      // Draw the rasterized page starting at 0, 0
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      ctx.drawImage(img, 0, 0);

      // A. FORENSIC DIAGONAL WATERMARK TILES (Phone camera / photograph deterrent)
      ctx.save();
      ctx.rotate((-22 * Math.PI) / 180);
      ctx.font = "bold 15px monospace";
      ctx.fillStyle = "rgba(71, 85, 105, 0.08)"; // Low opacity forensic pattern
      const dateStr = new Date().toISOString().slice(0, 10);
      for (let x = -canvas.width; x < canvas.width * 2; x += 320) {
        for (let y = -canvas.height; y < canvas.height * 2; y += 130) {
          ctx.fillText(`RESTRICTED // ${recipientId} // ${dateStr}`, x, y);
        }
      }
      ctx.restore();

      // B. FORENSIC SESSION BANNER AT BOTTOM OF CANVAS
      ctx.save();
      ctx.fillStyle = "rgba(10, 12, 16, 0.85)";
      ctx.fillRect(0, canvas.height - 34, canvas.width, 34);
      ctx.fillStyle = "rgba(255, 255, 255, 0.8)";
      ctx.font = "bold 12.5px monospace";
      ctx.fillText(
        `WEBEYE SECURE RECIPIENT ENCLAVE // OFFICER: ${recipientId} // SEED COMMITMENT: ${pageData.seed_commitment.slice(
          0,
          20
        )}... // 2D-DCT WATERMARKED`,
        18,
        canvas.height - 13
      );
      ctx.restore();
    };
    img.src = pageData.watermarked_image_data;
  }, [pageData, recipientId]);

  // 3. Client-Side Lockdown & Anti-Screenshot Event Interceptors
  useEffect(() => {
    // A. Intercept Keyboard Shortcuts at window level
    const handleKeyDown = (e: KeyboardEvent) => {
      const isCtrlOrMeta = e.ctrlKey || e.metaKey;

      // 1. SCREENSHOT KEY DETECTION (PrintScreen, Alt+PrintScreen, Ctrl+PrintScreen)
      if (e.key === "PrintScreen" || e.code === "PrintScreen") {
        e.preventDefault();
        e.stopPropagation();

        // Flush and overwrite the clipboard immediately
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard
            .writeText("WEBEYE CLASSIFIED DOCUMENT: SCREEN CAPTURE PROHIBITED BY ENCLAVE POLICY")
            .catch(() => {});
        }

        // Momentarily blackout canvas so screenshot tools capture a black screen
        setCanvasBlackout(true);
        setTimeout(() => setCanvasBlackout(false), 2200);

        setInterceptedScreenshots((prev) => prev + 1);
        reportSecurityViolation(
          "SCREENSHOT_KEY_PRINTSCREEN",
          "Hardware PrintScreen key pressed while viewing classified document",
          "Enclave intercepted keydown, purged system clipboard, and engaged blackout shield."
        );
        triggerAlert("🚨 SCREENSHOT DETECTED & INTERCEPTED: Officer FLAGGED. Incident recorded to audit ledger.");
        return;
      }

      // 2. Intercept Save: Ctrl+S, Cmd+S
      if (isCtrlOrMeta && (e.key === "s" || e.key === "S")) {
        e.preventDefault();
        e.stopPropagation();
        reportSecurityViolation(
          "UNAUTHORIZED_SAVE_ATTEMPT",
          "Attempted browser Save (Ctrl+S / Cmd+S) to extract document"
        );
        triggerAlert("🚫 SAVE PROHIBITED: Document extraction locked. Officer FLAGGED.");
        return;
      }

      // 3. Intercept Print: Ctrl+P, Cmd+P
      if (isCtrlOrMeta && (e.key === "p" || e.key === "P")) {
        e.preventDefault();
        e.stopPropagation();
        reportSecurityViolation(
          "UNAUTHORIZED_PRINT_ATTEMPT",
          "Attempted physical printout / PDF export (Ctrl+P / Cmd+P)"
        );
        triggerAlert("🚫 PRINTING BLOCKED: Physical printouts prohibited. Officer FLAGGED.");
        return;
      }

      // 4. Intercept View Source: Ctrl+U, Cmd+U
      if (isCtrlOrMeta && (e.key === "u" || e.key === "U")) {
        e.preventDefault();
        e.stopPropagation();
        triggerAlert("🚫 SOURCE LOCKED: Document is server-rasterized; no DOM text exists.");
        return;
      }

      // 5. Intercept DevTools: F12, Ctrl+Shift+I, Ctrl+Shift+C, Ctrl+Shift+J, Cmd+Option+I/J/C
      if (
        e.key === "F12" ||
        (isCtrlOrMeta &&
          e.shiftKey &&
          ["I", "i", "C", "c", "J", "j"].includes(e.key)) ||
        (e.metaKey && e.altKey && ["I", "i", "J", "j", "C", "c"].includes(e.key))
      ) {
        e.preventDefault();
        e.stopPropagation();
        reportSecurityViolation(
          "DEVTOOLS_INSPECTION_ATTEMPT",
          "Attempted Developer Tools / DOM inspector inspection to extract canvas data"
        );
        triggerAlert("🚫 DEVTOOLS INTERCEPTED: Debugging tools blocked. Officer FLAGGED.");
        return;
      }
    };

    // B. Window Blur & Visibility Change Detection (Fires when Snipping Tool or external capture tool activates)
    const handleWindowBlur = () => {
      setIsWindowBlurred(true);
      reportSecurityViolation(
        "SCREEN_CAPTURE_WINDOW_BLUR",
        "External capture tool / Snipping Tool engagement detected via window focus loss",
        "Canvas blanked with 24px blur shield to prevent screen recording."
      );
    };

    const handleWindowFocus = () => {
      setIsWindowBlurred(false);
    };

    const handleVisibilityChange = () => {
      if (document.hidden) {
        setIsWindowBlurred(true);
        reportSecurityViolation(
          "SCREEN_CAPTURE_WINDOW_BLUR",
          "Document hidden / Snipping Tool overlay detected via visibility change",
          "Canvas blanked with 24px blur shield."
        );
      } else {
        setIsWindowBlurred(false);
      }
    };

    // C. Intercept Clipboard Events (Copy, Cut)
    const handleCopyCut = (e: ClipboardEvent) => {
      e.preventDefault();
      triggerAlert("🚫 CLIPBOARD BLOCKED: Text and image copying is prohibited.");
    };

    // D. Intercept Right-Click Context Menu
    const handleContextMenu = (e: MouseEvent) => {
      e.preventDefault();
      triggerAlert("🚫 CONTEXT MENU DISABLED: Right-click options are disabled in the secure viewer.");
    };

    // E. Intercept Image Dragging & Selection
    const handleDragStart = (e: DragEvent) => {
      e.preventDefault();
      triggerAlert("🚫 DRAG-AND-DROP DISABLED: Canvas assets cannot be dragged out.");
    };

    const handleSelectStart = (e: Event) => {
      e.preventDefault();
    };

    // F. Blank canvas on Print attempt
    const handleBeforePrint = () => {
      triggerAlert("🚫 PRINT DETECTED: Blanking canvas to prevent reproduction.");
      if (canvasRef.current) {
        const ctx = canvasRef.current.getContext("2d");
        if (ctx) {
          ctx.fillStyle = "#000000";
          ctx.fillRect(0, 0, canvasRef.current.width, canvasRef.current.height);
          ctx.fillStyle = "#ffffff";
          ctx.font = "24px sans-serif";
          ctx.fillText("CLASSIFIED CONTENT — PRINT RESTRICTED", 100, 200);
        }
      }
    };

    // Attach listeners at window & document level
    window.addEventListener("keydown", handleKeyDown, true);
    window.addEventListener("blur", handleWindowBlur);
    window.addEventListener("focus", handleWindowFocus);
    document.addEventListener("visibilitychange", handleVisibilityChange);
    window.addEventListener("copy", handleCopyCut, true);
    window.addEventListener("cut", handleCopyCut, true);
    window.addEventListener("contextmenu", handleContextMenu, true);
    window.addEventListener("dragstart", handleDragStart, true);
    window.addEventListener("selectstart", handleSelectStart, true);
    window.addEventListener("beforeprint", handleBeforePrint);

    return () => {
      window.removeEventListener("keydown", handleKeyDown, true);
      window.removeEventListener("blur", handleWindowBlur);
      window.removeEventListener("focus", handleWindowFocus);
      document.removeEventListener("visibilitychange", handleVisibilityChange);
      window.removeEventListener("copy", handleCopyCut, true);
      window.removeEventListener("cut", handleCopyCut, true);
      window.removeEventListener("contextmenu", handleContextMenu, true);
      window.removeEventListener("dragstart", handleDragStart, true);
      window.removeEventListener("selectstart", handleSelectStart, true);
      window.removeEventListener("beforeprint", handleBeforePrint);
    };
  }, [triggerAlert]);

  // 4. Test DCT Watermark Detection on Live Rendered Canvas
  const handleVerifyDctWatermark = async () => {
    if (!pageData) return;
    setVerifying(true);
    setVerificationResult(null);

    try {
      const apiUrl = process.env.NEXT_PUBLIC_CRYPTO_API_URL || "/crypto-api";
      const resolvedDocHash = documentHash || (pageData as any)?.document_hash || (pageData as any)?.metadata?.document_hash || undefined;
      const res = await fetch(`${apiUrl}/documents/verify-dct-watermark`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          image_base64: pageData.watermarked_image_data,
          recipient_id: recipientId,
          document_hash: resolvedDocHash,
          document_id: documentId,
        }),
      });

      if (!res.ok) {
        throw new Error(`Verification service returned HTTP ${res.status}`);
      }

      const resData = await res.json();
      setVerificationResult(resData);
    } catch (e: any) {
      console.error("DCT Watermark verification error:", e);
      setVerificationResult({ error: e.message || "Verification failed." });
    } finally {
      setVerifying(false);
    }
  };

  return (
    <div
      ref={containerRef}
      style={{
        position: "relative",
        background: "#080a0e",
        color: "#ffffff",
        borderRadius: "12px",
        border: "1px solid rgba(255, 255, 255, 0.15)",
        boxShadow: "0 20px 40px rgba(0, 0, 0, 0.8)",
        overflow: "hidden",
        userSelect: "none",
        WebkitUserSelect: "none",
        MozUserSelect: "none",
        msUserSelect: "none",
      }}
    >
      {/* INJECTED PRINT PROTECTION CSS */}
      <style>{`
        @media print {
          html, body, * {
            display: none !important;
            visibility: hidden !important;
            opacity: 0 !important;
            background: #000000 !important;
          }
        }
      `}</style>

      {/* TOP ENCLAVE HEADER BAR */}
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          padding: "12px 18px",
          background: "rgba(255, 255, 255, 0.04)",
          borderBottom: "1px solid rgba(255, 255, 255, 0.1)",
          flexWrap: "wrap",
          gap: "10px",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
          <span
            style={{
              background: "rgba(239, 68, 68, 0.2)",
              color: "#f87171",
              border: "1px solid rgba(239, 68, 68, 0.4)",
              borderRadius: "6px",
              padding: "4px 8px",
              fontSize: "11px",
              fontWeight: "800",
              letterSpacing: "0.5px",
            }}
          >
            🔒 SECURE RECIPIENT ENCLAVE
          </span>
          <div>
            <div style={{ fontSize: "14px", fontWeight: "700", color: "#ffffff" }}>
              {documentTitle}
            </div>
            <div style={{ fontSize: "11px", color: "var(--text-secondary)" }}>
              Officer: <strong>{recipientName || recipientId}</strong> (<code style={{ color: "#ffffff" }}>{recipientId}</code>)
            </div>
          </div>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          {interceptedScreenshots > 0 && (
            <span
              style={{
                background: "rgba(239, 68, 68, 0.25)",
                color: "#fca5a5",
                padding: "4px 8px",
                borderRadius: "4px",
                fontSize: "11px",
                fontWeight: "700",
              }}
            >
              ⚠️ {interceptedScreenshots} Capture Attempt{interceptedScreenshots > 1 ? "s" : ""} Intercepted
            </span>
          )}


          <button
            onClick={() => {
              setCanvasBlackout(true);
              setTimeout(() => setCanvasBlackout(false), 2200);
              setInterceptedScreenshots((prev) => prev + 1);
              reportSecurityViolation(
                "SCREENSHOT_KEY_PRINTSCREEN",
                "Hardware PrintScreen key pressed while viewing classified document",
                "Manually simulated enclave audit test: clipboard purged, blackout engaged, officer flagged."
              );
              triggerAlert(
                `🚨 SCREENSHOT DETECTED & INTERCEPTED: Officer '${recipientId}' FLAGGED for security violation. Reason: Hardware PrintScreen capture attempt.`
              );
            }}
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
            title="Simulate an unauthorized screenshot capture to verify real-time officer flagging"
          >
            🚨 Simulate Screenshot Violation
          </button>

          <button
            onClick={handleVerifyDctWatermark}
            disabled={verifying || !pageData}
            style={{
              background: "rgba(255, 255, 255, 0.08)",
              border: "1px solid rgba(255, 255, 255, 0.2)",
              borderRadius: "6px",
              padding: "6px 12px",
              color: "#ffffff",
              fontSize: "11px",
              fontWeight: "600",
              cursor: verifying ? "not-allowed" : "pointer",
            }}
            title="Inspect 2D DCT mid-frequency coefficients and test correlation against officer seed_r"
          >
            {verifying ? "Auditing DCT..." : "🔍 Audit DCT Watermark"}
          </button>

          {onClose && (
            <button
              onClick={onClose}
              style={{
                background: "rgba(255, 255, 255, 0.05)",
                border: "1px solid rgba(255, 255, 255, 0.15)",
                borderRadius: "6px",
                padding: "6px 12px",
                color: "#cbd5e1",
                fontSize: "11px",
                fontWeight: "600",
                cursor: "pointer",
              }}
            >
              ✕ Exit Enclave
            </button>
          )}
        </div>
      </div>

      {/* SECURITY LOCKDOWN STATUS STRIP */}
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          padding: "6px 18px",
          background: "rgba(0, 0, 0, 0.4)",
          borderBottom: "1px solid rgba(255, 255, 255, 0.06)",
          fontSize: "10.5px",
          color: "var(--text-muted)",
          flexWrap: "wrap",
          gap: "8px",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "12px", flexWrap: "wrap" }}>
          <span>🛡️ Server-Side Headless Raster</span>
          <span>•</span>
          <span>🌊 2D DCT Mid-Frequency Spread-Spectrum</span>
          <span>•</span>
          <span>🚫 Zero Selectable DOM Text</span>
          <span>•</span>
          <span style={{ color: "#34d399" }}>● Anti-Screenshot Shield Active</span>
          {isMultiScreen && (
            <>
              <span>•</span>
              <span style={{ color: "#f59e0b", fontWeight: "700" }}>⚠️ Multi-Display Active</span>
            </>
          )}
        </div>
        <div>
          {pageData?.seed_commitment && (
            <span>
              SHA3-256 Seed Commitment:{" "}
              <code style={{ color: "#ffffff" }}>{pageData.seed_commitment.slice(0, 24)}...</code>
            </span>
          )}
        </div>
      </div>

      {/* VERIFICATION TOAST / ALERT BANNER */}
      {securityAlert && (
        <div
          style={{
            position: "absolute",
            top: "80px",
            left: "50%",
            transform: "translateX(-50%)",
            background: "rgba(185, 28, 28, 0.95)",
            color: "#ffffff",
            padding: "10px 20px",
            borderRadius: "8px",
            fontSize: "12px",
            fontWeight: "700",
            boxShadow: "0 8px 24px rgba(0, 0, 0, 0.6)",
            zIndex: 1000,
            border: "1px solid #f87171",
            display: "flex",
            alignItems: "center",
            gap: "8px",
            animation: "fadeIn 0.2s ease-in-out",
          }}
        >
          <span>⚠️</span>
          <span>{securityAlert}</span>
        </div>
      )}

      {/* DCT WATERMARK AUDIT RESULT MODAL / BANNER */}
      {verificationResult && (
        <div
          style={{
            margin: "12px 18px",
            padding: "12px 16px",
            borderRadius: "8px",
            background: verificationResult.is_match
              ? "rgba(16, 185, 129, 0.12)"
              : "rgba(239, 68, 68, 0.12)",
            border: verificationResult.is_match
              ? "1px solid rgba(16, 185, 129, 0.3)"
              : "1px solid rgba(239, 68, 68, 0.3)",
            fontSize: "12px",
          }}
        >
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span style={{ fontWeight: "700", color: verificationResult.is_match ? "#34d399" : "#f87171" }}>
              {verificationResult.is_match
                ? "✓ 2D DCT SPREAD-SPECTRUM WATERMARK CONFIRMED"
                : "⚠️ DCT WATERMARK MISMATCH"}
            </span>
            <button
              onClick={() => setVerificationResult(null)}
              style={{ background: "transparent", border: "none", color: "#cbd5e1", cursor: "pointer", fontSize: "14px" }}
            >
              ✕
            </button>
          </div>
          <div style={{ marginTop: "6px", color: "var(--text-secondary)", lineHeight: "1.4" }}>
            Recipient: <strong>{verificationResult.recipient_id}</strong> | Normalized Correlation:{" "}
            <strong style={{ color: "#ffffff" }}>{verificationResult.correlation}</strong> (Threshold: &gt; 0.08) | Evaluated Mid-Frequency Coefficients:{" "}
            <strong>{verificationResult.total_coefficients_evaluated?.toLocaleString()}</strong>
          </div>
        </div>
      )}

      {/* MAIN CANVAS VIEWER CONTAINER (Zero flexbox overflow bugs, centered inline-block, dedicated top padding) */}
      <div
        ref={scrollContainerRef}
        style={{
          width: "100%",
          height: "640px",
          maxHeight: "75vh",
          overflowY: "auto",
          overflowX: "auto",
          padding: "24px 20px 36px 20px",
          background: "#07090e",
          position: "relative",
          textAlign: "center",
          boxSizing: "border-box",
        }}
      >
        {/* PRIVACY SHIELD: TRIGGERS ON WINDOW BLUR / WHATSAPP SWITCH / SNIPPING TOOL */}
        {isWindowBlurred && (
          <div
            style={{
              position: "absolute",
              top: 0,
              left: 0,
              right: 0,
              bottom: 0,
              background: "#000000",
              zIndex: 50,
              display: "flex",
              flexDirection: "column",
              justifyContent: "center",
              alignItems: "center",
              color: "#ffffff",
              textAlign: "center",
              padding: "20px",
            }}
          >
            <div style={{ fontSize: "42px", marginBottom: "12px" }}>🛡️</div>
            <div style={{ fontSize: "17px", fontWeight: "800", color: "#f87171", letterSpacing: "1px" }}>
              ENCLAVE DEFENSE: WINDOW DEFOCUSED / TOTAL BLACKOUT
            </div>
            <div style={{ fontSize: "12.5px", color: "var(--text-secondary)", marginTop: "8px", maxWidth: "480px", lineHeight: "1.5" }}>
              Document canvas is 100% blacked out because window focus was lost (WhatsApp call, screen share, Snipping Tool, or external application detected).
            </div>
            <div
              style={{
                fontSize: "11px",
                color: "#94a3b8",
                marginTop: "16px",
                background: "rgba(255,255,255,0.06)",
                border: "1px solid rgba(255,255,255,0.12)",
                padding: "6px 16px",
                borderRadius: "6px",
              }}
            >
              Click anywhere in this window to resume viewing
            </div>
          </div>
        )}

        {/* PRINTSCREEN MOMENTARY BLACKOUT SHIELD */}
        {canvasBlackout && (
          <div
            style={{
              position: "absolute",
              top: 0,
              left: 0,
              right: 0,
              bottom: 0,
              background: "#000000",
              zIndex: 60,
              display: "flex",
              flexDirection: "column",
              justifyContent: "center",
              alignItems: "center",
              color: "#f87171",
              fontWeight: "800",
              fontSize: "15px",
            }}
          >
            <div style={{ fontSize: "36px", marginBottom: "10px" }}>⚠️</div>
            <div>SCREEN CAPTURE INTERCEPTED — CLIPBOARD FLUSHED</div>
            <div style={{ fontSize: "12px", color: "var(--text-muted)", marginTop: "4px" }}>
              Incident logged against officer {recipientId}
            </div>
          </div>
        )}

        {loading ? (
          <div style={{ textAlign: "center", padding: "80px 20px" }}>
            <div style={{ fontSize: "32px", marginBottom: "14px" }}>⚙️</div>
            <div style={{ fontSize: "14px", fontWeight: "700", color: "#ffffff" }}>
              Rasterizing Page {pageIndex + 1} &amp; Injecting 2D DCT Watermark...
            </div>
            <div style={{ fontSize: "12px", color: "var(--text-muted)", marginTop: "4px" }}>
              Applying mid-frequency spread-spectrum transformation server-side
            </div>
          </div>
        ) : errorMessage ? (
          <div style={{ textAlign: "center", padding: "60px 20px", color: "#f87171" }}>
            <div style={{ fontSize: "32px", marginBottom: "10px" }}>⚠️</div>
            <div style={{ fontSize: "14px", fontWeight: "700" }}>Rasterization Error</div>
            <div style={{ fontSize: "12px", color: "var(--text-secondary)", marginTop: "4px" }}>
              {errorMessage}
            </div>
            <button
              onClick={() => fetchPage(pageIndex)}
              style={{
                marginTop: "16px",
                background: "rgba(255, 255, 255, 0.1)",
                border: "1px solid rgba(255, 255, 255, 0.2)",
                borderRadius: "6px",
                padding: "6px 14px",
                color: "#ffffff",
                fontSize: "12px",
                cursor: "pointer",
              }}
            >
              Retry Loading
            </button>
          </div>
        ) : (
          <div
            style={{
              display: "inline-block",
              margin: "0 auto",
              verticalAlign: "top",
              boxShadow: "0 14px 44px rgba(0, 0, 0, 0.9), 0 0 0 1px rgba(255, 255, 255, 0.1)",
              borderRadius: "4px",
              background: "#000000",
              lineHeight: 0,
              position: "relative",
              overflow: "hidden",
              transition: "width 0.15s ease-out, height 0.15s ease-out",
            }}
          >
            {/* HTML5 CANVAS: ZERO SELECTABLE TEXT SPANS OR PDF.JS DOM TEXT LAYERS */}
            <canvas
              ref={canvasRef}
              style={{
                display: "block",
                width: `${displayDims.width}px`,
                height: `${displayDims.height}px`,
                pointerEvents: "none",
                borderRadius: "4px",
              }}
            />
          </div>
        )}
      </div>

      {/* BOTTOM CONTROL & PAGINATION STRIP */}
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          padding: "10px 18px",
          background: "rgba(255, 255, 255, 0.03)",
          borderTop: "1px solid rgba(255, 255, 255, 0.08)",
          flexWrap: "wrap",
          gap: "10px",
        }}
      >
        {/* Pagination */}
        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          <button
            onClick={() => setPageIndex((p) => Math.max(0, p - 1))}
            disabled={pageIndex <= 0 || loading}
            style={{
              background: "rgba(255, 255, 255, 0.06)",
              border: "1px solid rgba(255, 255, 255, 0.15)",
              borderRadius: "6px",
              padding: "5px 12px",
              color: pageIndex <= 0 ? "rgba(255,255,255,0.2)" : "#ffffff",
              fontSize: "12px",
              cursor: pageIndex <= 0 ? "not-allowed" : "pointer",
            }}
          >
            ◀ Prev Page
          </button>

          <span style={{ fontSize: "12px", color: "var(--text-secondary)", fontWeight: "600" }}>
            Page {pageIndex + 1} of {totalPages}
          </span>

          <button
            onClick={() => setPageIndex((p) => Math.min(totalPages - 1, p + 1))}
            disabled={pageIndex >= totalPages - 1 || loading}
            style={{
              background: "rgba(255, 255, 255, 0.06)",
              border: "1px solid rgba(255, 255, 255, 0.15)",
              borderRadius: "6px",
              padding: "5px 12px",
              color: pageIndex >= totalPages - 1 ? "rgba(255,255,255,0.2)" : "#ffffff",
              fontSize: "12px",
              cursor: pageIndex >= totalPages - 1 ? "not-allowed" : "pointer",
            }}
          >
            Next Page ▶
          </button>
        </div>

        {/* View Mode & Zoom Controls */}
        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          {/* Whole Page Mode Button */}
          <button
            onClick={() => {
              setViewMode("fit-page");
              setZoomFactor(1.0);
            }}
            style={{
              background: viewMode === "fit-page" ? "rgba(59, 130, 246, 0.25)" : "rgba(255, 255, 255, 0.05)",
              border: viewMode === "fit-page" ? "1px solid #3b82f6" : "1px solid rgba(255, 255, 255, 0.12)",
              borderRadius: "5px",
              padding: "4px 10px",
              color: viewMode === "fit-page" ? "#93c5fd" : "#cbd5e1",
              fontSize: "11.5px",
              fontWeight: "600",
              cursor: "pointer",
            }}
            title="Display entire page neatly in full without scrolling"
          >
            📄 Fit Whole Page
          </button>

          {/* Fit Width Button */}
          <button
            onClick={() => {
              setViewMode("fit-width");
              setZoomFactor(1.45);
            }}
            style={{
              background: viewMode === "fit-width" ? "rgba(59, 130, 246, 0.25)" : "rgba(255, 255, 255, 0.05)",
              border: viewMode === "fit-width" ? "1px solid #3b82f6" : "1px solid rgba(255, 255, 255, 0.12)",
              borderRadius: "5px",
              padding: "4px 10px",
              color: viewMode === "fit-width" ? "#93c5fd" : "#cbd5e1",
              fontSize: "11.5px",
              fontWeight: "600",
              cursor: "pointer",
            }}
            title="Expand to readable width with vertical scrolling"
          >
            ↔️ Fit Width
          </button>

          {/* Step Zoom Out */}
          <button
            onClick={() => {
              setViewMode("custom");
              setZoomFactor((z) => Math.max(0.5, +(z - 0.15).toFixed(2)));
            }}
            style={{
              background: "rgba(255, 255, 255, 0.05)",
              border: "1px solid rgba(255, 255, 255, 0.12)",
              borderRadius: "4px",
              padding: "3px 8px",
              color: "#ffffff",
              fontSize: "12px",
              cursor: "pointer",
            }}
            title="Zoom Out"
          >
            −
          </button>

          <span style={{ fontSize: "11px", color: "var(--text-muted)", minWidth: "48px", textAlign: "center" }}>
            {viewMode === "fit-page"
              ? "Whole Page"
              : viewMode === "fit-width"
              ? "Fit Width"
              : `${Math.round(zoomFactor * 100)}%`}
          </span>

          {/* Step Zoom In */}
          <button
            onClick={() => {
              setViewMode("custom");
              setZoomFactor((z) => Math.min(2.5, +(z + 0.15).toFixed(2)));
            }}
            style={{
              background: "rgba(255, 255, 255, 0.05)",
              border: "1px solid rgba(255, 255, 255, 0.12)",
              borderRadius: "4px",
              padding: "3px 8px",
              color: "#ffffff",
              fontSize: "12px",
              cursor: "pointer",
            }}
            title="Zoom In"
          >
            +
          </button>
        </div>

        {/* Technical Specs Callout */}
        {pageData?.metadata && (
          <div style={{ fontSize: "11px", color: "var(--text-muted)" }}>
            PSNR: <strong style={{ color: "#ffffff" }}>{pageData.metadata.psnr_db} dB</strong> | Blocks:{" "}
            {pageData.metadata.blocks_modulated?.toLocaleString()} | Mid-Band: {pageData.metadata.mid_freq_band}
          </div>
        )}
      </div>
    </div>
  );
}
