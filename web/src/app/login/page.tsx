"use client";

import React, { useState } from "react";
import { useRouter } from "next/navigation";

export default function LoginPage() {
  const router = useRouter();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [rememberMe, setRememberMe] = useState(true);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!username.trim() || !password) {
      setError("Please enter both username and password.");
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username: username.trim(),
          password,
        }),
      });

      const data = await res.json().catch(() => ({}));

      if (!res.ok) {
        throw new Error(data.error || `Login failed (Status: ${res.status})`);
      }

      const role = data.user?.role;
      if (role === "head") {
        router.push("/head");
      } else if (role === "recipient") {
        router.push("/recipient");
      } else {
        router.push("/");
      }
    } catch (err: any) {
      setError(err.message || "Authentication failed. Please verify credentials.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      style={{
        minHeight: "100vh",
        width: "100%",
        display: "flex",
        flexDirection: "column",
        justifyContent: "space-between",
        alignItems: "center",
        background: "linear-gradient(180deg, #050608 0%, #15171b 45%, #181a1f 55%, #07080a 100%)",
        color: "#ffffff",
        fontFamily: "'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
        padding: "24px 16px",
        boxSizing: "border-box",
        position: "relative",
      }}
    >
      {/* Top Header Bar */}
      <header
        style={{
          width: "100%",
          maxWidth: "760px",
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          fontSize: "11px",
          letterSpacing: "2px",
          textTransform: "uppercase",
          color: "rgba(255, 255, 255, 0.4)",
          fontFamily: "monospace",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          <span
            style={{
              width: "6px",
              height: "6px",
              borderRadius: "50%",
              background: "#10b981",
              display: "inline-block",
            }}
          />
          <span>WEBEYE ENCLAVE</span>
        </div>
        <span>FIPS 203 / 204 PQC</span>
      </header>

      {/* Main Center Login Container (Exact Match to User Reference Image) */}
      <main
        style={{
          width: "100%",
          maxWidth: "380px",
          margin: "auto 0",
          display: "flex",
          flexDirection: "column",
        }}
      >
        {/* Heading */}
        <h1
          style={{
            fontSize: "28px",
            fontWeight: 300,
            letterSpacing: "4px",
            color: "#ffffff",
            textAlign: "center",
            marginBottom: "44px",
            textTransform: "none",
          }}
        >
          Member Login
        </h1>

        {/* Error Alert */}
        {error && (
          <div
            style={{
              marginBottom: "24px",
              padding: "12px 14px",
              borderRadius: "6px",
              background: "rgba(239, 68, 68, 0.15)",
              border: "1px solid rgba(239, 68, 68, 0.4)",
              color: "#fca5a5",
              fontSize: "12px",
              lineHeight: "1.4",
              fontFamily: "monospace",
            }}
          >
            {error}
          </div>
        )}

        {/* Credentials Form */}
        <form onSubmit={handleLogin} style={{ width: "100%" }}>
          {/* Username / Email Field */}
          <div
            style={{
              display: "flex",
              alignItems: "center",
              borderBottom: "1px solid rgba(255, 255, 255, 0.3)",
              paddingBottom: "10px",
              marginBottom: "32px",
              transition: "border-color 0.2s ease",
            }}
          >
            {/* Explicitly sized SVG icon (18px x 18px) */}
            <svg
              width="18"
              height="18"
              viewBox="0 0 24 24"
              fill="none"
              stroke="rgba(255, 255, 255, 0.55)"
              strokeWidth="1.6"
              strokeLinecap="round"
              strokeLinejoin="round"
              style={{
                width: "18px",
                height: "18px",
                minWidth: "18px",
                maxWidth: "18px",
                marginRight: "14px",
                flexShrink: 0,
                display: "block",
              }}
            >
              <rect x="2" y="4" width="20" height="16" rx="2" />
              <path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7" />
            </svg>
            <input
              id="login-username"
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="Email ID"
              required
              style={{
                width: "100%",
                background: "transparent",
                border: "none",
                outline: "none",
                color: "#ffffff",
                fontSize: "15px",
                fontWeight: 300,
                letterSpacing: "0.5px",
                fontFamily: "inherit",
              }}
            />
          </div>

          {/* Password Field */}
          <div
            style={{
              display: "flex",
              alignItems: "center",
              borderBottom: "1px solid rgba(255, 255, 255, 0.3)",
              paddingBottom: "10px",
              marginBottom: "26px",
              transition: "border-color 0.2s ease",
            }}
          >
            {/* Explicitly sized SVG icon (18px x 18px) */}
            <svg
              width="18"
              height="18"
              viewBox="0 0 24 24"
              fill="none"
              stroke="rgba(255, 255, 255, 0.55)"
              strokeWidth="1.6"
              strokeLinecap="round"
              strokeLinejoin="round"
              style={{
                width: "18px",
                height: "18px",
                minWidth: "18px",
                maxWidth: "18px",
                marginRight: "14px",
                flexShrink: 0,
                display: "block",
              }}
            >
              <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
              <path d="M7 11V7a5 5 0 0 1 10 0v4" />
            </svg>
            <input
              id="login-password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Password"
              required
              style={{
                width: "100%",
                background: "transparent",
                border: "none",
                outline: "none",
                color: "#ffffff",
                fontSize: "15px",
                fontWeight: 300,
                letterSpacing: "0.5px",
                fontFamily: "inherit",
              }}
            />
          </div>

          {/* Options Row: Remember Me & Forgot Password */}
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              fontSize: "12.5px",
              color: "rgba(255, 255, 255, 0.55)",
              fontWeight: 300,
              marginBottom: "36px",
            }}
          >
            <label
              style={{
                display: "flex",
                alignItems: "center",
                gap: "8px",
                cursor: "pointer",
              }}
            >
              <input
                type="checkbox"
                checked={rememberMe}
                onChange={(e) => setRememberMe(e.target.checked)}
                style={{
                  width: "14px",
                  height: "14px",
                  accentColor: "#ffffff",
                  cursor: "pointer",
                }}
              />
              <span>Remember me</span>
            </label>

            <span
              onClick={() => fillQuick("head", "123456")}
              style={{
                fontStyle: "italic",
                cursor: "pointer",
                color: "rgba(255, 255, 255, 0.55)",
                transition: "color 0.2s",
              }}
              onMouseEnter={(e) => (e.currentTarget.style.color = "#ffffff")}
              onMouseLeave={(e) => (e.currentTarget.style.color = "rgba(255, 255, 255, 0.55)")}
            >
              Forgot Password?
            </span>
          </div>

          {/* Rectangular Bordered Button (Exact match to reference image) */}
          <button
            id="login-submit-btn"
            type="submit"
            disabled={loading}
            style={{
              width: "100%",
              height: "46px",
              background: "transparent",
              border: "1px solid rgba(255, 255, 255, 0.45)",
              color: "#ffffff",
              fontSize: "13px",
              fontWeight: 600,
              letterSpacing: "3px",
              textTransform: "uppercase",
              cursor: loading ? "not-allowed" : "pointer",
              transition: "all 0.25s ease",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              boxSizing: "border-box",
            }}
            onMouseEnter={(e) => {
              if (!loading) {
                e.currentTarget.style.background = "#ffffff";
                e.currentTarget.style.color = "#000000";
                e.currentTarget.style.borderColor = "#ffffff";
              }
            }}
            onMouseLeave={(e) => {
              if (!loading) {
                e.currentTarget.style.background = "transparent";
                e.currentTarget.style.color = "#ffffff";
                e.currentTarget.style.borderColor = "rgba(255, 255, 255, 0.45)";
              }
            }}
          >
            {loading ? "VERIFYING..." : "LOGIN"}
          </button>
        </form>
      </main>

      {/* Bottom Footer */}
      <footer
        style={{
          width: "100%",
          maxWidth: "760px",
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          fontSize: "10.5px",
          color: "rgba(255, 255, 255, 0.25)",
          fontFamily: "monospace",
        }}
      >
        <span>WEBEYE POST-QUANTUM FORENSIC ATTRIBUTION</span>
        <span>ZERO-TRUST ENCLAVE</span>
      </footer>
    </div>
  );
}
