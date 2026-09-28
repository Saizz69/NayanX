import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "NayanX Forensic — Post-Quantum Document Attribution System",
  description: "Air-gapped post-quantum document provenance and leak attribution protocol powered by ML-KEM-768, ML-DSA-65, AES-256-GCM, and hash-chained Merkle ledger.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link
          href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap"
          rel="stylesheet"
        />
      </head>
      <body suppressHydrationWarning>{children}</body>
    </html>
  );
}
