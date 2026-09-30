import { NextRequest, NextResponse } from "next/server";

const BACKEND_URL = process.env.CRYPTO_SERVICE_URL || "http://127.0.0.1:8000";

/**
 * API Route: Security Violation Reporting & Recipient Flagging
 * 
 * Logs unauthorized screenshot attempts, Snipping Tool detections, PrintScreen
 * key captures, and document exfiltration violations to the tamper-evident audit ledger.
 */
export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const {
      recipient_id,
      violation_type = "SCREENSHOT_ATTEMPT",
      reason = "Unauthorized screen capture attempt intercepted by enclave guard",
      details,
      action = "flag",
    } = body;

    if (!recipient_id) {
      return NextResponse.json(
        { error: "recipient_id is required to log security incident." },
        { status: 400 }
      );
    }

    const endpoint =
      action === "unflag"
        ? `${BACKEND_URL}/recipients/${encodeURIComponent(recipient_id)}/unflag`
        : `${BACKEND_URL}/recipients/${encodeURIComponent(recipient_id)}/flag`;

    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };
    const incomingCookie = req.headers.get("cookie");
    if (incomingCookie) {
      headers["Cookie"] = incomingCookie;
    }
    const authHeader = req.headers.get("authorization");
    if (authHeader) {
      headers["Authorization"] = authHeader;
    }

    const backendRes = await fetch(endpoint, {
      method: "POST",
      headers,
      body: JSON.stringify({
        recipient_id,
        violation_type,
        reason,
        details,
      }),
    });

    if (!backendRes.ok) {
      const errText = await backendRes.text();
      return NextResponse.json(
        { error: `Backend security flagging error: ${errText}` },
        { status: backendRes.status }
      );
    }

    const data = await backendRes.json();
    return NextResponse.json(data);
  } catch (error: any) {
    console.error("Flag violation proxy error:", error);
    return NextResponse.json(
      { error: error.message || "Internal server error logging security incident." },
      { status: 500 }
    );
  }
}

export async function GET() {
  try {
    const backendRes = await fetch(`${BACKEND_URL}/recipients/flagged`, {
      cache: "no-store",
    });
    if (!backendRes.ok) {
      return NextResponse.json([]);
    }
    const data = await backendRes.json();
    return NextResponse.json(data);
  } catch (e: any) {
    return NextResponse.json([], { status: 200 });
  }
}
