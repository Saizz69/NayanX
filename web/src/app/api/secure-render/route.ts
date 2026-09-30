import { NextRequest, NextResponse } from "next/server";

const BACKEND_URL = process.env.CRYPTO_SERVICE_URL || "http://127.0.0.1:8000";

/**
 * Server-Side Secure Document Rasterization API Route.
 *
 * CRITICAL SECURITY INVARIANT:
 * - This route intercepts incoming file requests.
 * - It NEVER streams raw PDF, DOCX, or text source bytes to the client.
 * - Converts target pages into raster image buffers server-side and injects
 *   mid-frequency 2D DCT spread-spectrum watermarks derived from recipient seed_r.
 * - Returns strictly the watermarked image data for canvas rendering.
 */
export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const {
      recipient_id,
      document_hash,
      document_id,
      pdf_base64,
      page_index = 0,
      dpi_scale = 2.0,
      alpha = 3.5,
    } = body;

    if (!recipient_id) {
      return NextResponse.json(
        { error: "recipient_id is required for secure rasterization." },
        { status: 400 }
      );
    }

    // Forward request to backend server-side rasterization pipeline
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

    const backendRes = await fetch(`${BACKEND_URL}/documents/secure-render-page`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        recipient_id,
        document_hash,
        document_id,
        pdf_base64,
        page_index,
        dpi_scale,
        alpha,
      }),
    });

    if (!backendRes.ok) {
      const errText = await backendRes.text();
      return NextResponse.json(
        { error: `Rasterization service error: ${errText}` },
        { status: backendRes.status }
      );
    }

    const payload = await backendRes.json();

    // Enforce that raw PDF is never transmitted in this response
    delete (payload as any).raw_pdf;
    delete (payload as any).pdf_bytes;

    return NextResponse.json(payload, {
      status: 200,
      headers: {
        "Cache-Control": "no-store, no-cache, must-revalidate, proxy-revalidate",
        "Pragma": "no-cache",
        "Expires": "0",
        "X-Content-Type-Options": "nosniff",
      },
    });
  } catch (error: any) {
    console.error("Secure render pipeline error:", error);
    return NextResponse.json(
      { error: `Internal rasterization pipeline error: ${error.message || error}` },
      { status: 500 }
    );
  }
}
