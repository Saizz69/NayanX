import { NextRequest, NextResponse } from "next/server";
import { login } from "@/lib/auth";

export async function POST(req: NextRequest) {
  try {
    const body = await req.json().catch(() => ({}));
    const { username, password } = body;

    if (!username || !password) {
      return NextResponse.json(
        { error: "Username and password are required." },
        { status: 400 }
      );
    }

    const result = await login(username.trim(), password);

    if (!result.success) {
      return NextResponse.json(
        { error: result.error || "Authentication failed." },
        { status: result.status || 401 }
      );
    }

    // STRICT CONSTRAINT: Session token must NEVER be sent in response body
    return NextResponse.json({
      success: true,
      user: {
        id: result.user?.id,
        username: result.user?.username,
        role: result.user?.role,
        recipient_id: result.user?.recipient_id,
        name: result.user?.name,
      },
    });
  } catch (error: any) {
    console.error("API Auth Login error:", error);
    return NextResponse.json(
      { error: error.message || "Internal server error during authentication." },
      { status: 500 }
    );
  }
}
