import { cookies } from "next/headers";

const BACKEND_URL = process.env.CRYPTO_SERVICE_URL || "http://127.0.0.1:8000";

export interface UserSession {
  id: string;
  username: string;
  role: "head" | "recipient";
  recipient_id: string | null;
  name?: string | null;
  created_at?: string;
}

export interface LoginResult {
  success: boolean;
  user?: UserSession;
  error?: string;
  status?: number;
}

/**
 * Server-only helper to authenticate user credentials with crypto-service FastAPI.
 * On success, sets an opaque random 256-bit session token as an httpOnly, Secure,
 * SameSite=Strict cookie.
 * 
 * STRICT SECURITY CONSTRAINTS:
 * - Session tokens are NEVER exposed to client-side JavaScript.
 * - No claims or JWT payloads are issued or accepted.
 */
export async function login(username: string, password: string): Promise<LoginResult> {
  try {
    const res = await fetch(`${BACKEND_URL}/auth/login`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ username, password }),
      cache: "no-store",
    });

    const data = await res.json().catch(() => ({}));

    if (!res.ok) {
      return {
        success: false,
        error: data.detail || `Authentication failed (${res.status})`,
        status: res.status,
      };
    }

    const token = data.token;
    const role = data.role;
    if (!token || !role) {
      return {
        success: false,
        error: "Malformed authentication response from crypto-service.",
        status: 500,
      };
    }

    const user: UserSession = {
      id: data.id || data.username,
      username: data.username,
      role: data.role,
      recipient_id: data.recipient_id || null,
      name: data.name || data.username,
    };

    // Set opaque session token as httpOnly, Secure, SameSite=Strict cookie
    const cookieStore = await cookies();
    cookieStore.set("session_token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      path: "/",
      maxAge: 60 * 60 * 24, // 24 hours
    });

    return {
      success: true,
      user,
    };
  } catch (err: any) {
    console.error("Login server helper error:", err);
    return {
      success: false,
      error: err.message || "Failed to reach backend authentication service.",
      status: 503,
    };
  }
}

/**
 * Server-only helper to terminate session.
 * Deletes the server-side session row in SQLite and clears the cookie.
 */
export async function logout(): Promise<{ success: boolean }> {
  try {
    const cookieStore = await cookies();
    const token = cookieStore.get("session_token")?.value;

    if (token) {
      // Notify crypto-service to purge session from database
      await fetch(`${BACKEND_URL}/auth/logout`, {
        method: "POST",
        headers: {
          "X-Session-Token": token,
          "Cookie": `session_token=${token}`,
        },
        cache: "no-store",
      }).catch((e) => console.warn("Failed to notify backend of logout:", e));
    }

    // Purge cookie in all cases
    cookieStore.delete("session_token");
    return { success: true };
  } catch (err) {
    console.error("Logout error:", err);
    try {
      const cookieStore = await cookies();
      cookieStore.delete("session_token");
    } catch {}
    return { success: true };
  }
}

/**
 * Server-only helper to validate the current session against crypto-service DB.
 * Returns null if token is missing, expired, or invalid.
 */
export async function getSessionUser(): Promise<UserSession | null> {
  try {
    const cookieStore = await cookies();
    const token = cookieStore.get("session_token")?.value;
    if (!token) return null;

    const res = await fetch(`${BACKEND_URL}/auth/me`, {
      method: "GET",
      headers: {
        "X-Session-Token": token,
        "Cookie": `session_token=${token}`,
      },
      cache: "no-store",
    });

    if (!res.ok) {
      return null;
    }

    const data = await res.json();
    return data.user || (data.role ? data : null);
  } catch (err) {
    console.error("Failed to verify session user:", err);
    return null;
  }
}

/**
 * Server-only helper to retrieve raw session token for server-side proxying.
 */
export async function getSessionToken(): Promise<string | null> {
  const cookieStore = await cookies();
  return cookieStore.get("session_token")?.value || null;
}
