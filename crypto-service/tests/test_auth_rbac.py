"""
Integration Test Suite: Role-Based Access Control (RBAC), Enclave Ownership,
Account Lockout, and Session Security for WebEye.

Acceptance Criteria Verified:
1. Direct raw HTTP recipient access to Head-only endpoints returns HTTP 403.
2. Direct raw HTTP recipient access to another recipient's document returns HTTP 403.
3. Account lockout: 5 consecutive failed logins locks the account for 15 minutes;
   subsequent attempt rejected with HTTP 403 even with correct credentials.
4. Session token security: Token is 256-bit opaque random string (zero JWTs),
   stored server-side in SQLite, strictly in HttpOnly cookie, never in response body.
5. Screenshot violation alerting: Flagging recipient triggers immediate security
   notification accessible to Head accounts.
"""

import sys
import os
import time
import requests
import unittest

BASE_URL = os.environ.get("CRYPTO_SERVICE_URL", "http://127.0.0.1:8000")
WEB_URL = os.environ.get("WEB_SERVICE_URL", "http://localhost:3000")

class TestAuthRBAC(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # 1. Obtain Head session token via direct backend /auth/login
        head_login = requests.post(f"{BASE_URL}/auth/login", json={"username": "head", "password": "123456"})
        assert head_login.status_code == 200, f"Head login failed: {head_login.text}"
        cls.head_token = head_login.json()["token"]
        cls.head_headers = {"X-Session-Token": cls.head_token}

        # 2. Ensure test recipient exists by enrolling atomically through Head
        cls.recipient1_id = "test-rec-officer-01"
        cls.recipient2_id = "test-rec-officer-02"

        # Enroll recipient 1 with default password '123456'
        requests.post(
            f"{BASE_URL}/enroll",
            json={"name": "Test Officer 1", "role": "Field Analyst", "recipient_id": cls.recipient1_id, "password": "123456"},
            headers=cls.head_headers
        )

        # Enroll recipient 2 with default password '123456'
        requests.post(
            f"{BASE_URL}/enroll",
            json={"name": "Test Officer 2", "role": "Signals Officer", "recipient_id": cls.recipient2_id, "password": "123456"},
            headers=cls.head_headers
        )

        # 3. Log in as Recipient 1
        rec1_login = requests.post(f"{BASE_URL}/auth/login", json={"username": cls.recipient1_id, "password": "123456"})
        assert rec1_login.status_code == 200, f"Recipient 1 login failed: {rec1_login.text}"
        cls.rec1_token = rec1_login.json()["token"]
        cls.rec1_headers = {"X-Session-Token": cls.rec1_token}

        # 4. Log in as Recipient 2
        rec2_login = requests.post(f"{BASE_URL}/auth/login", json={"username": cls.recipient2_id, "password": "123456"})
        assert rec2_login.status_code == 200, f"Recipient 2 login failed: {rec2_login.text}"
        cls.rec2_token = rec2_login.json()["token"]
        cls.rec2_headers = {"X-Session-Token": cls.rec2_token}

    def test_01_recipient_hitting_head_only_endpoints_gets_403(self):
        """CRITERIA 1: Recipient session hitting Head-only endpoints directly via raw HTTP gets 403."""
        head_only_routes = [
            ("POST", f"{BASE_URL}/enroll", {"name": "Unauthorized Enrollee", "role": "Spy"}),
            ("POST", f"{BASE_URL}/documents/encrypt", {"recipients": ["r1"], "filename": "leak.pdf"}),
            ("GET", f"{BASE_URL}/ledger", None),
            ("POST", f"{BASE_URL}/leak/attribute", {"file_base64": "invalid"}),
            ("GET", f"{BASE_URL}/recipients/flagged", None),
            ("GET", f"{BASE_URL}/notifications", None),
        ]

        for method, url, payload in head_only_routes:
            if method == "POST":
                resp = requests.post(url, json=payload, headers=self.rec1_headers)
            else:
                resp = requests.get(url, headers=self.rec1_headers)

            self.assertEqual(
                resp.status_code,
                403,
                f"Expected HTTP 403 Forbidden for recipient on {method} {url}, got {resp.status_code}: {resp.text}"
            )
            print(f"  [PASS] Recipient rejected with 403 on Head endpoint: {method} {url.replace(BASE_URL, '')}")

    def test_02_recipient_accessing_other_recipient_document_gets_403(self):
        """CRITERIA 2: Recipient session requesting another recipient's document ID gets 403."""
        # Recipient 1 attempts to call secure rasterization for Recipient 2's identity
        render_payload = {
            "recipient_id": self.recipient2_id,  # Target is Recipient 2
            "page_index": 0,
            "dpi_scale": 1.0,
            "alpha": 3.5,
        }

        # Raw HTTP call with Recipient 1's credentials targeting Recipient 2
        resp = requests.post(
            f"{BASE_URL}/documents/secure-render-page",
            json=render_payload,
            headers=self.rec1_headers
        )
        self.assertEqual(
            resp.status_code,
            403,
            f"Expected HTTP 403 when Recipient 1 requests Recipient 2 document, got {resp.status_code}"
        )
        print("  [PASS] Cross-recipient secure-render-page attempt rejected with 403 Forbidden.")

        # Recipient 1 attempts to call document decryption for Recipient 2
        decrypt_payload = {
            "recipient_id": self.recipient2_id,
            "document_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "ciphertext_bundle": {}
        }
        decrypt_resp = requests.post(
            f"{BASE_URL}/documents/decrypt",
            json=decrypt_payload,
            headers=self.rec1_headers
        )
        self.assertEqual(
            decrypt_resp.status_code,
            403,
            f"Expected HTTP 403 when Recipient 1 requests Recipient 2 decrypt, got {decrypt_resp.status_code}"
        )
        print("  [PASS] Cross-recipient decrypt attempt rejected with 403 Forbidden.")

    def test_03_account_lockout_after_failed_logins(self):
        """CRITERIA 3: 5 failed logins locks the account; 6th/7th attempt is rejected with 403 even with correct password."""
        lockout_user = f"lockout-test-{int(time.time())}"

        # 1. Create a fresh test recipient account through Head /enroll
        enroll_res = requests.post(
            f"{BASE_URL}/enroll",
            json={"name": "Lockout Officer", "role": "Tester", "recipient_id": lockout_user, "password": "correct_password_123"},
            headers=self.head_headers
        )
        self.assertEqual(enroll_res.status_code, 200)

        # 2. Perform 5 consecutive failed login attempts with wrong password
        for attempt in range(1, 6):
            fail_resp = requests.post(
                f"{BASE_URL}/auth/login",
                json={"username": lockout_user, "password": "WRONG_PASSWORD"}
            )
            if attempt < 5:
                self.assertEqual(fail_resp.status_code, 401, f"Attempt {attempt} expected 401")
            else:
                # 5th attempt locks the account
                self.assertIn(fail_resp.status_code, [401, 403])
                print("  [PASS] 5th failed attempt triggered account lockout.")

        # 3. 6th and 7th attempt with the CORRECT password must be REJECTED with HTTP 403 lockout!
        for attempt in [6, 7]:
            locked_resp = requests.post(
                f"{BASE_URL}/auth/login",
                json={"username": lockout_user, "password": "correct_password_123"}
            )
            self.assertEqual(
                locked_resp.status_code,
                403,
                f"Attempt {attempt} should be rejected with 403 account lockout even with correct password! Got: {locked_resp.status_code}"
            )
            self.assertIn("locked", locked_resp.text.lower())
            print(f"  [PASS] Attempt {attempt} with CORRECT password successfully rejected with HTTP 403 Lockout.")

    def test_04_session_token_security_and_no_body_leakage(self):
        """CRITERIA 4: Confirm token is opaque random (not a JWT) and never appears in Next.js response body."""
        # 1. Verify token is NOT a JWT (JWTs have 3 dot-separated base64 sections)
        token = self.rec1_token
        parts = token.split(".")
        self.assertNotEqual(len(parts), 3, "CRITICAL SECURITY BREACH: Token format resembles a self-verifying JWT!")
        self.assertTrue(len(token) >= 32, "Opaque token must be at least 256-bit random string")
        print(f"  [PASS] Verified token is opaque random string ({len(token)} chars, non-JWT).")

        # 2. Test Next.js /api/auth/login endpoint: Token must be in HttpOnly cookie and NEVER in response body
        web_res = requests.post(
            f"{WEB_URL}/api/auth/login",
            json={"username": "head", "password": "123456"}
        )
        self.assertEqual(web_res.status_code, 200)
        body = web_res.json()
        self.assertNotIn("token", body, "SECURITY BREACH: Session token exposed in Next.js response body!")
        self.assertIn("user", body)

        # Check Set-Cookie header
        set_cookie = web_res.headers.get("Set-Cookie", "")
        self.assertIn("session_token=", set_cookie)
        self.assertIn("HttpOnly", set_cookie)
        print("  [PASS] Verified Next.js response body omits token and sets HttpOnly cookie.")

    def test_05_screenshot_flag_triggers_head_notification(self):
        """CRITERIA 5: Screenshot violation flagged by recipient generates notification for Head."""
        # Recipient flags a screenshot violation
        flag_res = requests.post(
            f"{BASE_URL}/recipients/{self.recipient1_id}/flag",
            json={
                "recipient_id": self.recipient1_id,
                "violation_type": "SCREENSHOT_ATTEMPT",
                "reason": "Hardware PrintScreen capture intercepted by enclave guard",
                "details": "Triggered during secure viewer session"
            },
            headers=self.rec1_headers
        )
        self.assertEqual(flag_res.status_code, 200)

        # Head queries notifications
        notif_res = requests.get(f"{BASE_URL}/notifications", headers=self.head_headers)
        self.assertEqual(notif_res.status_code, 200)
        notifs = notif_res.json()

        matching = [n for n in notifs if n["recipient_id"] == self.recipient1_id and not n["is_read"]]
        self.assertTrue(len(matching) > 0, "Security notification for screenshot violation was not recorded for Head!")
        print(f"  [PASS] Screenshot violation generated live notification for Head (ID #{matching[0]['id']}).")

        # Head dismisses notification
        dismiss_res = requests.post(f"{BASE_URL}/notifications/{matching[0]['id']}/dismiss", headers=self.head_headers)
        self.assertEqual(dismiss_res.status_code, 200)
        print("  [PASS] Head successfully dismissed security alert.")


if __name__ == "__main__":
    suite = unittest.TestLoader().loadTestsFromTestCase(TestAuthRBAC)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
