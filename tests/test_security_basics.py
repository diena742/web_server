import hashlib
import os
import unittest
from unittest.mock import patch

import app as dashboard
from werkzeug.security import check_password_hash


class PasswordHashTests(unittest.TestCase):
    def test_pbkdf2_hash_round_trip(self):
        encoded = dashboard.create_password_hash("a long test password")
        self.assertTrue(encoded.startswith("pbkdf2:"))
        self.assertTrue(check_password_hash(encoded, "a long test password"))
        self.assertTrue(dashboard.verify_password_hash("a long test password", encoded))
        self.assertFalse(dashboard.verify_password_hash("wrong password", encoded))

    def test_legacy_sha256_hash_is_supported_for_migration(self):
        legacy = hashlib.sha256(b"legacy password").hexdigest()
        self.assertTrue(dashboard.verify_password_hash("legacy password", legacy))
        self.assertFalse(dashboard.verify_password_hash("incorrect", legacy))
        self.assertTrue(dashboard.is_legacy_password_hash(legacy))

    def test_modern_hash_is_not_classified_as_legacy(self):
        encoded = dashboard.create_password_hash("another password")
        self.assertFalse(dashboard.is_legacy_password_hash(encoded))


class AuthenticationGuardTests(unittest.TestCase):
    def setUp(self):
        dashboard.app.testing = True
        self.client = dashboard.app.test_client()

    def test_initial_default_password_must_use_setup_wizard(self):
        default_hash = hashlib.sha256(b"admin").hexdigest()
        config = {
            "username": "admin",
            "password_hash": default_hash,
            "users": [],
            "max_login_attempts": 5,
            "lockout_duration": 300,
        }
        with patch.object(dashboard, "load_security_config", return_value=config):
            response = self.client.post(
                "/api/auth/login",
                json={"username": "admin", "password": "admin"},
            )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.get_json()["error"], "Initial setup required")

    def test_file_content_api_rejects_unauthenticated_request(self):
        response = self.client.get(
            "/api/files/content?path=/etc/passwd",
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(response.status_code, 401)

    def test_lxd_mutation_rejects_unauthenticated_request(self):
        response = self.client.post(
            "/api/lxd/action",
            json={"name": "test-container", "action": "stop"},
        )
        self.assertEqual(response.status_code, 401)

    def test_mobile_backup_mutation_requires_session_or_configured_token(self):
        with patch.dict(os.environ, {"MOBILE_ACCESS_TOKEN": ""}):
            response = self.client.post(
                "/api/mobile-backup/delete",
                json={"path": "/tmp/not-a-real-backup-file"},
            )
        self.assertEqual(response.status_code, 401)

    def test_terminal_socket_event_rejects_anonymous_client(self):
        flask_client = dashboard.app.test_client()
        socket_client = dashboard.socketio.test_client(
            dashboard.app, flask_test_client=flask_client
        )
        try:
            socket_client.emit("start_terminal", {"session_id": "test-session"})
            events = socket_client.get_received()
            self.assertTrue(any(event["name"] == "terminal_error" for event in events))
            self.assertFalse(any(event["name"] == "terminal_started" for event in events))
        finally:
            socket_client.disconnect()

    def test_unlisted_cross_origin_is_not_granted_cors_access(self):
        response = self.client.get(
            "/api/mobile-backup/ping",
            headers={"Origin": "https://untrusted.example"},
        )
        self.assertNotIn("Access-Control-Allow-Origin", response.headers)


if __name__ == "__main__":
    unittest.main()
