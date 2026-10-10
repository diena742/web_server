import hashlib
import os
import tempfile
import time
import unittest
from urllib.parse import urlencode
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

    def test_first_run_setup_rejects_missing_setup_token(self):
        config = {
            "username": "admin",
            "password_hash": hashlib.sha256(b"admin").hexdigest(),
            "users": [],
            "require_auth": True,
        }
        with patch.dict(os.environ, {"SETUP_TOKEN": ""}), patch.object(
            dashboard, "load_security_config", return_value=config
        ):
            response = self.client.post(
                "/api/setup-admin",
                json={"username": "owner", "password": "long enough password"},
            )
        self.assertEqual(response.status_code, 503)

    def test_first_run_setup_rejects_incorrect_setup_token(self):
        config = {
            "username": "admin",
            "password_hash": hashlib.sha256(b"admin").hexdigest(),
            "users": [],
            "require_auth": True,
        }
        with patch.dict(os.environ, {"SETUP_TOKEN": "correct-one-time-token"}), patch.object(
            dashboard, "load_security_config", return_value=config
        ):
            response = self.client.post(
                "/api/setup-admin",
                json={
                    "setup_token": "wrong-token",
                    "username": "owner",
                    "password": "long enough password",
                },
            )
        self.assertEqual(response.status_code, 403)

    def test_first_run_setup_accepts_correct_token_and_hashes_password(self):
        config = {
            "username": "admin",
            "password_hash": hashlib.sha256(b"admin").hexdigest(),
            "users": [],
            "require_auth": True,
        }
        with patch.dict(os.environ, {"SETUP_TOKEN": "correct-one-time-token"}), patch.object(
            dashboard, "load_security_config", return_value=config
        ), patch.object(dashboard, "save_security_config") as save_config:
            response = self.client.post(
                "/api/setup-admin",
                json={
                    "setup_token": "correct-one-time-token",
                    "username": "new-owner",
                    "password": "a sufficiently long password",
                },
            )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(config["password_hash"].startswith("pbkdf2:"))
        self.assertTrue(
            dashboard.verify_password_hash(
                "a sufficiently long password", config["password_hash"]
            )
        )
        save_config.assert_called_once_with(config)

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


    def test_read_only_file_path_is_scoped_to_configured_roots(self):
        with tempfile.TemporaryDirectory() as allowed_root, tempfile.TemporaryDirectory() as outside_root:
            allowed_file = os.path.join(allowed_root, "safe.txt")
            outside_file = os.path.join(outside_root, "private.txt")
            with open(allowed_file, "w", encoding="utf-8") as handle:
                handle.write("shared data")
            with open(outside_file, "w", encoding="utf-8") as handle:
                handle.write("secret")
            with patch.dict(os.environ, {"FILES_READONLY_ROOTS": allowed_root}):
                self.assertTrue(dashboard.file_path_allowed_for_role(allowed_file, "readonly"))
                self.assertFalse(dashboard.file_path_allowed_for_role(outside_file, "readonly"))
                self.assertTrue(dashboard.file_path_allowed_for_role(outside_file, "admin"))

    def test_read_only_file_content_cannot_escape_configured_root(self):
        with tempfile.TemporaryDirectory() as allowed_root, tempfile.TemporaryDirectory() as outside_root:
            safe_file = os.path.join(allowed_root, "safe.txt")
            secret_file = os.path.join(outside_root, "secret.txt")
            with open(safe_file, "w", encoding="utf-8") as handle:
                handle.write("visible")
            with open(secret_file, "w", encoding="utf-8") as handle:
                handle.write("not visible")
            with patch.dict(os.environ, {"FILES_READONLY_ROOTS": allowed_root}):
                with self.client.session_transaction() as sess:
                    sess.update({"logged_in": True, "username": "viewer", "role": "readonly", "last_active": time.time()})
                allowed = self.client.get("/api/files/content?" + urlencode({"path": safe_file}))
                denied = self.client.get("/api/files/content?" + urlencode({"path": secret_file}))
            self.assertEqual(allowed.status_code, 200)
            self.assertEqual(allowed.get_json()["content"], "visible")
            self.assertEqual(denied.status_code, 403)

    def test_read_only_settings_response_redacts_integration_secrets(self):
        config = {
            "require_auth": True,
            "session_timeout": 3600,
        }
        settings = {
            "integrations": {
                "telegram_token": "bot-secret",
                "telegram_chat_id": "private-chat",
                "webhook_url": "https://example.test/?token=secret",
            },
            "mqtt": {"enabled": True, "password": "mqtt-secret", "host": "broker.local"},
        }
        with self.client.session_transaction() as sess:
            sess.update({"logged_in": True, "username": "viewer", "role": "readonly", "last_active": time.time()})
        with patch.object(dashboard, "load_security_config", return_value=config), patch.object(
            dashboard, "load_app_settings", return_value=settings.copy()
        ):
            response = self.client.get("/api/settings")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["integrations"]["telegram_token"], "")
        self.assertEqual(payload["integrations"]["telegram_chat_id"], "")
        self.assertEqual(payload["integrations"]["webhook_url"], "")
        self.assertEqual(payload["mqtt"]["password"], "")

    def test_read_only_role_cannot_access_docker_logs(self):
        config = {"require_auth": True, "session_timeout": 3600}
        with self.client.session_transaction() as sess:
            sess.update({"logged_in": True, "username": "viewer", "role": "readonly", "last_active": time.time()})
        with patch.object(dashboard, "load_security_config", return_value=config):
            response = self.client.get("/api/docker/example/logs")
        self.assertEqual(response.status_code, 403)

    def test_additional_user_can_change_only_own_password(self):
        owner_password = "owner current password"
        user_password = "viewer current password"
        config = {
            "username": "owner",
            "password_hash": dashboard.create_password_hash(owner_password),
            "require_auth": True,
            "session_timeout": 3600,
            "users": [{
                "username": "viewer",
                "role": "readonly",
                "password_hash": dashboard.create_password_hash(user_password),
            }],
        }
        new_password = "viewer new password 123"
        with self.client.session_transaction() as sess:
            sess.update({"logged_in": True, "username": "viewer", "role": "readonly", "last_active": time.time()})
        with patch.object(dashboard, "load_security_config", return_value=config), patch.object(
            dashboard, "save_security_config"
        ):
            response = self.client.post(
                "/api/security/change-password",
                json={"current_password": user_password, "new_password": new_password},
            )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(dashboard.verify_password_hash(new_password, config["users"][0]["password_hash"]))
        self.assertTrue(dashboard.verify_password_hash(owner_password, config["password_hash"]))




class ServiceControlAuthorizationTests(unittest.TestCase):
    def setUp(self):
        dashboard.app.testing = True
        self.client = dashboard.app.test_client()
        self.security_config = {
            "require_auth": True,
            "session_timeout": 3600,
            "max_login_attempts": 5,
            "lockout_duration": 300,
        }

    def _login_as(self, role):
        with self.client.session_transaction() as sess:
            sess.update({
                "logged_in": True,
                "username": "test-user",
                "role": role,
                "login_time": time.time(),
                "last_active": time.time(),
            })

    def test_unlisted_service_is_rejected_without_host_command(self):
        self._login_as("admin")
        with patch.object(dashboard, "load_security_config", return_value=self.security_config), \
             patch.object(dashboard, "load_app_settings", return_value={"services": [{"id": "ssh"}]}), \
             patch.object(dashboard, "run_host_command") as run_command:
            response = self.client.post(
                "/api/services/control",
                json={"service": "unexpected-service", "action": "restart"},
            )
        self.assertEqual(response.status_code, 400)
        run_command.assert_not_called()

    def test_operator_cannot_stop_configured_service(self):
        self._login_as("operator")
        with patch.object(dashboard, "load_security_config", return_value=self.security_config), \
             patch.object(dashboard, "load_app_settings", return_value={"services": [{"id": "ssh"}]}), \
             patch.object(dashboard, "run_host_command") as run_command:
            response = self.client.post(
                "/api/services/control",
                json={"service": "ssh", "action": "stop"},
            )
        self.assertEqual(response.status_code, 403)
        run_command.assert_not_called()

    def test_operator_can_restart_configured_service(self):
        self._login_as("operator")
        completed = type("Completed", (), {"returncode": 0})()
        with patch.object(dashboard, "load_security_config", return_value=self.security_config), \
             patch.object(dashboard, "load_app_settings", return_value={"services": [{"id": "ssh"}]}), \
             patch.object(dashboard, "run_host_command", return_value=completed) as run_command, \
             patch.object(dashboard, "audit_log"):
            response = self.client.post(
                "/api/services/control",
                json={"service": "ssh", "action": "restart"},
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), {"success": True})
        run_command.assert_called_once_with(["systemctl", "restart", "ssh"])

    def test_failed_systemctl_command_is_not_reported_as_success(self):
        self._login_as("admin")
        completed = type("Completed", (), {"returncode": 1})()
        with patch.object(dashboard, "load_security_config", return_value=self.security_config), \
             patch.object(dashboard, "load_app_settings", return_value={"services": [{"id": "ssh"}]}), \
             patch.object(dashboard, "run_host_command", return_value=completed), \
             patch.object(dashboard, "audit_log"):
            response = self.client.post(
                "/api/services/control",
                json={"service": "ssh", "action": "restart"},
            )
        self.assertEqual(response.status_code, 502)
        self.assertNotEqual(response.get_json(), {"success": True})

if __name__ == "__main__":
    unittest.main()
