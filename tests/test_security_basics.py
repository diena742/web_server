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


class PrivilegedRouteAuthorizationTests(unittest.TestCase):
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

    def test_disabling_authentication_does_not_grant_admin_role(self):
        with patch.object(
            dashboard, "load_security_config",
            return_value={"require_auth": False, "session_timeout": 3600},
        ):
            response = self.client.post("/api/perform-update", json={})
        self.assertEqual(response.status_code, 403)

    def test_readonly_user_cannot_grant_casaos_access(self):
        self._login_as("readonly")
        with patch.object(dashboard, "load_security_config", return_value=self.security_config):
            response = self.client.post("/api/casaos/access", json={})
        self.assertEqual(response.status_code, 403)

    def test_readonly_user_cannot_access_mobile_backup_mutations(self):
        self._login_as("readonly")
        with patch.dict(os.environ, {"MOBILE_ACCESS_TOKEN": ""}), patch.object(
            dashboard, "load_security_config", return_value=self.security_config
        ):
            response = self.client.post(
                "/api/mobile-backup/delete",
                json={"path": "/tmp/not-a-real-backup-file"},
            )
        self.assertEqual(response.status_code, 403)

    def test_readonly_user_cannot_change_web_monitor_domain(self):
        self._login_as("readonly")
        with patch.object(dashboard, "load_security_config", return_value=self.security_config):
            response = self.client.post(
                "/api/web_monitor/config",
                json={"domain": "example.invalid"},
            )
        self.assertEqual(response.status_code, 403)

    def test_readonly_user_cannot_list_backups_or_reload_nginx(self):
        self._login_as("readonly")
        with patch.object(dashboard, "load_security_config", return_value=self.security_config):
            backup_response = self.client.get("/api/backup/list")
            nginx_response = self.client.post("/api/websites/reload_nginx", json={})
        self.assertEqual(backup_response.status_code, 403)
        self.assertEqual(nginx_response.status_code, 403)



class BackupRestoreTests(unittest.TestCase):
    def setUp(self):
        dashboard.app.testing = True
        self.client = dashboard.app.test_client()
        self.security_config = {
            "require_auth": True,
            "session_timeout": 3600,
            "max_login_attempts": 5,
            "lockout_duration": 300,
        }
        with self.client.session_transaction() as sess:
            sess.update({
                "logged_in": True,
                "username": "admin-user",
                "role": "admin",
                "login_time": time.time(),
                "last_active": time.time(),
            })

    def test_backup_includes_canonical_application_config_files(self):
        import tarfile
        with tempfile.TemporaryDirectory() as temporary:
            data_dir = os.path.join(temporary, "data")
            backup_dir = os.path.join(data_dir, "backups")
            base_dir = os.path.join(temporary, "base")
            os.makedirs(backup_dir)
            os.makedirs(base_dir)
            settings_path = os.path.join(data_dir, "app_settings.json")
            security_path = os.path.join(data_dir, "security_config.json")
            compose_path = os.path.join(base_dir, "docker-compose.yml")
            for path, body in (
                (settings_path, '{"general":{"server_name":"test"}}'),
                (security_path, '{"username":"owner"}'),
                (compose_path, 'services: {}'),
            ):
                with open(path, "w", encoding="utf-8") as handle:
                    handle.write(body)

            with patch.object(dashboard, "DATA_DIR", data_dir), \
                 patch.object(dashboard, "BASE_DIR", base_dir), \
                 patch.object(dashboard, "BACKUP_DIR", backup_dir), \
                 patch.object(dashboard, "APP_SETTINGS_FILE", settings_path), \
                 patch.object(dashboard, "SECURITY_CONFIG_FILE", security_path), \
                 patch.object(dashboard, "load_security_config", return_value=self.security_config), \
                 patch.object(dashboard, "audit_log"):
                response = self.client.post(
                    "/api/backup/create",
                    json={"name": "config-test", "include_config": True, "include_docker": True},
                )
                self.assertEqual(response.status_code, 200)
                filename = response.get_json()["filename"]
                with tarfile.open(os.path.join(backup_dir, filename), "r:gz") as archive:
                    names = set(archive.getnames())

            self.assertIn("app_settings.json", names)
            self.assertIn("security_config.json", names)
            self.assertIn("docker-compose.yml", names)
            self.assertNotIn("settings.json", names)

    def test_restore_writes_config_to_canonical_paths_and_ignores_symlinks(self):
        import io
        import tarfile
        with tempfile.TemporaryDirectory() as temporary:
            data_dir = os.path.join(temporary, "data")
            backup_dir = os.path.join(data_dir, "backups")
            base_dir = os.path.join(temporary, "base")
            os.makedirs(backup_dir)
            os.makedirs(base_dir)
            settings_path = os.path.join(data_dir, "app_settings.json")
            security_path = os.path.join(data_dir, "security_config.json")
            compose_path = os.path.join(base_dir, "docker-compose.yml")
            archive_path = os.path.join(backup_dir, "restore-test.tar.gz")

            with tarfile.open(archive_path, "w:gz") as archive:
                for name, body in (
                    ("app_settings.json", b'{"general":{"server_name":"restored"}}'),
                    ("security_config.json", b'{"username":"restored-owner"}'),
                    ("docker-compose.yml", b"services: {}"),
                ):
                    info = tarfile.TarInfo(name)
                    info.size = len(body)
                    archive.addfile(info, io.BytesIO(body))
                link = tarfile.TarInfo("untrusted-link")
                link.type = tarfile.SYMTYPE
                link.linkname = "../../outside.txt"
                archive.addfile(link)

            with patch.object(dashboard, "DATA_DIR", data_dir), \
                 patch.object(dashboard, "BASE_DIR", base_dir), \
                 patch.object(dashboard, "BACKUP_DIR", backup_dir), \
                 patch.object(dashboard, "APP_SETTINGS_FILE", settings_path), \
                 patch.object(dashboard, "SECURITY_CONFIG_FILE", security_path), \
                 patch.object(dashboard, "load_security_config", return_value=self.security_config), \
                 patch.object(dashboard, "audit_log"):
                response = self.client.post("/api/backup/restore", json={"id": "restore-test.tar.gz"})

            self.assertEqual(response.status_code, 200)
            with open(settings_path, encoding="utf-8") as handle:
                self.assertIn("restored", handle.read())
            with open(security_path, encoding="utf-8") as handle:
                self.assertIn("restored-owner", handle.read())
            with open(compose_path, encoding="utf-8") as handle:
                self.assertEqual(handle.read(), "services: {}")
            self.assertFalse(os.path.exists(os.path.join(temporary, "outside.txt")))
            self.assertEqual(os.stat(security_path).st_mode & 0o777, 0o600)


class BackupDownloadAuthorizationTests(unittest.TestCase):
    def test_readonly_user_cannot_download_backup_archives(self):
        dashboard.app.testing = True
        client = dashboard.app.test_client()
        with client.session_transaction() as sess:
            sess.update({
                "logged_in": True,
                "username": "viewer",
                "role": "readonly",
                "login_time": time.time(),
                "last_active": time.time(),
            })
        with patch.object(
            dashboard, "load_security_config",
            return_value={"require_auth": True, "session_timeout": 3600},
        ):
            response = client.get("/api/backup/download/backup-test.tar.gz")
        self.assertEqual(response.status_code, 403)



class HostCommandSafetyTests(unittest.TestCase):
    def setUp(self):
        dashboard.app.testing = True
        self.client = dashboard.app.test_client()
        self.security_config = {
            "require_auth": True,
            "session_timeout": 3600,
            "max_login_attempts": 5,
            "lockout_duration": 300,
        }
        with self.client.session_transaction() as sess:
            sess.update({
                "logged_in": True,
                "username": "owner",
                "role": "owner",
                "login_time": time.time(),
                "last_active": time.time(),
            })

    def test_update_command_quotes_working_directory_and_uses_argv(self):
        import docker
        container = type("Container", (), {
            "name": "eka_dashboard",
            "labels": {"com.docker.compose.project.working_dir": "/tmp/install ; touch /tmp/nope"},
        })()
        client = type("DockerClient", (), {
            "containers": type("Containers", (), {
                "list": lambda self: [container],
            })(),
        })()
        with patch.object(dashboard, "load_security_config", return_value=self.security_config), \
             patch.object(docker, "from_env", return_value=client), \
             patch.object(dashboard.subprocess, "Popen") as popen:
            response = self.client.post("/api/perform-update", json={})

        self.assertEqual(response.status_code, 200)
        args, kwargs = popen.call_args
        self.assertIsInstance(args[0], list)
        self.assertFalse(kwargs.get("shell", False))
        self.assertIn("cd '/tmp/install ; touch /tmp/nope' &&", args[0][-1])
        self.assertEqual(args[0][-3:], ["sh", "-c", args[0][-1]])

    def test_update_rejects_null_byte_in_working_directory(self):
        import docker
        container = type("Container", (), {
            "name": "eka_dashboard",
            "labels": {"com.docker.compose.project.working_dir": "/tmp/unsafe\x00path"},
        })()
        client = type("DockerClient", (), {
            "containers": type("Containers", (), {
                "list": lambda self: [container],
            })(),
        })()
        with patch.object(dashboard, "load_security_config", return_value=self.security_config), \
             patch.object(docker, "from_env", return_value=client), \
             patch.object(dashboard.subprocess, "Popen") as popen:
            response = self.client.post("/api/perform-update", json={})
        self.assertEqual(response.status_code, 400)
        popen.assert_not_called()

    def test_readonly_cannot_run_host_disk_analysis_commands(self):
        with self.client.session_transaction() as sess:
            sess.update({"role": "readonly", "username": "viewer"})
        with patch.object(dashboard, "load_security_config", return_value=self.security_config), \
             patch.object(dashboard.subprocess, "run") as run_command:
            disk_response = self.client.get("/api/disk-analysis")
            storage_response = self.client.get("/api/storage/analyze?path=/var/log")
        self.assertEqual(disk_response.status_code, 403)
        self.assertEqual(storage_response.status_code, 403)
        run_command.assert_not_called()



class PermissionHierarchyTests(unittest.TestCase):
    def test_limited_permission_includes_view_but_not_full_control(self):
        self.assertTrue(dashboard.has_permission("operator", "services", "view"))
        self.assertTrue(dashboard.has_permission("operator", "services", "limited"))
        self.assertFalse(dashboard.has_permission("operator", "services", "full"))

    def test_operator_can_view_configured_service_status(self):
        dashboard.app.testing = True
        client = dashboard.app.test_client()
        with client.session_transaction() as sess:
            sess.update({
                "logged_in": True,
                "username": "operator-user",
                "role": "operator",
                "login_time": time.time(),
                "last_active": time.time(),
            })
        config = {"require_auth": True, "session_timeout": 3600}
        result = type("CommandResult", (), {"stdout": "active\n", "returncode": 0})()
        with patch.object(dashboard, "load_security_config", return_value=config), \
             patch.object(dashboard, "load_app_settings", return_value={"services": [{"id": "ssh", "name": "SSH Server"}]}), \
             patch.object(dashboard, "run_host_command", return_value=result) as run_command:
            response = client.get("/api/services/status")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["services"][0]["status_text"], "Running")
        run_command.assert_called_once_with(["systemctl", "is-active", "ssh"])



class HostManagementReadAuthorizationTests(unittest.TestCase):
    def test_readonly_role_cannot_query_admin_host_management_apis(self):
        dashboard.app.testing = True
        client = dashboard.app.test_client()
        with client.session_transaction() as sess:
            sess.update({
                "logged_in": True,
                "username": "viewer",
                "role": "readonly",
                "login_time": time.time(),
                "last_active": time.time(),
            })
        config = {"require_auth": True, "session_timeout": 3600}
        protected_endpoints = [
            "/api/network/info",
            "/api/network-details",
            "/api/storage/disks",
            "/api/storage/info",
            "/api/smb/status",
            "/api/smb/shares",
            "/api/vpn/status",
            "/api/vpn/clients",
            "/api/vpn/client/example/config",
            "/api/store/catalog",
            "/api/store/installed",
            "/api/zerotier/status",
            "/api/vpn/scan",
            "/api/lxd/containers",
            "/api/websites/nginx_status",
            "/api/websites/threats",
            "/api/websites/threats/blocked_ips",
            "/api/web_monitor/config",
            "/api/web_monitor/status",
            "/api/web_monitor/ssl_details",
            "/api/web_monitor/traffic",
            "/api/web_monitor/bot_details",
            "/api/web_monitor/security",
            "/api/web_monitor/backup",
            "/api/webpanel/database",
        ]
        with patch.object(dashboard, "load_security_config", return_value=config), \
             patch.object(dashboard.subprocess, "run") as host_command:
            statuses = {
                path: client.get(path).status_code
                for path in protected_endpoints
            }
        self.assertEqual(statuses, {path: 403 for path in protected_endpoints})
        host_command.assert_not_called()



class WebShieldDomainValidationTests(unittest.TestCase):
    def test_domain_normalizer_accepts_hosts_and_rejects_paths(self):
        self.assertEqual(
            dashboard.normalize_web_shield_domain("HTTPS://Example.COM/"),
            "example.com",
        )
        self.assertEqual(
            dashboard.normalize_web_shield_domain("example.com."),
            "example.com",
        )
        for value in (
            "../etc/passwd",
            "example.com/path",
            "user@example.com",
            "example.com:443",
            "example.com?next=internal",
            "",
            None,
        ):
            with self.subTest(value=value):
                self.assertIsNone(dashboard.normalize_web_shield_domain(value))

    def test_web_monitor_config_rejects_path_traversal_domain(self):
        import tempfile
        dashboard.app.testing = True
        client = dashboard.app.test_client()
        with client.session_transaction() as sess:
            sess.update({
                "logged_in": True,
                "username": "admin-user",
                "role": "admin",
                "login_time": time.time(),
                "last_active": time.time(),
            })
        config = {"require_auth": True, "session_timeout": 3600}
        with tempfile.TemporaryDirectory() as data_dir, \
             patch.object(dashboard, "DATA_DIR", data_dir), \
             patch.object(dashboard, "load_security_config", return_value=config):
            response = client.post(
                "/api/web_monitor/config",
                json={"domain": "../../etc/passwd"},
            )
            self.assertEqual(response.status_code, 400)
            self.assertFalse(os.path.exists(os.path.join(data_dir, "web_shield.json")))

    def test_web_monitor_backup_rejects_path_outside_web_root(self):
        dashboard.app.testing = True
        client = dashboard.app.test_client()
        with client.session_transaction() as sess:
            sess.update({
                "logged_in": True,
                "username": "admin-user",
                "role": "admin",
                "login_time": time.time(),
                "last_active": time.time(),
            })
        config = {"require_auth": True, "session_timeout": 3600}
        with patch.object(dashboard, "load_security_config", return_value=config), \
             patch.object(dashboard, "get_web_shield_domain", return_value="../etc"):
            response = client.get("/api/web_monitor/backup")
        self.assertEqual(response.status_code, 403)



class MobileBackupSafetyTests(unittest.TestCase):
    def setUp(self):
        dashboard.app.testing = True
        self.client = dashboard.app.test_client()
        self.security_config = {"require_auth": True, "session_timeout": 3600}
        with self.client.session_transaction() as sess:
            sess.update({
                "logged_in": True,
                "username": "admin-user",
                "role": "admin",
                "login_time": time.time(),
                "last_active": time.time(),
            })

    def test_copy_move_and_rename_do_not_overwrite_existing_files(self):
        import tempfile
        with tempfile.TemporaryDirectory() as base_dir:
            source_dir = os.path.join(base_dir, "source")
            dest_dir = os.path.join(base_dir, "dest")
            os.makedirs(source_dir)
            os.makedirs(dest_dir)
            cases = [
                ("rename.txt", "existing.txt"),
                ("move.txt", "move.txt"),
                ("copy.txt", "copy.txt"),
            ]
            for source_name, dest_name in cases:
                with open(os.path.join(source_dir, source_name), "w", encoding="utf-8") as f:
                    f.write(f"source-{source_name}")
                with open(os.path.join(dest_dir if source_name != "rename.txt" else source_dir, dest_name), "w", encoding="utf-8") as f:
                    f.write(f"destination-{dest_name}")

            with patch.object(dashboard, "BACKUP_BASE_DIR", base_dir), \
                 patch.object(dashboard, "load_security_config", return_value=self.security_config), \
                 patch.dict(os.environ, {"MOBILE_ACCESS_TOKEN": ""}):
                rename_response = self.client.post(
                    "/api/mobile-backup/rename",
                    json={"path": os.path.join(source_dir, "rename.txt"), "new_name": "existing.txt"},
                )
                move_response = self.client.post(
                    "/api/mobile-backup/move",
                    json={"src": os.path.join(source_dir, "move.txt"), "dest_dir": dest_dir},
                )
                copy_response = self.client.post(
                    "/api/mobile-backup/copy",
                    json={"src": os.path.join(source_dir, "copy.txt"), "dest_dir": dest_dir},
                )

            self.assertEqual(rename_response.status_code, 409)
            self.assertEqual(move_response.status_code, 409)
            self.assertEqual(copy_response.status_code, 409)
            with open(os.path.join(source_dir, "rename.txt"), encoding="utf-8") as f:
                self.assertEqual(f.read(), "source-rename.txt")
            with open(os.path.join(source_dir, "existing.txt"), encoding="utf-8") as f:
                self.assertEqual(f.read(), "destination-existing.txt")
            with open(os.path.join(source_dir, "move.txt"), encoding="utf-8") as f:
                self.assertEqual(f.read(), "source-move.txt")
            with open(os.path.join(dest_dir, "move.txt"), encoding="utf-8") as f:
                self.assertEqual(f.read(), "destination-move.txt")
            with open(os.path.join(source_dir, "copy.txt"), encoding="utf-8") as f:
                self.assertEqual(f.read(), "source-copy.txt")
            with open(os.path.join(dest_dir, "copy.txt"), encoding="utf-8") as f:
                self.assertEqual(f.read(), "destination-copy.txt")

    def test_listing_missing_subfolder_does_not_create_it(self):
        import tempfile
        with tempfile.TemporaryDirectory() as temporary:
            base_dir = os.path.join(temporary, "MobileBackup")
            os.makedirs(base_dir)
            missing = os.path.join(base_dir, "should-not-be-created")
            with patch.object(dashboard, "BACKUP_BASE_DIR", base_dir), \
                 patch.object(dashboard, "load_security_config", return_value=self.security_config), \
                 patch.dict(os.environ, {"MOBILE_ACCESS_TOKEN": ""}):
                response = self.client.get("/api/mobile-backup/files", query_string={"path": missing})
            self.assertEqual(response.status_code, 404)
            self.assertFalse(os.path.exists(missing))

    def test_network_detection_does_not_return_stale_example_ips(self):
        import tempfile
        with tempfile.TemporaryDirectory() as temporary:
            config_file = os.path.join(temporary, "missing-config.json")
            with patch.object(dashboard, "MOBILE_BACKUP_CONFIG_FILE", config_file), \
                 patch.dict(os.environ, {"MOBILE_BACKUP_LAN_IP": "", "MOBILE_BACKUP_TS_IP": ""}), \
                 patch.object(dashboard.subprocess, "run", side_effect=FileNotFoundError):
                result = dashboard.get_mobile_backup_config()
        self.assertEqual(result, {"lan_ip": "", "ts_ip": ""})

    def test_network_detection_uses_host_default_route_and_tailscale_interface(self):
        import tempfile
        route = type("CommandResult", (), {
            "returncode": 0,
            "stdout": "default via 192.168.1.1 dev eth0 proto dhcp\n",
        })()
        addresses = type("CommandResult", (), {
            "returncode": 0,
            "stdout": (
                "2: eth0    inet 192.168.1.50/24 brd 192.168.1.255 scope global eth0\n"
                "5: tailscale0    inet 100.100.1.2/32 scope global tailscale0\n"
            ),
        })()
        with tempfile.TemporaryDirectory() as temporary:
            with patch.object(dashboard, "MOBILE_BACKUP_CONFIG_FILE", os.path.join(temporary, "none.json")), \
                 patch.dict(os.environ, {"MOBILE_BACKUP_LAN_IP": "", "MOBILE_BACKUP_TS_IP": ""}), \
                 patch.object(dashboard.subprocess, "run", side_effect=[route, addresses]):
                result = dashboard.get_mobile_backup_config()
        self.assertEqual(result, {"lan_ip": "192.168.1.50", "ts_ip": "100.100.1.2"})

    def test_mobile_backup_config_rejects_non_ip_values(self):
        import tempfile
        with tempfile.TemporaryDirectory() as temporary:
            config_file = os.path.join(temporary, "mobile_backup_config.json")
            with patch.object(dashboard, "MOBILE_BACKUP_CONFIG_FILE", config_file), \
                 patch.object(dashboard, "DATA_DIR", temporary), \
                 patch.object(dashboard, "load_security_config", return_value=self.security_config), \
                 patch.dict(os.environ, {"MOBILE_ACCESS_TOKEN": ""}):
                response = self.client.post(
                    "/api/mobile-backup/config",
                    json={"lan_ip": "../../etc/passwd", "ts_ip": "100.100.1.2"},
                )
            self.assertEqual(response.status_code, 400)
            self.assertFalse(os.path.exists(config_file))



class MobileBackupPageAuthorizationTests(unittest.TestCase):
    def test_readonly_user_cannot_open_mobile_backup_management_page(self):
        dashboard.app.testing = True
        client = dashboard.app.test_client()
        with client.session_transaction() as sess:
            sess.update({
                "logged_in": True,
                "username": "viewer",
                "role": "readonly",
                "login_time": time.time(),
                "last_active": time.time(),
            })
        with patch.object(
            dashboard, "load_security_config",
            return_value={"require_auth": True, "session_timeout": 3600},
        ):
            response = client.get("/mobile-backup")
        self.assertIn(response.status_code, (302, 403))


if __name__ == "__main__":
    unittest.main()
