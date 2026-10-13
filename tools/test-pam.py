#!/usr/bin/env python3
"""PAM regression checks. --native changes users ONLY in an explicitly opted-in container.

    python3 tools/test-pam.py
    HAM_PAM_NATIVE_TEST=1 python3 tools/test-pam.py --native
"""
import copy
from datetime import date
import json
from http.cookies import SimpleCookie
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
_tmp = tempfile.TemporaryDirectory(prefix="ham-pam-")
os.environ["HAM_DATA_DIR"] = _tmp.name
os.environ["HAM_DRY_RUN"] = "1"

import ham
from ham import auth, pam_auth, twofactor
from ham.config import DEFAULT_CONFIG, load_config, save_config

POLICY = {"mode": "pam", "pam_service": "haproxy-manager", "allowed_group": "ham-test"}
LOCAL = dict(POLICY, mode="local")
ADMIN = {"username": "admin", "password": "local-test-password"}
ALICE = {"username": "alias@domain", "password": "system-test-password"}
BOB = {"username": "bob@domain", "password": "system-test-password"}


def session_token(response):
    cookie = SimpleCookie()
    cookie.load(response.headers["Set-Cookie"])
    return cookie[auth.SESSION_COOKIE].value


class PamTests(unittest.TestCase):
    def setUp(self):
        cfg = copy.deepcopy(DEFAULT_CONFIG)
        auth.set_admin(cfg, **ADMIN)
        cfg["local"]["api_key"] = "test-api-key"
        save_config(cfg)
        auth._login_fails.clear()
        ham.app.config["TESTING"] = True
        self.client = ham.app.test_client()
        self.users = {"alias@domain": ("alice@domain", 101), "alice@domain": ("alice@domain", 101),
                      "bob@domain": ("bob@domain", 102), "outsider": ("outsider", 103)}
        self.groups = {"alice@domain": [101, 77], "bob@domain": [77], "outsider": [103]}
        self.pam_result = True
        self.pam_calls = []
        def passwd(name):
            canonical, gid = self.users[name]
            return SimpleNamespace(pw_name=canonical, pw_gid=gid)
        def group(name):
            if name != "ham-test":
                raise KeyError(name)
            return SimpleNamespace(gr_gid=77, gr_mem=["bob@domain"])
        def verify(username, password, **kwargs):
            self.pam_calls.append((username, kwargs))
            return self.pam_result and password == "system-test-password"
        self.patches = [
            patch.dict(sys.modules, {"pwd": SimpleNamespace(getpwnam=passwd, getpwall=lambda: []),
                                    "grp": SimpleNamespace(getgrnam=group),
                                    "pam": SimpleNamespace(pam=lambda: SimpleNamespace(authenticate=verify))}),
            patch.object(os, "getgrouplist", lambda name, gid: self.groups[name], create=True),
            patch.object(pam_auth, "PAM_DIR", Path(_tmp.name)),
            patch("time.sleep"),
        ]
        (Path(_tmp.name) / "haproxy-manager").write_text("test service")
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)

    def login(self, credentials=ADMIN, client=None):
        return (client or self.client).post("/api/login", json=credentials)

    def switch(self, policy=POLICY, current=ADMIN, target=ALICE):
        return self.client.put("/api/ui-auth", json=dict(policy, current=current, target=target))

    def enable(self):
        self.assertEqual(self.login().status_code, 200)
        self.assertEqual(self.switch().status_code, 200)

    def test_switch_rotates_sessions_and_checks_target(self):
        token = session_token(self.login())
        other = ham.app.test_client(use_cookies=False)
        cookie = {"Cookie": auth.SESSION_COOKIE + "=" + token}
        self.assertEqual(other.get("/api/local", headers=cookie).status_code, 200)
        before = load_config()
        self.assertEqual(self.switch(target=dict(ALICE, password="bad")).status_code, 403)
        self.assertEqual(load_config(), before)
        self.assertEqual(self.switch().get_json()["username"], "alice@domain")
        self.assertNotEqual(load_config()["local"]["session_secret"], before["local"]["session_secret"])
        self.assertEqual(other.get("/api/local", headers=cookie).status_code, 401)
        self.assertEqual(self.client.get("/api/whoami").get_json()["auth_mode"], "pam")

    def test_pam_password_account_and_no_admin_fallback(self):
        self.enable()
        self.assertEqual(self.login(ALICE).status_code, 200)
        self.assertEqual(self.pam_calls[-1], ("alice@domain", {"service": "haproxy-manager", "resetcreds": False}))
        self.assertEqual(self.login(dict(ALICE, password="bad")).status_code, 401)
        self.assertEqual(self.login(ADMIN).status_code, 401)
        self.pam_result = False  # Includes pam_acct_mgmt denial in python-pam.
        self.assertEqual(self.login(ALICE).status_code, 401)
        self.assertEqual(self.client.post("/api/setup", json=ADMIN).status_code, 409)
        cfg = load_config()
        cfg["local"]["admin"] = {}
        save_config(cfg)
        self.assertEqual(self.client.post("/api/setup", json=ADMIN).status_code, 409)
        self.assertFalse(ham.app.test_client().get("/api/whoami").get_json()["needs_setup"])

    def test_primary_supplementary_and_revoked_membership(self):
        self.groups["alice@domain"] = [77]  # Primary GID as returned by NSS.
        self.users["alice@domain"] = ("alice@domain", 77)
        self.assertEqual(pam_auth.member("alice@domain", "ham-test"), "alice@domain")
        self.assertEqual(pam_auth.member("bob@domain", "ham-test"), "bob@domain")
        self.enable()
        self.assertEqual(self.login({"username": "outsider", "password": "system-test-password"}).status_code, 401)
        self.groups["alice@domain"] = [101]
        self.assertEqual(self.client.get("/api/local").status_code, 401)
        self.assertFalse(self.client.get("/api/whoami").get_json()["authenticated"])

    def test_nss_and_pam_fail_closed(self):
        self.enable()
        for error in (KeyError("missing"), OSError("NSS offline"), RuntimeError("resolver error")):
            with patch.object(os, "getgrouplist", side_effect=error):
                self.assertEqual(self.login(ALICE).status_code, 401)
                self.assertEqual(self.client.get("/api/local").status_code, 401)
        with patch.dict(sys.modules, {"pam": None}):
            self.assertEqual(self.login(ALICE).status_code, 401)
        (Path(_tmp.name) / "haproxy-manager").unlink()
        self.assertEqual(self.login(ALICE).status_code, 401)

    def test_diagnostics_lookup_and_missing_group(self):
        self.login()
        state = self.client.get("/api/ui-auth?username=alias@domain").get_json()
        self.assertTrue(state["lookup"]["member"] is False)  # Default group differs.
        before = load_config()
        for policy in (dict(POLICY, allowed_group="missing"), dict(POLICY, mode="unknown"),
                       dict(POLICY, pam_service="../login"), dict(POLICY, pam_service="absent-service"),
                       dict(POLICY, allowed_group="bad\0group")):
            self.assertEqual(self.switch(policy=policy).status_code, 400)
            self.assertEqual(load_config(), before)
        with patch.dict(sys.modules, {"pam": None}):
            self.assertEqual(self.switch().status_code, 400)
            self.assertEqual(load_config(), before)
        self.switch()
        state = self.client.get("/api/ui-auth?username=alias@domain").get_json()
        self.assertEqual(state["lookup"], {"username": "alice@domain", "member": True})
        self.assertEqual(state["members"], ["bob@domain"])
        self.assertIn("omit domain members", state["members_note"])
        anonymous = ham.app.test_client()
        self.assertEqual(anonymous.get("/api/ui-auth").status_code, 401)

    def test_reauthentication_and_api_key_boundary(self):
        self.login()
        before = load_config()
        self.assertEqual(self.switch(current=dict(ADMIN, password="bad")).status_code, 403)
        self.assertEqual(load_config(), before)
        other = ham.app.test_client()
        self.assertEqual(other.get("/api/local", headers={"X-API-Key": "test-api-key"}).status_code, 200)
        self.assertEqual(other.put("/api/ui-auth", headers={"X-API-Key": "test-api-key"},
                                  json=dict(POLICY, current=ADMIN, target=ALICE)).status_code, 401)
        self.enable()
        before = load_config()
        self.assertEqual(self.switch(current=BOB).status_code, 403)
        self.assertEqual(load_config(), before)
        self.assertEqual(other.get("/api/local", headers={"X-API-Key": "test-api-key"}).status_code, 200)

    def test_typed_credentials_and_rate_limit(self):
        for body in ([], {"username": 7, "password": "x"}, dict(ADMIN, password=[]),
                     dict(ADMIN, password=""), dict(ADMIN, password="a\0b"),
                     dict(ADMIN, username="a|b"), dict(ADMIN, username="a\nb"),
                     dict(ADMIN, username="a\x7fb"), dict(ADMIN, code=3)):
            with self.subTest(body=body):
                self.assertEqual(self.login(body).status_code, 400)
        self.enable()
        for _ in range(auth.LOGIN_MAX_FAILS):
            self.assertEqual(self.login(dict(ALICE, password="bad")).status_code, 401)
        self.assertEqual(self.login(ALICE).status_code, 429)

    def test_profiles_are_isolated_and_credentials_read_only(self):
        self.enable()
        admin = load_config()["local"]["admin"]
        self.assertEqual(self.client.post("/api/password", json={"theme": "dark", "email": "alice@example.org"}).status_code, 200)
        bob = ham.app.test_client()
        self.assertEqual(self.login(BOB, bob).status_code, 200)
        self.assertEqual(bob.get("/api/whoami").get_json()["email"], "")
        self.assertEqual(bob.post("/api/password", json={"theme": "light"}).status_code, 200)
        self.assertEqual(self.client.get("/api/whoami").get_json()["theme"], "dark")
        for body in ({"username": "evil"}, {"new": "changed-password"}, {"propagate": True}):
            self.assertEqual(self.client.post("/api/password", json=body).status_code, 400)
        for endpoint in ("setup", "enable", "disable"):
            self.assertEqual(self.client.post("/api/2fa/" + endpoint, json={}).status_code, 403)
        self.assertEqual(load_config()["local"]["admin"], admin)
        self.assertNotIn(ALICE["password"], json.dumps(load_config()))
        exported = self.client.get("/api/export/config").get_json()["config"]
        self.assertNotIn("local", exported)

    def test_local_totp_survives_failed_switch_and_return_requires_it(self):
        cfg = load_config()
        plain, hashes = twofactor.make_recovery_codes()
        cfg["local"]["admin"].update(totp_enabled=True, totp_secret=twofactor.new_secret(), totp_recovery=hashes)
        save_config(cfg)
        self.assertTrue(self.login().get_json()["totp_required"])
        with self.assertLogs(auth.log, level="INFO") as audit:
            self.assertEqual(self.login(dict(ADMIN, code=plain[0])).status_code, 200)
        self.assertTrue(any("a recovery code was used" in line for line in audit.output))
        self.assertFalse(any(ADMIN["password"] in line or plain[0] in line for line in audit.output))
        proof = dict(ADMIN, code=plain[7])
        self.assertEqual(self.switch(LOCAL, proof, proof).status_code, 200)
        before = load_config()
        self.assertEqual(self.switch(current=dict(ADMIN, code=plain[1]), target=dict(ALICE, password="bad")).status_code, 403)
        self.assertEqual(load_config(), before)  # Even the recovery code was not consumed.
        self.assertEqual(self.switch(current=dict(ADMIN, code=plain[1])).status_code, 200)
        self.assertFalse(self.client.get("/api/whoami").get_json()["totp_enabled"])
        self.assertEqual(self.login(ALICE).status_code, 200)
        before = load_config()
        self.assertTrue(self.switch(LOCAL, ALICE, ADMIN).get_json()["totp_required"])
        self.assertEqual(load_config(), before)
        token = session_token(self.login(ALICE))
        self.assertEqual(self.switch(LOCAL, ALICE, dict(ADMIN, code=plain[2])).status_code, 200)
        self.assertIsNone(auth.read_session(load_config(), token))
        self.assertTrue(self.client.get("/api/whoami").get_json()["totp_enabled"])


class NativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not Path("/.dockerenv").exists() or os.environ.get("HAM_PAM_NATIVE_TEST") != "1":
            raise RuntimeError("native checks must run in an opted-in disposable container")

    def test_native_installation_preserves_custom_pam(self):
        Path("/opt/haproxy-manager").symlink_to("/app")
        service = Path("/etc/pam.d/haproxy-manager")
        service.unlink()
        env = dict(os.environ)
        env.pop("HAM_DATA_DIR", None)
        subprocess.run(["sh", "packaging/postinstall.sh"], env=env, check=True, capture_output=True)
        expected = "common-auth" if Path("/etc/pam.d/common-auth").is_file() else "system-auth"
        self.assertIn("auth include " + expected, service.read_text())
        self.assertTrue(pam_auth.diagnostics(dict(POLICY, allowed_group="haproxy-manager"))["ready"])
        custom = service.read_text() + "# local administrator customization\n"
        service.write_text(custom)
        subprocess.run(["sh", "packaging/postinstall.sh"], env=env, check=True, capture_output=True)
        self.assertEqual(service.read_text(), custom)

    def test_native_password_account_and_restart(self):
        group = "ham-pam-test"
        subprocess.run(["groupadd", group], check=True)
        for name, args in (("hamprimary", ["-g", group]), ("hamsecondary", ["-G", group]), ("hamoutsider", [])):
            subprocess.run(["useradd", "-M", *args, name], check=True)
            subprocess.run(["chpasswd"], input=name + ":native-test-password\n", text=True, check=True)
        cfg = copy.deepcopy(DEFAULT_CONFIG)
        auth.set_admin(cfg, **ADMIN)
        save_config(cfg)
        client = ham.app.test_client()
        self.assertEqual(client.post("/api/login", json=ADMIN).status_code, 200)
        policy = dict(POLICY, allowed_group=group)
        credentials = {"username": "hamprimary", "password": "native-test-password"}
        self.assertTrue(pam_auth.diagnostics(policy)["ready"])
        self.assertEqual(client.put("/api/ui-auth", json=dict(policy, current=ADMIN, target=credentials)).status_code, 200)
        for name in ("hamprimary", "hamsecondary"):
            self.assertEqual(client.post("/api/login", json=dict(credentials, username=name)).status_code, 200)
        self.assertEqual(client.post("/api/login", json=dict(credentials, password="bad")).status_code, 401)
        self.assertEqual(client.post("/api/login", json=dict(credentials, username="hamoutsider")).status_code, 401)
        self.assertEqual(client.post("/api/login", json=ADMIN).status_code, 401)
        auth._login_fails.clear()
        subprocess.run(["usermod", "-L", "hamprimary"], check=True)
        self.assertEqual(client.post("/api/login", json=credentials).status_code, 401)
        subprocess.run(["usermod", "-U", "hamprimary"], check=True)
        subprocess.run(["chage", "-E", "0", "hamprimary"], check=True)
        self.assertEqual(client.post("/api/login", json=credentials).status_code, 401)
        subprocess.run(["chage", "-E", "-1", "hamprimary"], check=True)
        subprocess.run(["chage", "-d", "0", "hamprimary"], check=True)
        self.assertEqual(client.post("/api/login", json=credentials).status_code, 401)
        subprocess.run(["chage", "-d", date.today().isoformat(), "hamprimary"], check=True)
        subprocess.run([sys.executable, "-c", 'import ham; from ham.config import load_config; '
                        'assert load_config()["local"]["ui_auth"]["mode"] == "pam"; '
                        'c=ham.app.test_client(); '
                        'assert c.post("/api/login", json=' + repr(credentials) + ').status_code == 200; '
                        'print("PASS: PAM login after process restart")'], check=True)


if __name__ == "__main__":
    native = "--native" in sys.argv
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(NativeTests if native else PamTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
