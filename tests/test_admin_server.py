import base64
import hashlib
import json
import os
import tempfile
import time
import unittest
from pathlib import Path

import httpx

import admin.server as admin_server
from core.workbuddy_atrest_crypto import encrypt_auth_field, is_encrypted_field

ADMIN = "admin-test-credential-long-enough"
API = "client-existing-key"

# 与 test_workbuddy_atrest.py 使用同一个测试密钥，避免两个文件互相污染
# protector_key() 的进程级缓存（_cached_key 一旦写入就不再读环境变量）。
TEST_SECRET = base64.b64encode(hashlib.sha256(b"test-seed").digest()).decode()
_ORIGINAL_SECRET = os.environ.get("WORKBUDDY_AT_REST_SECRET")


def setUpModule():
    os.environ["WORKBUDDY_AT_REST_SECRET"] = TEST_SECRET


def tearDownModule():
    if _ORIGINAL_SECRET is None:
        os.environ.pop("WORKBUDDY_AT_REST_SECRET", None)
    else:
        os.environ["WORKBUDDY_AT_REST_SECRET"] = _ORIGINAL_SECRET


def credential(uid="one", name="测试账号"):
    return {"account": {"uid": uid, "nickname": name, "enterpriseId": "test"}, "auth": {"accessToken": "private-access-token", "refreshToken": "private-refresh-token", "expiresAt": int(time.time() * 1000) + 3600000}}


def encrypted_credential(uid="enc", name="加密账号"):
    """WorkBuddy 5.6+ 形态：token 是 $wbEncrypted 信封，其余字段照旧。"""
    return {
        "account": {"uid": uid, "nickname": name, "enterpriseId": "test"},
        "auth": {
            "accessToken": encrypt_auth_field("encrypted-access-token"),
            "refreshToken": encrypt_auth_field("encrypted-refresh-token"),
            "expiresAt": int(time.time() * 1000) + 3600000,
        },
    }


class AdminTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.auth = self.root / "auth"
        self.auth.mkdir()
        (self.auth / "session.info").write_text(json.dumps(credential()), encoding="utf-8")
        self.make_app()

    def make_app(self):
        self.app = admin_server.create_app(self.root / "management", self.auth, API, ADMIN)
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app), base_url="https://console.test")

    async def asyncTearDown(self):
        await self.client.aclose()
        self.temp.cleanup()

    async def login(self):
        result = await self.client.post("/admin/api/login", json={"key": ADMIN})
        self.assertEqual(result.status_code, 200)
        cookie = result.headers["set-cookie"].lower()
        for flag in ["secure", "httponly", "samesite=strict", "path=/admin"]:
            self.assertIn(flag, cookie)
        self.client.headers["X-CSRF-Token"] = result.json()["csrf"]

    async def test_access_boundaries(self):
        self.assertEqual((await self.client.get("/admin/api/overview")).status_code, 401)
        self.assertEqual((await self.client.get("/admin/api/overview", headers={"Authorization": "Bearer " + API})).status_code, 401)
        self.assertEqual((await self.client.get("/v1/models")).status_code, 401)
        self.assertEqual((await self.client.get("/v1/models", headers={"Authorization": "Bearer " + API})).status_code, 200)
        self.assertEqual((await self.client.get("/health")).json(), {"status": "ok"})
        await self.login()
        self.client.headers.pop("X-CSRF-Token")
        self.assertEqual((await self.client.post("/admin/api/keys", json={"name": "bad"})).status_code, 403)

    async def test_account_import_switch_disable_delete_and_restart(self):
        await self.login()
        first = (await self.client.get("/admin/api/overview")).json()["accounts"][0]
        result = await self.client.post("/admin/api/accounts", json={"name": "Second", "credential": credential("two")})
        self.assertEqual(result.status_code, 200)
        aid = result.json()["id"]
        self.assertTrue(first["active"])
        result = await self.client.patch("/admin/api/accounts/" + aid, json={"active": True})
        self.assertEqual(result.status_code, 200)
        self.assertEqual(admin_server.converter.CONFIG["cred"].path.name, aid + ".info")
        await self.client.patch("/admin/api/accounts/" + aid, json={"enabled": False})
        self.assertIsNone(admin_server.converter.CONFIG["cred"])
        self.assertEqual((await self.client.patch("/admin/api/accounts/" + aid, json={"active": True})).status_code, 400)
        await self.client.patch("/admin/api/accounts/" + first["id"], json={"active": True, "name": "Primary"})
        await self.client.delete("/admin/api/accounts/" + aid)
        self.assertTrue(list((self.root / "management/trash").glob("*/credential.json")))
        await self.client.aclose()
        self.make_app()
        await self.login()
        accounts = (await self.client.get("/admin/api/overview")).json()["accounts"]
        self.assertEqual(len(accounts), 1)
        self.assertTrue(accounts[0]["active"])
        self.assertEqual(accounts[0]["name"], "Primary")

    async def test_key_revocation_persists_and_no_secret_leak(self):
        await self.login()
        overview = await self.client.get("/admin/api/overview")
        for forbidden in [API, "private-access-token", "private-refresh-token", '"hash"']:
            self.assertNotIn(forbidden, overview.text)
        old = overview.json()["keys"][0]["id"]
        self.assertEqual((await self.client.delete("/admin/api/keys/" + old)).status_code, 400)
        result = await self.client.post("/admin/api/keys", json={"name": "New"})
        newkey = result.json()["key"]
        await self.client.delete("/admin/api/keys/" + old)
        self.assertEqual((await self.client.get("/v1/models", headers={"Authorization":"Bearer " + API})).status_code, 401)
        self.assertEqual((await self.client.get("/v1/models", headers={"Authorization":"Bearer " + newkey})).status_code, 200)
        self.assertNotIn(newkey, self.app.state.store.path.read_text(encoding="utf-8"))
        await self.client.aclose()
        self.make_app()
        self.assertEqual((await self.client.get("/v1/models", headers={"Authorization":"Bearer " + API})).status_code, 401)
        self.assertEqual((await self.client.get("/v1/models", headers={"Authorization":"Bearer " + newkey})).status_code, 200)

    async def test_invalid_credentials_and_limits(self):
        await self.login()
        for doc in [{}, {"auth": {}, "account": {}}, {**credential(), "account": {"uid": "bad\r\nheader"}}, {**credential(), "auth": {**credential()["auth"], "expiresAt": "not-time"}}]:
            r = await self.client.post("/admin/api/accounts", json={"credential": doc})
            self.assertEqual(r.status_code, 400, r.text)
        r = await self.client.post("/admin/api/accounts", content=b"x" * (1024 * 1024 + 1))
        self.assertEqual(r.status_code, 413)
        r = await self.client.get("/admin/assets/unknown.js")
        self.assertEqual(r.status_code, 404)

    async def test_import_encrypted_credential(self):
        """5.6+ 的 $wbEncrypted 凭据必须能导入，且落盘后仍保持加密。"""
        await self.login()
        doc = encrypted_credential()
        base = (await self.client.get("/admin/api/overview")).json()["accounts"][0]
        r = await self.client.post("/admin/api/accounts", json={"credential": doc})
        self.assertEqual(r.status_code, 200, r.text)
        aid = r.json()["id"]

        # 落盘仍为加密形态：转换器刷新 token 时要按原格式回写，
        # 明文回写会让 WorkBuddy 客户端报 integrity 错误。
        stored = json.loads((self.auth / (aid + ".info")).read_text(encoding="utf-8"))
        self.assertTrue(is_encrypted_field(stored["auth"]["accessToken"]))
        self.assertTrue(is_encrypted_field(stored["auth"]["refreshToken"]))

        # 昵称照常展示，不能把信封 repr 泄漏成账号名。
        row = next(a for a in (await self.client.get("/admin/api/overview")).json()["accounts"] if a["id"] == aid)
        self.assertEqual(row["name"], "加密账号")
        self.assertEqual(row["nickname"], "加密账号")
        self.assertTrue(base["active"])

    async def test_undecryptable_credential_returns_400(self):
        """信封损坏不能冒成 500，必须按 400 拒绝并给出可读原因。"""
        await self.login()
        doc = encrypted_credential()
        doc["auth"]["accessToken"] = {"$wbEncrypted": 1, "envelope": "not-base64!!"}
        r = await self.client.post("/admin/api/accounts", json={"credential": doc})
        self.assertEqual(r.status_code, 400, r.text)
        self.assertIn("解密", r.text)

    async def test_plaintext_credential_still_accepted(self):
        """旧版明文凭据路径不回归。"""
        await self.login()
        r = await self.client.post("/admin/api/accounts", json={"credential": credential("legacy")})
        self.assertEqual(r.status_code, 200, r.text)
        aid = r.json()["id"]
        stored = json.loads((self.auth / (aid + ".info")).read_text(encoding="utf-8"))
        self.assertEqual(stored["auth"]["accessToken"], "private-access-token")

    async def test_logout_and_rate_limit(self):
        await self.login()
        self.assertEqual((await self.client.post("/admin/api/logout")).status_code, 200)
        self.assertEqual((await self.client.get("/admin/api/overview")).status_code, 401)
        for _ in range(8):
            self.assertEqual((await self.client.post("/admin/api/login", json={"key":"wrong"})).status_code, 401)
        self.assertEqual((await self.client.post("/admin/api/login", json={"key":ADMIN})).status_code, 429)


if __name__ == "__main__":
    unittest.main()
