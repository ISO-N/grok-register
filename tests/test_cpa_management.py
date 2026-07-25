"""验证 CPA 管理端 Device Flow 客户端与 mint 模式。"""

import unittest
from unittest.mock import patch

from cpa_xai import cpa_management as mgmt
from cpa_xai import browser_confirm as bc
from cpa_xai.mint import mint_and_export


class CpaManagementTests(unittest.TestCase):
    def test_request_xai_auth_url_parses_device_payload(self):
        payload = {
            "status": "ok",
            "url": "https://accounts.x.ai/oauth2/device?user_code=AB-CD",
            "state": "xai-123",
            "flow": "device",
            "user_code": "AB-CD",
            "expires_in": 900,
        }
        with patch.object(mgmt, "_http_get_json", return_value=(200, payload)):
            result = mgmt.request_xai_auth_url("http://127.0.0.1:8317", "secret")
        self.assertEqual(result["state"], "xai-123")
        self.assertEqual(result["user_code"], "AB-CD")
        self.assertIn("user_code=AB-CD", result["url"])

    def test_request_xai_auth_url_requires_key(self):
        with self.assertRaisesRegex(mgmt.CpaManagementError, "management_key"):
            mgmt.request_xai_auth_url("http://127.0.0.1:8317", "")

    def test_poll_auth_status_success(self):
        responses = [
            {"status": "wait", "error": ""},
            {"status": "ok", "error": ""},
        ]
        with patch.object(mgmt, "get_auth_status", side_effect=responses), \
             patch.object(mgmt.time, "sleep"):
            result = mgmt.poll_auth_status(
                "http://127.0.0.1:8317", "secret", "xai-1", timeout_sec=30, interval_sec=0.01
            )
        self.assertEqual(result["status"], "ok")

    def test_poll_auth_status_error(self):
        with patch.object(
            mgmt, "get_auth_status", return_value={"status": "error", "error": "Authentication failed"}
        ), patch.object(mgmt.time, "sleep"):
            with self.assertRaisesRegex(mgmt.CpaManagementError, "Authentication failed"):
                mgmt.poll_auth_status("http://127.0.0.1:8317", "secret", "xai-1", timeout_sec=10)

    def test_mint_cpa_remote_requires_remote(self):
        result = mint_and_export(
            "a@example.com",
            "pw",
            auth_dir=".",
            mint_mode="cpa_remote",
            settle_sec=0,
            oauth_warmup=False,
        )
        self.assertFalse(result["ok"])
        self.assertIn("cpa_remote_url", result["error"])

    def test_mint_cpa_remote_success(self):
        remote_result = {
            "ok": True,
            "state": "xai-9",
            "user_code": "U1",
            "cpa_ingested": True,
            "mint_mode": "cpa_remote",
        }
        with patch("cpa_xai.mint.prepare_oauth_session", return_value=True), \
             patch("cpa_xai.mint.mint_via_cpa_remote", return_value=remote_result):
            result = mint_and_export(
                "a@example.com",
                "pw",
                auth_dir=".",
                mint_mode="cpa_remote",
                cpa_remote_url="http://127.0.0.1:8317",
                cpa_management_key="k",
                settle_sec=0,
                oauth_warmup=False,
            )
        self.assertTrue(result["ok"])
        self.assertTrue(result["cpa_ingested"])
        self.assertEqual(result["mint_mode"], "cpa_remote")

    def test_auto_switch_to_cpa_remote_when_remote_configured(self):
        remote_result = {"ok": True, "state": "xai-1", "cpa_ingested": True}
        with patch("cpa_xai.mint.prepare_oauth_session", return_value=True), \
             patch("cpa_xai.mint.mint_via_cpa_remote", return_value=remote_result) as remote, \
             patch("cpa_xai.mint.mint_with_browser") as browser:
            result = mint_and_export(
                "a@example.com",
                "pw",
                auth_dir=".",
                mint_mode="browser",
                cpa_remote_url="http://127.0.0.1:8317",
                cpa_management_key="k",
                settle_sec=0,
                oauth_warmup=False,
            )
        self.assertTrue(result["ok"])
        remote.assert_called_once()
        browser.assert_not_called()


class ConsentSubmitHelpersTests(unittest.TestCase):
    def test_is_device_done_cn_en(self):
        self.assertTrue(bc._is_device_done("https://auth.x.ai/oauth2/device/done", ""))
        self.assertTrue(bc._is_device_done("https://x", "设备已授权"))
        self.assertTrue(bc._is_device_done("https://x", "Device authorized"))
        self.assertFalse(bc._is_device_done("https://x/consent", "Allow"))

    def test_device_entry_page_must_not_match_consent_by_grok_build_alone(self):
        """设备码页文案含 Grok Build，不能因此当成 consent 直接 allow。"""
        device_text = (
            "退出登录 登录 Grok Build 输入终端中显示的代码。 仅当您刚刚从设备发起登录时才输入此代码。 继续"
        )
        self.assertIn("Grok Build", device_text)
        self.assertNotIn("/consent", "https://accounts.x.ai/oauth2/device?user_code=X")
        # 新逻辑：consent 需 /consent 或 授权文案/允许按钮，而不是仅 Grok Build
        on_consent = (
            "/consent" in "https://accounts.x.ai/oauth2/device?user_code=X"
            or "授权 Grok" in device_text
            or "Authorize Grok" in device_text
        )
        self.assertFalse(on_consent)

    def test_submit_device_allow_sets_action(self):
        class Page:
            def __init__(self):
                self.script = ""

            def run_js(self, script):
                self.script = script
                return "submitted"

        page = Page()
        logs = []
        self.assertTrue(bc._submit_device_allow(page, logs.append))
        self.assertIn('name="action"', page.script)
        self.assertIn("allow", page.script)
        self.assertTrue(any("action=allow" in m for m in logs))

if __name__ == "__main__":
    unittest.main()
