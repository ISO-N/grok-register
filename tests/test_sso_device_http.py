"""验证纯 HTTP SSO Device Flow 的会话分离与严格授权判定。"""

import unittest
from unittest.mock import MagicMock, patch

from cpa_xai import sso_device_http as http_flow
from cpa_xai.oauth_device import DeviceCodeSession, OAuthDeviceError, TokenResult


class FakeResp:
    def __init__(self, url="", status_code=200, text="", headers=None):
        self.url = url
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}


class SsoDeviceHttpTests(unittest.TestCase):
    def test_sso_to_token_honors_pre_cancel(self):
        with self.assertRaisesRegex(http_flow.SsoDeviceHttpError, "cancelled"):
            http_flow.sso_to_token("sso", cancel=lambda: True)

    def test_sso_empty(self):
        with self.assertRaisesRegex(http_flow.SsoDeviceHttpError, "sso empty"):
            http_flow.sso_to_token("")

    def test_device_code_and_token_use_clean_request_path(self):
        browser = MagicMock()
        browser.get.return_value = FakeResp(url="https://accounts.x.ai/account")
        browser.post.side_effect = [
            FakeResp(url="https://accounts.x.ai/oauth2/device/consent?user_code=UC", status_code=200, text="allow"),
            FakeResp(url="https://auth.x.ai/oauth2/device/done", status_code=200, text="Device authorized"),
        ]
        session = DeviceCodeSession(
            device_code="dc",
            user_code="UC",
            verification_uri="https://accounts.x.ai/oauth2/device",
            verification_uri_complete="https://accounts.x.ai/oauth2/device?user_code=UC",
            expires_in=600,
            interval=5,
            token_endpoint="https://auth.x.ai/oauth2/token",
            raw={},
        )
        token = TokenResult("access", "refresh", None, "Bearer", 3600, {})

        with patch.object(http_flow, "_new_session", return_value=browser) as new_sess, \
             patch.object(http_flow, "discover", return_value={}), \
             patch.object(http_flow, "request_device_code", return_value=session) as req_code, \
             patch.object(http_flow, "poll_device_token", return_value=token) as poll:
            result = http_flow.sso_to_token("sso-cookie-value", max_retries=1, proxy="http://127.0.0.1:9")

        self.assertEqual(result["access_token"], "access")
        self.assertEqual(result["refresh_token"], "refresh")
        # 浏览器 session 带 SSO；device_code/token 走独立 urllib 路径（request_device_code/poll）
        self.assertTrue(new_sess.called)
        self.assertEqual(new_sess.call_args.kwargs.get("with_sso"), "sso-cookie-value")
        self.assertTrue(req_code.called)
        self.assertTrue(poll.called)

    def test_approve_rejects_bare_200_without_done(self):
        browser = MagicMock()
        browser.get.return_value = FakeResp(url="https://accounts.x.ai/oauth2/device")
        browser.post.side_effect = [
            FakeResp(url="https://accounts.x.ai/oauth2/device/consent", status_code=200, text="allow consent"),
            FakeResp(url="https://accounts.x.ai/oauth2/device/consent", status_code=200, text="still consent"),
        ]
        with self.assertRaisesRegex(http_flow.SsoDeviceHttpError, "did not reach done"):
            http_flow._approve_device(
                browser,
                user_code="UC",
                verification_complete="https://accounts.x.ai/oauth2/device?user_code=UC",
                log=None,
                cancel=None,
                attempt=1,
            )

    def test_retries_new_device_code_after_token_failure(self):
        browser = MagicMock()
        browser.get.return_value = FakeResp(url="https://accounts.x.ai/account")
        browser.post.side_effect = [
            FakeResp(url="https://accounts.x.ai/oauth2/device/consent", status_code=200, text="allow"),
            FakeResp(url="https://auth.x.ai/oauth2/device/done", status_code=200, text="Device authorized"),
            FakeResp(url="https://accounts.x.ai/oauth2/device/consent", status_code=200, text="allow"),
            FakeResp(url="https://auth.x.ai/oauth2/device/done", status_code=200, text="Device authorized"),
        ]
        sessions = [
            DeviceCodeSession("dc1", "U1", "https://x", "https://x?user_code=U1", 600, 5, "https://auth.x.ai/oauth2/token", {}),
            DeviceCodeSession("dc2", "U2", "https://x", "https://x?user_code=U2", 600, 5, "https://auth.x.ai/oauth2/token", {}),
        ]
        token = TokenResult("a2", "r2", None, "Bearer", 3600, {})

        with patch.object(http_flow, "_new_session", return_value=browser), \
             patch.object(http_flow, "discover", return_value={}), \
             patch.object(http_flow, "request_device_code", side_effect=sessions), \
             patch.object(
                 http_flow,
                 "poll_device_token",
                 side_effect=[OAuthDeviceError("invalid_grant"), token],
             ), \
             patch.object(http_flow.time, "sleep"):
            result = http_flow.sso_to_token("sso", max_retries=2)

        self.assertEqual(result["access_token"], "a2")
        self.assertEqual(result["user_code"], "U2")


class SessionWarmupTests(unittest.TestCase):
    def test_settle_seconds_from_env(self):
        from cpa_xai import session_warmup as warm

        with patch.dict("os.environ", {"GROK_OAUTH_SETTLE_SEC": "7"}):
            self.assertEqual(warm.settle_seconds(), 7.0)
        self.assertEqual(warm.settle_seconds(3), 3.0)

    def test_oauth_settle_cancel(self):
        from cpa_xai import session_warmup as warm

        ok = warm.oauth_settle(2, cancel=lambda: True, log=lambda m: None)
        self.assertFalse(ok)

    def test_prepare_skips_warmup_when_disabled(self):
        from cpa_xai import session_warmup as warm

        with patch.object(warm, "oauth_settle", return_value=True) as settle, \
             patch.object(warm, "warmup_sso_session") as warmup:
            ok = warm.prepare_oauth_session(sso="abc", settle_sec=0, do_warmup=False)
        self.assertTrue(ok)
        settle.assert_called_once()
        warmup.assert_not_called()


if __name__ == "__main__":
    unittest.main()
