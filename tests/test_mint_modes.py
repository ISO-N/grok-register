"""验证 mint_and_export 的 settle / browser / http 模式切换。"""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cpa_xai.mint import mint_and_export


class MintModeTests(unittest.TestCase):
    def test_http_mode_requires_sso(self):
        result = mint_and_export(
            "a@example.com",
            "pw",
            tempfile.gettempdir(),
            mint_mode="http",
            sso="",
            settle_sec=0,
            oauth_warmup=False,
        )
        self.assertFalse(result["ok"])
        self.assertIn("sso", result["error"])

    def test_http_mode_success(self):
        with tempfile.TemporaryDirectory() as directory:
            tokens = {
                "access_token": "a",
                "refresh_token": "r",
                "id_token": None,
                "expires_in": 3600,
                "user_code": "UC",
                "token_endpoint": "https://auth.x.ai/oauth2/token",
            }
            with patch("cpa_xai.mint.prepare_oauth_session", return_value=True), \
                 patch("cpa_xai.mint._tokens_from_http", return_value=tokens), \
                 patch("cpa_xai.mint.build_cpa_xai_auth", return_value={"email": "a@example.com"}), \
                 patch("cpa_xai.mint.write_cpa_xai_auth", return_value=Path(directory) / "xai.json") as write:
                result = mint_and_export(
                    "a@example.com",
                    "pw",
                    directory,
                    mint_mode="http",
                    sso="sso-value",
                    settle_sec=0,
                    oauth_warmup=False,
                )
            self.assertTrue(result["ok"])
            self.assertEqual(result["mint_mode"], "http")
            write.assert_called_once()

    def test_browser_then_http_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            tokens = {
                "access_token": "a",
                "refresh_token": "r",
                "expires_in": 3600,
                "user_code": "UC",
                "token_endpoint": "https://auth.x.ai/oauth2/token",
            }
            with patch("cpa_xai.mint.prepare_oauth_session", return_value=True), \
                 patch("cpa_xai.mint.mint_with_browser", side_effect=RuntimeError("browser down")), \
                 patch("cpa_xai.mint._tokens_from_http", return_value=tokens), \
                 patch("cpa_xai.mint.build_cpa_xai_auth", return_value={"email": "a@example.com"}), \
                 patch("cpa_xai.mint.write_cpa_xai_auth", return_value=Path(directory) / "xai.json"):
                result = mint_and_export(
                    "a@example.com",
                    "pw",
                    directory,
                    mint_mode="browser_then_http",
                    sso="sso-value",
                    settle_sec=0,
                    oauth_warmup=False,
                )
            self.assertTrue(result["ok"])
            self.assertEqual(result["mint_mode"], "http")

    def test_cancelled_during_settle(self):
        with patch("cpa_xai.mint.prepare_oauth_session", return_value=False):
            result = mint_and_export(
                "a@example.com",
                "pw",
                tempfile.gettempdir(),
                mint_mode="browser",
                settle_sec=12,
            )
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "cancelled")


if __name__ == "__main__":
    unittest.main()
