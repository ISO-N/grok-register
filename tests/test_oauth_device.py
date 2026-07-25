"""验证 OAuth Device Authorization 的发现、重试、轮询和错误处理。"""

import json
import unittest
from unittest.mock import patch

from cpa_xai import oauth_device as oauth


class Response:
    def __init__(self, body, status=200):
        self.body = body.encode("utf-8")
        self.status = status
    def __enter__(self):
        return self
    def __exit__(self, *args):
        return False
    def read(self):
        return self.body


class Opener:
    def __init__(self, actions):
        self.actions = list(actions)
        self.calls = 0
    def open(self, request, timeout=None):
        self.calls += 1
        action = self.actions.pop(0)
        if isinstance(action, BaseException):
            raise action
        return action


class OAuthDeviceTests(unittest.TestCase):
    def test_discovery_success(self):
        payload = {"device_authorization_endpoint": "https://auth.x.ai/device", "token_endpoint": "https://auth.x.ai/token"}
        opener = Opener([Response(json.dumps(payload))])
        with patch.object(oauth, "_build_opener", return_value=opener):
            self.assertEqual(oauth.discover(retries=0)["token_endpoint"], payload["token_endpoint"])

    def test_discovery_cancelled_before_request(self):
        with self.assertRaisesRegex(oauth.OAuthDeviceError, "cancelled"):
            oauth.discover(cancel=lambda: True)

    def test_discovery_retries_transient_error(self):
        payload = {"device_authorization_endpoint": "https://auth.x.ai/device", "token_endpoint": "https://auth.x.ai/token"}
        opener = Opener([TimeoutError("slow"), Response(json.dumps(payload))])
        with patch.object(oauth, "_build_opener", return_value=opener), patch.object(oauth, "_sleep_with_cancel"):
            oauth.discover(retries=1)
        self.assertEqual(opener.calls, 2)

    def test_post_form_returns_non_json_body(self):
        opener = Opener([Response("not-json", status=502)])
        with patch.object(oauth, "_build_opener", return_value=opener):
            status, payload = oauth._post_form("https://auth.x.ai/token", {}, retries=0)
        self.assertEqual((status, payload), (502, "not-json"))

    def test_slow_down_increases_wait(self):
        responses = [
            (400, {"error": "slow_down"}),
            (200, {"access_token": "a", "refresh_token": "r"}),
        ]
        waits = []
        with patch.object(oauth, "_post_form", side_effect=responses), patch.object(oauth, "_sleep_with_cancel", side_effect=lambda seconds, cancel=None: waits.append(seconds)):
            result = oauth.poll_device_token(
                "d", "https://auth.x.ai/token", interval=1, expires_in=60, initial_delay=0
            )
        self.assertEqual(result.refresh_token, "r")
        self.assertEqual(waits, [6])

    def test_invalid_grant_soft_retries_then_success(self):
        responses = [
            (400, {"error": "invalid_grant", "error_description": "temporary"}),
            (400, {"error": "invalid_grant"}),
            (200, {"access_token": "a", "refresh_token": "r"}),
        ]
        waits = []
        with patch.object(oauth, "_post_form", side_effect=responses), patch.object(
            oauth, "_sleep_with_cancel", side_effect=lambda seconds, cancel=None: waits.append(seconds)
        ):
            result = oauth.poll_device_token(
                "d",
                "https://auth.x.ai/token",
                interval=2,
                expires_in=60,
                initial_delay=0,
                soft_invalid_grant_retries=3,
            )
        self.assertEqual(result.access_token, "a")
        self.assertEqual(waits, [3, 4])

    def test_invalid_grant_exhausts_soft_retries(self):
        responses = [
            (400, {"error": "invalid_grant"}),
            (400, {"error": "invalid_grant"}),
        ]
        with patch.object(oauth, "_post_form", side_effect=responses), patch.object(
            oauth, "_sleep_with_cancel"
        ):
            with self.assertRaisesRegex(oauth.OAuthDeviceError, "invalid_grant"):
                oauth.poll_device_token(
                    "d",
                    "https://auth.x.ai/token",
                    interval=1,
                    expires_in=60,
                    initial_delay=0,
                    soft_invalid_grant_retries=1,
                )

    def test_initial_delay_runs_before_first_poll(self):
        waits = []
        responses = [(200, {"access_token": "a", "refresh_token": "r"})]
        with patch.object(oauth, "_post_form", side_effect=responses) as post, patch.object(
            oauth, "_sleep_with_cancel", side_effect=lambda seconds, cancel=None: waits.append(seconds)
        ):
            oauth.poll_device_token(
                "d", "https://auth.x.ai/token", interval=5, expires_in=60, initial_delay=3.5
            )
        self.assertEqual(waits, [3.5])
        self.assertEqual(post.call_count, 1)

if __name__ == "__main__":
    unittest.main()
