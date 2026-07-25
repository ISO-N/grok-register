"""验证 mihomo 代理轮询顺序、上限和批次集成。"""

import unittest
from unittest.mock import Mock

from mihomo_proxy import (
    MihomoProxyError,
    MihomoProxyRotator,
    MihomoSettings,
    filter_selectable_nodes,
    ordered_candidates,
)
from registration_flow import RegistrationCallbacks, RegistrationOperations, run_batch


class Cancelled(Exception):
    pass


class Retryable(Exception):
    pass


class FakeMihomoClient:
    def __init__(self, nodes, current, delays):
        self.nodes = list(nodes)
        self.current = current
        self.delays = dict(delays)
        self.selected = []
        self.closed = 0
        self.ping_calls = []

    def list_group_nodes(self, group):
        return {"now": self.current, "all": list(self.nodes), "type": "Selector"}

    def ping_node(self, name, ping_url, timeout_ms):
        self.ping_calls.append(name)
        return self.delays.get(name)

    def select_node(self, group, name):
        self.selected.append((group, name))
        self.current = name

    def close_connections(self):
        self.closed += 1


class MihomoProxyUnitTests(unittest.TestCase):
    def test_filter_skips_special_nodes(self):
        nodes = filter_selectable_nodes(
            ["DIRECT", "REJECT", "node-a", "GLOBAL", "node-b"],
            group="PROXY",
        )
        self.assertEqual(nodes, ["node-a", "node-b"])

    def test_ordered_candidates_start_after_current(self):
        self.assertEqual(
            ordered_candidates(["a", "b", "c"], "b"),
            ["c", "a", "b"],
        )
        self.assertEqual(ordered_candidates(["a", "b"], "missing"), ["a", "b"])

    def test_switch_uses_first_available_in_order(self):
        client = FakeMihomoClient(
            nodes=["a", "b", "c"],
            current="a",
            delays={"b": None, "c": 120, "a": 50},
        )
        rotator = MihomoProxyRotator(
            MihomoSettings(
                api_base="http://127.0.0.1:9090",
                proxy_group="PROXY",
                switch_every=1,
                ping_max_tries=5,
            ),
            client=client,
            sleep=lambda _s: None,
        )
        logs = []
        chosen = rotator.switch_to_next_available(log=logs.append)
        self.assertEqual(chosen, "c")
        self.assertEqual(client.ping_calls, ["b", "c"])
        self.assertEqual(client.selected, [("PROXY", "c")])
        self.assertEqual(client.closed, 1)

    def test_max_tries_stops_before_infinite_loop(self):
        client = FakeMihomoClient(
            nodes=["a", "b", "c"],
            current="a",
            delays={"b": None, "c": None, "a": None},
        )
        rotator = MihomoProxyRotator(
            MihomoSettings(
                api_base="http://127.0.0.1:9090",
                proxy_group="PROXY",
                switch_every=1,
                ping_max_tries=2,
            ),
            client=client,
            sleep=lambda _s: None,
        )
        with self.assertRaises(MihomoProxyError):
            rotator.switch_to_next_available()
        self.assertEqual(client.ping_calls, ["b", "c"])
        self.assertEqual(client.selected, [])

    def test_zero_max_tries_keeps_polling_until_recovery(self):
        client = FakeMihomoClient(
            nodes=["a", "b"],
            current="a",
            delays={"b": None, "a": None},
        )
        sleeps = []

        def recover(_seconds):
            sleeps.append(_seconds)
            if len(sleeps) == 1:
                client.delays["b"] = 88

        rotator = MihomoProxyRotator(
            MihomoSettings(
                api_base="http://127.0.0.1:9090",
                proxy_group="PROXY",
                switch_every=1,
                ping_max_tries=0,
                poll_sleep_sec=1.5,
            ),
            client=client,
            sleep=recover,
        )
        chosen = rotator.switch_to_next_available()
        self.assertEqual(chosen, "b")
        self.assertEqual(sleeps, [1.5])
        self.assertIn("b", client.ping_calls)

    def test_note_success_threshold(self):
        rotator = MihomoProxyRotator(
            MihomoSettings(
                api_base="http://127.0.0.1:9090",
                proxy_group="PROXY",
                switch_every=2,
            ),
            client=FakeMihomoClient(["a"], "a", {"a": 1}),
        )
        self.assertFalse(rotator.note_success())
        self.assertTrue(rotator.note_success())


class ProxyRotateBatchTests(unittest.TestCase):
    def test_batch_stops_when_rotate_returns_false(self):
        events = []
        account_no = {"n": 0}

        def fill_email():
            account_no["n"] += 1
            return "user%s@example.com" % account_no["n"], "token"

        ops = RegistrationOperations(
            start_browser=lambda: events.append("start"),
            restart_browser=lambda: events.append("restart"),
            browser_missing=lambda: False,
            open_signup_page=lambda: None,
            fill_email_and_submit=fill_email,
            save_mail_credential=lambda email, token: True,
            fill_code_and_submit=lambda email, token: "123456",
            fill_profile_and_submit=lambda: {
                "given_name": "A",
                "family_name": "B",
                "password": "pw",
            },
            wait_for_sso_cookie=lambda: "sso",
            enable_nsfw=lambda sso: (True, "ok"),
            persist_account_line=lambda email, password, sso: events.append(("persist", email)),
            queue_unsaved_result=lambda payload, error: True,
            add_tokens=lambda sso, email: {
                "local": {"enabled": False, "ok": None, "error": None},
                "remote": {"enabled": False, "ok": None, "error": None},
            },
            export_cpa=lambda email, password, sso: {"ok": False, "skipped": True},
            cleanup=lambda reason: events.append(("cleanup", reason)),
            sleep=lambda seconds: None,
            cancelled_exception=Cancelled,
            retry_exception=Retryable,
            rotate_proxy_after_success=lambda: False,
        )
        logs = []
        callbacks = RegistrationCallbacks(log=logs.append, cancelled=lambda: False)
        batch = run_batch(3, callbacks, lambda *args: None, ops)
        self.assertEqual(batch.success_count, 1)
        self.assertTrue(batch.cancelled)
        self.assertEqual(account_no["n"], 1)
        self.assertTrue(any("代理轮询切换失败" in line for line in logs))

    def test_batch_rotates_only_after_threshold(self):
        rotate_calls = []

        def rotate():
            rotate_calls.append(1)
            return True

        account_no = {"n": 0}

        def fill_email():
            account_no["n"] += 1
            return "user%s@example.com" % account_no["n"], "token"

        ops = RegistrationOperations(
            start_browser=lambda: None,
            restart_browser=lambda: None,
            browser_missing=lambda: False,
            open_signup_page=lambda: None,
            fill_email_and_submit=fill_email,
            save_mail_credential=lambda email, token: True,
            fill_code_and_submit=lambda email, token: "123456",
            fill_profile_and_submit=lambda: {
                "given_name": "A",
                "family_name": "B",
                "password": "pw",
            },
            wait_for_sso_cookie=lambda: "sso",
            enable_nsfw=lambda sso: (True, "ok"),
            persist_account_line=lambda email, password, sso: None,
            queue_unsaved_result=lambda payload, error: True,
            add_tokens=lambda sso, email: {
                "local": {"enabled": False, "ok": None, "error": None},
                "remote": {"enabled": False, "ok": None, "error": None},
            },
            export_cpa=lambda email, password, sso: {"ok": False, "skipped": True},
            cleanup=lambda reason: None,
            sleep=lambda seconds: None,
            cancelled_exception=Cancelled,
            retry_exception=Retryable,
            rotate_proxy_after_success=rotate,
        )
        batch = run_batch(
            2,
            RegistrationCallbacks(log=lambda _m: None, cancelled=lambda: False),
            lambda *args: None,
            ops,
        )
        self.assertEqual(batch.success_count, 2)
        # 最后一个账号成功后不会再切换（没有后续账号）
        self.assertEqual(len(rotate_calls), 1)


class ConfigMihomoTests(unittest.TestCase):
    def test_switch_requires_group(self):
        import app_config

        cfg = dict(app_config.DEFAULT_CONFIG)
        cfg["proxy_switch_every"] = 3
        cfg["mihomo_proxy_group"] = ""
        with self.assertRaises(app_config.ConfigError):
            app_config.validate_run_requirements(cfg)

    def test_switch_zero_skips_group_requirement(self):
        import app_config

        cfg = dict(app_config.DEFAULT_CONFIG)
        cfg["proxy_switch_every"] = 0
        cfg["mihomo_proxy_group"] = ""
        validated = app_config.validate_run_requirements(cfg)
        self.assertEqual(validated["proxy_switch_every"], 0)


if __name__ == "__main__":
    unittest.main()
