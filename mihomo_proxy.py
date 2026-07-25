"""通过 mihomo / Clash Meta 外部控制器 API 轮询切换代理节点。"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Sequence


DEFAULT_PING_URL = "http://www.gstatic.com/generate_204"
DEFAULT_PING_TIMEOUT_MS = 5000
DEFAULT_POLL_SLEEP_SEC = 3.0
SKIP_NODE_NAMES = frozenset({
    "DIRECT",
    "REJECT",
    "REJECT-DROP",
    "PASS",
    "COMPATIBLE",
    "GLOBAL",
})


class MihomoProxyError(RuntimeError):
    """mihomo API 或轮询切换失败。"""


@dataclass
class MihomoSettings:
    api_base: str = "http://127.0.0.1:9090"
    api_secret: str = ""
    proxy_group: str = ""
    switch_every: int = 0
    ping_max_tries: int = 0
    ping_url: str = DEFAULT_PING_URL
    ping_timeout_ms: int = DEFAULT_PING_TIMEOUT_MS
    poll_sleep_sec: float = DEFAULT_POLL_SLEEP_SEC

    @classmethod
    def from_config(cls, cfg: Dict[str, Any]) -> "MihomoSettings":
        return cls(
            api_base=str(cfg.get("mihomo_api_base") or "http://127.0.0.1:9090").strip(),
            api_secret=str(cfg.get("mihomo_api_secret") or "").strip(),
            proxy_group=str(cfg.get("mihomo_proxy_group") or "").strip(),
            switch_every=int(cfg.get("proxy_switch_every") or 0),
            ping_max_tries=int(cfg.get("proxy_ping_max_tries") or 0),
            ping_url=str(cfg.get("mihomo_ping_url") or DEFAULT_PING_URL).strip() or DEFAULT_PING_URL,
            ping_timeout_ms=int(cfg.get("mihomo_ping_timeout_ms") or DEFAULT_PING_TIMEOUT_MS),
            poll_sleep_sec=float(cfg.get("mihomo_poll_sleep_sec") or DEFAULT_POLL_SLEEP_SEC),
        )

    @property
    def enabled(self) -> bool:
        return self.switch_every > 0 and bool(self.api_base) and bool(self.proxy_group)


class MihomoClient:
    """最小 mihomo external-controller HTTP 客户端（始终直连，不走业务代理）。"""

    def __init__(self, api_base: str, api_secret: str = "", timeout: float = 15.0):
        self.api_base = str(api_base or "").rstrip("/")
        self.api_secret = str(api_secret or "").strip()
        self.timeout = float(timeout)

    def _headers(self, content_type: Optional[str] = None) -> Dict[str, str]:
        headers = {"Accept": "application/json"}
        if self.api_secret:
            headers["Authorization"] = "Bearer %s" % self.api_secret
        if content_type:
            headers["Content-Type"] = content_type
        return headers

    def _request(
        self,
        method: str,
        path: str,
        query: Optional[Dict[str, Any]] = None,
        body: Optional[Dict[str, Any]] = None,
    ) -> Any:
        if not self.api_base:
            raise MihomoProxyError("mihomo API 地址为空")
        url = self.api_base + path
        if query:
            url = url + "?" + urllib.parse.urlencode(query)
        data = None
        headers = self._headers("application/json" if body is not None else None)
        if body is not None:
            data = json.dumps(body).encode("utf-8")
        request = urllib.request.Request(url, data=data, headers=headers, method=method.upper())
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                raw = response.read()
                if not raw:
                    return None
                try:
                    return json.loads(raw.decode("utf-8"))
                except Exception:
                    return raw.decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            detail = ""
            try:
                detail = exc.read().decode("utf-8", errors="replace")
            except Exception:
                detail = str(exc.reason or "")
            raise MihomoProxyError(
                "mihomo API %s %s 失败: HTTP %s %s"
                % (method.upper(), path, exc.code, detail.strip() or exc.reason)
            ) from exc
        except Exception as exc:
            raise MihomoProxyError("mihomo API %s %s 失败: %s" % (method.upper(), path, exc)) from exc

    def get_proxy(self, name: str) -> Dict[str, Any]:
        encoded = urllib.parse.quote(str(name), safe="")
        payload = self._request("GET", "/proxies/%s" % encoded)
        if not isinstance(payload, dict):
            raise MihomoProxyError("获取代理组信息失败: 响应不是对象")
        return payload

    def list_group_nodes(self, group: str) -> Dict[str, Any]:
        info = self.get_proxy(group)
        members = info.get("all")
        if not isinstance(members, list):
            raise MihomoProxyError("代理组 %r 没有可用节点列表 (all)" % group)
        return {
            "now": str(info.get("now") or ""),
            "all": [str(item) for item in members if str(item or "").strip()],
            "type": str(info.get("type") or ""),
        }

    def ping_node(self, name: str, ping_url: str, timeout_ms: int) -> Optional[int]:
        encoded = urllib.parse.quote(str(name), safe="")
        query = {
            "url": ping_url,
            "timeout": str(int(timeout_ms)),
        }
        # delay 接口本身可能因节点超时返回非 2xx；当作不可用处理。
        try:
            payload = self._request("GET", "/proxies/%s/delay" % encoded, query=query)
        except MihomoProxyError:
            return None
        if not isinstance(payload, dict):
            return None
        delay = payload.get("delay")
        try:
            value = int(delay)
        except (TypeError, ValueError):
            return None
        if value <= 0:
            return None
        return value

    def select_node(self, group: str, name: str) -> None:
        encoded = urllib.parse.quote(str(group), safe="")
        self._request("PUT", "/proxies/%s" % encoded, body={"name": name})

    def close_connections(self) -> None:
        try:
            self._request("DELETE", "/connections")
        except MihomoProxyError:
            # 关闭连接失败不应阻断切换结果，旧连接会逐渐自然结束。
            pass


def filter_selectable_nodes(nodes: Sequence[str], group: str = "") -> List[str]:
    result = []
    group_name = str(group or "").strip()
    for name in nodes:
        item = str(name or "").strip()
        if not item:
            continue
        if item == group_name:
            continue
        if item.upper() in SKIP_NODE_NAMES:
            continue
        result.append(item)
    return result


def ordered_candidates(nodes: Sequence[str], current: str = "") -> List[str]:
    """从当前节点的下一个开始，按顺序环形排列候选节点。"""
    items = list(nodes)
    if not items:
        return []
    if current in items:
        start = (items.index(current) + 1) % len(items)
        return items[start:] + items[:start]
    return items


class MihomoProxyRotator:
    """按成功注册数触发节点切换；按顺序 ping，直到找到可用节点。"""

    def __init__(
        self,
        settings: MihomoSettings,
        client: Optional[MihomoClient] = None,
        sleep: Optional[Callable[[float], None]] = None,
    ):
        self.settings = settings
        self.client = client or MihomoClient(settings.api_base, settings.api_secret)
        self._sleep = sleep or time.sleep
        self.success_since_switch = 0

    @property
    def enabled(self) -> bool:
        return self.settings.enabled

    def note_success(self) -> bool:
        """记录一次成功注册。返回 True 表示现在应切换代理。"""
        if not self.enabled:
            return False
        self.success_since_switch += 1
        return self.success_since_switch >= self.settings.switch_every

    def reset_counter(self) -> None:
        self.success_since_switch = 0

    def switch_to_next_available(
        self,
        log: Optional[Callable[[str], None]] = None,
        cancelled: Optional[Callable[[], bool]] = None,
    ) -> str:
        """
        按顺序 ping 下一个节点并切换。

        - proxy_ping_max_tries > 0: 最多尝试 N 次后失败
        - proxy_ping_max_tries == 0: 持续轮询直到某个节点恢复或任务取消
        """
        if not self.enabled:
            raise MihomoProxyError("代理轮询未启用")

        logger = log or (lambda _message: None)
        is_cancelled = cancelled or (lambda: False)
        group = self.settings.proxy_group
        max_tries = int(self.settings.ping_max_tries)
        unlimited = max_tries <= 0

        group_info = self.client.list_group_nodes(group)
        nodes = filter_selectable_nodes(group_info["all"], group=group)
        if not nodes:
            raise MihomoProxyError("代理组 %r 没有可切换节点" % group)

        current = group_info.get("now") or ""
        candidates = ordered_candidates(nodes, current)
        logger(
            "[*] 准备切换 mihomo 代理: 组=%s 当前=%s 候选=%d 上限=%s"
            % (group, current or "(未知)", len(candidates), "无限" if unlimited else max_tries)
        )

        tried = 0
        cycle = 0
        while True:
            if is_cancelled():
                raise MihomoProxyError("代理切换在等待可用节点时被取消")
            cycle += 1
            for name in candidates:
                if is_cancelled():
                    raise MihomoProxyError("代理切换在等待可用节点时被取消")
                if not unlimited and tried >= max_tries:
                    raise MihomoProxyError(
                        "已尝试 %d 个节点均不可用，达到 proxy_ping_max_tries 上限"
                        % max_tries
                    )
                tried += 1
                delay = self.client.ping_node(
                    name,
                    self.settings.ping_url,
                    self.settings.ping_timeout_ms,
                )
                if delay is None:
                    logger("[!] 节点不可用，跳过: %s (第 %d 次尝试)" % (name, tried))
                    continue
                self.client.select_node(group, name)
                self.client.close_connections()
                self.reset_counter()
                logger("[+] 已切换 mihomo 代理节点: %s (delay=%sms, 尝试=%d)" % (name, delay, tried))
                return name

            if not unlimited:
                raise MihomoProxyError(
                    "已尝试 %d 个节点均不可用，达到 proxy_ping_max_tries 上限"
                    % max_tries
                )
            logger(
                "[!] 本轮 %d 个节点均不可用，继续轮询等待恢复 (cycle=%d, sleep=%.1fs)"
                % (len(candidates), cycle, self.settings.poll_sleep_sec)
            )
            # 重新拉取列表，节点订阅可能已更新。
            try:
                group_info = self.client.list_group_nodes(group)
                nodes = filter_selectable_nodes(group_info["all"], group=group)
                current = group_info.get("now") or current
                if nodes:
                    candidates = ordered_candidates(nodes, current)
            except MihomoProxyError as exc:
                logger("[!] 刷新代理列表失败，沿用上一轮列表: %s" % exc)
            self._sleep(max(0.5, float(self.settings.poll_sleep_sec)))

    def maybe_rotate_after_success(
        self,
        log: Optional[Callable[[str], None]] = None,
        cancelled: Optional[Callable[[], bool]] = None,
    ) -> Optional[str]:
        """成功注册后调用。若未到切换阈值返回 None；切换成功返回节点名。"""
        if not self.note_success():
            return None
        return self.switch_to_next_available(log=log, cancelled=cancelled)


def build_rotator_from_config(cfg: Dict[str, Any], sleep: Optional[Callable[[float], None]] = None) -> Optional[MihomoProxyRotator]:
    settings = MihomoSettings.from_config(cfg)
    if not settings.enabled:
        return None
    return MihomoProxyRotator(settings, sleep=sleep)
