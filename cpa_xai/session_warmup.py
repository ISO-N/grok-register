"""OAuth 前会话 settle 与 accounts 轻量预热。

新注册账号立刻走 Device Flow 时，常见 invalid_grant / Access denied。
对齐补丁包逻辑：
1. 等待会话落库（GROK_OAUTH_SETTLE_SEC，默认 12s）
2. 访问 accounts + SetTosAcceptedVersion 轻预热
"""

from __future__ import annotations

import os
import struct
import time
from typing import Callable, Optional

from .proxyutil import resolve_proxy


LogFn = Callable[[str], None]
CancelFn = Callable[[], bool]

DEFAULT_SETTLE_SEC = 12.0
BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
)


def settle_seconds(explicit=None) -> float:
    """解析 OAuth settle 秒数：参数 > 环境变量 > 默认 12。"""
    if explicit is not None:
        try:
            return max(float(explicit), 0.0)
        except (TypeError, ValueError):
            return DEFAULT_SETTLE_SEC
    raw = (os.environ.get("GROK_OAUTH_SETTLE_SEC") or "").strip()
    if not raw:
        return DEFAULT_SETTLE_SEC
    try:
        return max(float(raw), 0.0)
    except ValueError:
        return DEFAULT_SETTLE_SEC


def oauth_settle(
    seconds=None,
    cancel: Optional[CancelFn] = None,
    log: Optional[LogFn] = None,
) -> bool:
    """阻塞等待会话就绪。返回 False 表示被取消。"""
    logger = log or (lambda message: None)
    wait = settle_seconds(seconds)
    if wait <= 0:
        return True
    logger("oauth settle %.0fs ..." % wait)
    deadline = time.time() + wait
    while time.time() < deadline:
        if cancel and cancel():
            logger("oauth settle cancelled")
            return False
        time.sleep(min(0.5, max(0.05, deadline - time.time())))
    if cancel and cancel():
        logger("oauth settle cancelled")
        return False
    return True


def _apply_sso_cookies(session, sso: str) -> None:
    cookie = str(sso or "").strip()
    if not cookie:
        return
    for domain in (".x.ai", "accounts.x.ai", "auth.x.ai"):
        session.cookies.set("sso", cookie, domain=domain)
        session.cookies.set("sso-rw", cookie, domain=domain)


def warmup_sso_session(
    sso: str,
    proxy: Optional[str] = None,
    log: Optional[LogFn] = None,
    timeout: float = 20.0,
) -> bool:
    """访问 accounts + SetTosAcceptedVersion。失败不抛错，返回是否成功。"""
    logger = log or (lambda message: None)
    cookie = str(sso or "").strip()
    if not cookie:
        logger("oauth warmup skipped: empty sso")
        return False
    try:
        from curl_cffi import requests as curl_requests
    except Exception as exc:
        logger("oauth warmup skipped: curl_cffi unavailable (%s)" % exc)
        return False

    resolved = resolve_proxy(proxy)
    try:
        session = curl_requests.Session()
        if resolved:
            session.proxies = {"http": resolved, "https": resolved}
        _apply_sso_cookies(session, cookie)
        session.get(
            "https://accounts.x.ai/account",
            impersonate="chrome",
            timeout=float(timeout),
            headers={"User-Agent": BROWSER_UA},
        )
        # SetTosAcceptedVersion field1=1（grpc-web frame）
        tos_body = b"\x00" + struct.pack(">I", 2) + bytes([0x08, 0x01])
        session.post(
            "https://accounts.x.ai/auth_mgmt.AuthManagement/SetTosAcceptedVersion",
            data=tos_body,
            headers={
                "Content-Type": "application/grpc-web+proto",
                "X-Grpc-Web": "1",
                "Origin": "https://accounts.x.ai",
                "Referer": "https://accounts.x.ai/account",
                "User-Agent": BROWSER_UA,
            },
            impersonate="chrome",
            timeout=float(timeout),
        )
        logger("oauth warmup ok (account+TOS)")
        return True
    except Exception as exc:
        logger("oauth warmup skipped: %s" % exc)
        return False


def prepare_oauth_session(
    sso: str = "",
    proxy: Optional[str] = None,
    settle_sec=None,
    cancel: Optional[CancelFn] = None,
    log: Optional[LogFn] = None,
    do_warmup: bool = True,
) -> bool:
    """settle + 可选预热。返回 False 表示被取消。"""
    if not oauth_settle(settle_sec, cancel=cancel, log=log):
        return False
    if do_warmup and str(sso or "").strip():
        warmup_sso_session(sso, proxy=proxy, log=log)
    return not (cancel and cancel())
