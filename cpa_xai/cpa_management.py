"""CLIProxyAPI 管理端 Device Flow 客户端。

对齐 CPA：
  GET /v0/management/xai-auth-url   → {url, state, user_code, flow=device}
  GET /v0/management/get-auth-status?state=... → wait | ok | error

认证：Authorization: Bearer <management_key>
参考：https://github.com/router-for-me/CLIProxyAPI
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Callable, Optional


LogFn = Callable[[str], None]
CancelFn = Callable[[], bool]


class CpaManagementError(RuntimeError):
    pass


def _normalize_base(url: str) -> str:
    value = str(url or "").strip().rstrip("/")
    if not value:
        raise CpaManagementError("cpa_remote_url is empty")
    return value


def _auth_headers(management_key: str) -> dict:
    key = str(management_key or "").strip()
    if not key:
        raise CpaManagementError("cpa_management_key is empty")
    return {
        "Authorization": "Bearer %s" % key,
        "Accept": "application/json",
        "User-Agent": "grok-register-cpa/1.0",
    }


def _http_get_json(url: str, headers: dict, timeout: float = 30.0) -> tuple[int, dict]:
    request = urllib.request.Request(url, method="GET", headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=float(timeout)) as response:
            body = response.read().decode("utf-8", errors="replace")
            status = int(getattr(response, "status", 200) or 200)
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        status = int(exc.code)
    except Exception as exc:
        raise CpaManagementError("CPA management request failed: %s" % exc)
    try:
        payload = json.loads(body) if body else {}
    except Exception:
        payload = {"raw": body}
    if not isinstance(payload, dict):
        payload = {"raw": payload}
    return status, payload


def request_xai_auth_url(
    remote_url: str,
    management_key: str,
    timeout: float = 30.0,
    log: Optional[LogFn] = None,
) -> dict:
    """GET /v0/management/xai-auth-url → device 链接与 state。"""
    logger = log or (lambda message: None)
    base = _normalize_base(remote_url)
    endpoint = base + "/v0/management/xai-auth-url"
    logger("CPA xai-auth-url: %s" % endpoint)
    status, payload = _http_get_json(endpoint, _auth_headers(management_key), timeout=timeout)
    if status != 200:
        raise CpaManagementError(
            "xai-auth-url HTTP %s: %s" % (status, payload.get("error") or payload)
        )
    auth_url = str(payload.get("url") or payload.get("verification_uri_complete") or "").strip()
    state = str(payload.get("state") or "").strip()
    if not auth_url:
        raise CpaManagementError("xai-auth-url missing url: %r" % payload)
    if not state:
        raise CpaManagementError("xai-auth-url missing state: %r" % payload)
    user_code = str(payload.get("user_code") or "").strip()
    if not user_code and "user_code=" in auth_url:
        try:
            user_code = urllib.parse.parse_qs(
                urllib.parse.urlparse(auth_url).query
            ).get("user_code", [""])[0]
        except Exception:
            user_code = ""
    expires_in = int(payload.get("expires_in") or 1800)
    logger(
        "CPA device flow state=%s user_code=%s expires_in=%s"
        % (state, user_code or "(none)", expires_in)
    )
    return {
        "url": auth_url,
        "state": state,
        "user_code": user_code,
        "expires_in": expires_in,
        "flow": str(payload.get("flow") or "device"),
        "raw": payload,
    }


def get_auth_status(
    remote_url: str,
    management_key: str,
    state: str,
    timeout: float = 15.0,
) -> dict:
    """GET /v0/management/get-auth-status?state=..."""
    base = _normalize_base(remote_url)
    state_value = str(state or "").strip()
    if not state_value:
        raise CpaManagementError("get-auth-status missing state")
    query = urllib.parse.urlencode({"state": state_value})
    endpoint = base + "/v0/management/get-auth-status?" + query
    status, payload = _http_get_json(endpoint, _auth_headers(management_key), timeout=timeout)
    if status >= 400 and status != 200:
        raise CpaManagementError(
            "get-auth-status HTTP %s: %s" % (status, payload.get("error") or payload)
        )
    return {
        "status": str(payload.get("status") or "").strip().lower(),
        "error": str(payload.get("error") or "").strip(),
        "raw": payload,
        "http_status": status,
    }


def poll_auth_status(
    remote_url: str,
    management_key: str,
    state: str,
    timeout_sec: float = 300.0,
    interval_sec: float = 2.0,
    request_timeout: float = 15.0,
    log: Optional[LogFn] = None,
    cancel: Optional[CancelFn] = None,
) -> dict:
    """轮询直到 CPA 入库成功（status=ok）或失败/超时。"""
    logger = log or (lambda message: None)
    deadline = time.time() + max(float(timeout_sec), 30.0)
    sleep_seconds = max(float(interval_sec), 0.5)
    last = {}
    while time.time() < deadline:
        if cancel and cancel():
            raise CpaManagementError("cancelled")
        try:
            last = get_auth_status(
                remote_url,
                management_key,
                state,
                timeout=request_timeout,
            )
        except CpaManagementError:
            raise
        except Exception as exc:
            logger("get-auth-status blip: %s" % exc)
            time.sleep(sleep_seconds)
            continue
        status = last.get("status") or ""
        if status == "ok":
            logger("CPA get-auth-status ok — credential ingested")
            return last
        if status == "error":
            raise CpaManagementError(
                "CPA auth failed: %s" % (last.get("error") or last.get("raw"))
            )
        if status in ("wait", ""):
            logger("CPA auth pending (wait) ...")
            time.sleep(sleep_seconds)
            continue
        # 未知状态：当作 wait，避免误杀
        logger("CPA auth status=%r — continue" % status)
        time.sleep(sleep_seconds)
    raise CpaManagementError(
        "CPA auth status timed out: %s" % (last.get("error") or last or "no response")
    )
