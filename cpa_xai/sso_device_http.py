"""纯 HTTP Device Authorization Flow：SSO cookie → access/refresh token。

对齐 OAuth 加固补丁（sso_to_auth_json）：
- device_code / token 使用**不带 SSO** 的干净 session（模拟 CLI 设备侧）
- verify / approve 使用带 SSO 的浏览器 session，跟随跳转
- 严格校验 consent → done，禁止裸 HTTP 200 冒充已授权
- invalid_grant 软重试 + 换新 device code 重试
- 授权后先 sleep interval 再 poll token
"""

from __future__ import annotations

import time
import urllib.parse
from typing import Callable, Optional

from .oauth_device import (
    CLIENT_ID,
    SCOPE,
    OAuthDeviceError,
    discover,
    poll_device_token,
    request_device_code,
)
from .proxyutil import resolve_proxy


LogFn = Callable[[str], None]
CancelFn = Callable[[], bool]

DEVICE_VERIFY_URL = "https://auth.x.ai/oauth2/device/verify"
DEVICE_APPROVE_URL = "https://auth.x.ai/oauth2/device/approve"
BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
)


class SsoDeviceHttpError(OAuthDeviceError):
    pass


def _log(fn: Optional[LogFn], message: str) -> None:
    if fn:
        fn(message)


def _cancelled(cancel: Optional[CancelFn]) -> bool:
    return bool(cancel and cancel())


def _proxy_dict(proxy: Optional[str]) -> Optional[dict]:
    resolved = resolve_proxy(proxy)
    if not resolved:
        return None
    return {"http": resolved, "https": resolved}


def _new_session(proxy: Optional[str] = None, with_sso: str = ""):
    """新建 curl_cffi session。device_code/token 必须 with_sso 为空。"""
    from curl_cffi import requests

    session = requests.Session()
    proxies = _proxy_dict(proxy)
    if proxies:
        session.proxies = proxies
    cookie = str(with_sso or "").strip()
    if cookie:
        for domain in (".x.ai", "accounts.x.ai", "auth.x.ai"):
            session.cookies.set("sso", cookie, domain=domain)
            session.cookies.set("sso-rw", cookie, domain=domain)
    return session


def _url_has(url: str, *parts: str) -> bool:
    low = str(url or "").lower()
    return any(part.lower() in low for part in parts)


def _device_location_error(loc: str) -> Optional[str]:
    if not loc:
        return None
    try:
        err = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query).get("error", [None])[0]
    except Exception:
        return None
    return err or None


def _is_rate_limited(url: str = "", body: str = "") -> bool:
    blob = "%s\n%s" % (url, body)
    low = blob.lower()
    return any(
        needle in low
        for needle in (
            "rate_limited",
            "rate-limited",
            "too_many_requests",
            "ratelimit",
            "429",
        )
    )


def _validate_sso(browser, log: Optional[LogFn], cancel: Optional[CancelFn]) -> None:
    if _cancelled(cancel):
        raise SsoDeviceHttpError("cancelled")
    try:
        response = browser.get("https://accounts.x.ai/", impersonate="chrome", timeout=15)
    except Exception as exc:
        raise SsoDeviceHttpError("network error validating sso: %s" % exc)
    if _cancelled(cancel):
        raise SsoDeviceHttpError("cancelled")
    url = str(getattr(response, "url", "") or "")
    if "sign-in" in url or "sign-up" in url:
        raise SsoDeviceHttpError("sso invalid")
    _log(log, "sso valid")


def _approve_device(
    browser,
    user_code: str,
    verification_complete: str,
    log: Optional[LogFn],
    cancel: Optional[CancelFn],
    attempt: int,
) -> None:
    form_headers = {
        "User-Agent": BROWSER_UA,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Origin": "https://accounts.x.ai",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    try:
        browser.get(
            verification_complete,
            headers={
                "User-Agent": BROWSER_UA,
                "Accept": form_headers["Accept"],
                "Accept-Language": "en-US,en;q=0.9",
            },
            impersonate="chrome",
            timeout=15,
        )
    except Exception as exc:
        _log(log, "open device page failed: %s" % exc)

    try:
        verify_resp = browser.post(
            DEVICE_VERIFY_URL,
            data=urllib.parse.urlencode({"user_code": user_code}),
            headers={**form_headers, "Referer": verification_complete},
            impersonate="chrome",
            timeout=15,
            allow_redirects=True,
        )
    except Exception as exc:
        raise SsoDeviceHttpError("device verify error: %s" % exc)
    if _cancelled(cancel):
        raise SsoDeviceHttpError("cancelled")

    vurl = str(getattr(verify_resp, "url", "") or "")
    vloc = str(verify_resp.headers.get("Location") or "")
    if _is_rate_limited(vurl, str(verify_resp.text or "")) or verify_resp.status_code == 429:
        raise SsoDeviceHttpError("device verify rate limited")
    loc_err = _device_location_error(vurl) or _device_location_error(vloc)
    if loc_err:
        raise SsoDeviceHttpError("device verify error=%s" % loc_err)
    if verify_resp.status_code == 403:
        raise SsoDeviceHttpError("device verify challenge/403")

    verified = _url_has(vurl, "consent", "device/done") or _url_has(vloc, "consent", "device/done")
    if not verified and verify_resp.status_code // 100 == 2:
        body_l = str(verify_resp.text or "").lower()
        verified = "allow" in body_l or "consent" in body_l or "user_code" in body_l
    if not verified:
        raise SsoDeviceHttpError(
            "device verify did not reach consent status=%s url=%s"
            % (verify_resp.status_code, vurl[:140])
        )

    if _url_has(vurl, "device/done") or _url_has(vloc, "device/done"):
        _log(log, "device already authorized (verify -> done)")
        return

    consent_ref = vurl if _url_has(vurl, "consent") else (
        vloc if str(vloc).startswith("http") else (
            "https://accounts.x.ai" + vloc if str(vloc).startswith("/") else verification_complete
        )
    )
    if not _url_has(consent_ref, "consent"):
        consent_ref = (
            "https://accounts.x.ai/oauth2/device/consent?"
            "user_code=%s" % urllib.parse.quote(user_code)
        )
    try:
        approve_resp = browser.post(
            DEVICE_APPROVE_URL,
            data=urllib.parse.urlencode({
                "user_code": user_code,
                "action": "allow",
                "principal_type": "User",
                "principal_id": "",
            }),
            headers={**form_headers, "Referer": consent_ref},
            impersonate="chrome",
            timeout=15,
            allow_redirects=True,
        )
    except Exception as exc:
        raise SsoDeviceHttpError("device approve error: %s" % exc)
    if _cancelled(cancel):
        raise SsoDeviceHttpError("cancelled")

    aurl = str(getattr(approve_resp, "url", "") or "")
    aloc = str(approve_resp.headers.get("Location") or "")
    if _is_rate_limited(aurl, str(approve_resp.text or "")) or approve_resp.status_code == 429:
        raise SsoDeviceHttpError("device approve rate limited")
    aerr = _device_location_error(aurl) or _device_location_error(aloc)
    if aerr:
        raise SsoDeviceHttpError("device approve error=%s" % aerr)

    body_l = str(approve_resp.text or "").lower()
    # 严格：必须到 done，或明确 Device authorized 文案（禁止裸 200 冒充）
    approved = (
        _url_has(aurl, "device/done")
        or _url_has(aloc, "device/done")
        or "device authorized" in body_l
        or "设备已授权" in (approve_resp.text or "")
    )
    if not approved:
        if approve_resp.status_code == 403:
            raise SsoDeviceHttpError("device approve challenge/403")
        raise SsoDeviceHttpError(
            "device approve did not reach done status=%s url=%s"
            % (approve_resp.status_code, aurl[:140])
        )
    _log(log, "device authorized (attempt %s)" % attempt)


def sso_to_token(
    sso_cookie: str,
    proxy: Optional[str] = None,
    log: Optional[LogFn] = None,
    cancel: Optional[CancelFn] = None,
    max_retries: int = 5,
    request_timeout_sec: float = 15.0,
    poll_timeout_sec: float = 15.0,
) -> dict:
    """SSO cookie → token dict (access/refresh/expires_in/id_token/...)。

    device_code / token 无 SSO；verify / approve 带 SSO。
    """
    if _cancelled(cancel):
        raise SsoDeviceHttpError("cancelled")
    sso_cookie = str(sso_cookie or "").strip()
    if not sso_cookie:
        raise SsoDeviceHttpError("sso empty")

    resolved = resolve_proxy(proxy)
    browser = _new_session(resolved, with_sso=sso_cookie)
    _validate_sso(browser, log, cancel)

    # 预热 discovery（device_code 仍走干净 urllib session，见 request_device_code）
    discover(proxy=resolved, timeout=float(request_timeout_sec), cancel=cancel, retries=2)
    if _cancelled(cancel):
        raise SsoDeviceHttpError("cancelled")

    _log(log, "Device Flow HTTP (device/token clean session; verify/approve with SSO)")
    retries = max(1, int(max_retries or 1))
    last_error: Optional[Exception] = None

    for attempt in range(1, retries + 1):
        if _cancelled(cancel):
            raise SsoDeviceHttpError("cancelled")
        try:
            session = request_device_code(
                proxy=resolved,
                timeout=float(request_timeout_sec),
                cancel=cancel,
                retries=2,
            )
        except Exception as exc:
            last_error = exc
            _log(log, "device code failed: %s" % exc)
            if attempt < retries:
                time.sleep(2 + attempt)
                continue
            raise SsoDeviceHttpError("device code failed: %s" % exc)

        _log(
            log,
            "user_code=%s interval=%ss try=%s/%s"
            % (session.user_code, session.interval, attempt, retries),
        )
        try:
            _approve_device(
                browser,
                user_code=session.user_code,
                verification_complete=session.verification_uri_complete,
                log=log,
                cancel=cancel,
                attempt=attempt,
            )
        except SsoDeviceHttpError as exc:
            last_error = exc
            message = str(exc).lower()
            _log(log, str(exc))
            if "rate limited" in message and attempt < retries:
                delay = min(45, 10 * attempt)
                _log(log, "rate limited, retry in %ss" % delay)
                time.sleep(delay)
                continue
            if attempt < retries:
                time.sleep(2 + attempt)
                continue
            raise
        except Exception as exc:
            last_error = exc
            _log(log, "approve failed: %s" % exc)
            if attempt < retries:
                time.sleep(2 + attempt)
                continue
            raise SsoDeviceHttpError("approve failed: %s" % exc)

        try:
            token = poll_device_token(
                session.device_code,
                token_endpoint=session.token_endpoint,
                interval=max(session.interval, 5),
                expires_in=session.expires_in,
                log=log,
                cancel=cancel,
                proxy=resolved,
                timeout=float(poll_timeout_sec),
            )
            return {
                "access_token": token.access_token,
                "refresh_token": token.refresh_token,
                "id_token": token.id_token,
                "token_type": token.token_type,
                "expires_in": token.expires_in,
                "user_code": session.user_code,
                "token_endpoint": session.token_endpoint,
                "raw": token.raw,
            }
        except OAuthDeviceError as exc:
            last_error = exc
            _log(log, "token poll failed: %s" % exc)
            if attempt < retries:
                delay = min(25, 4 * attempt)
                _log(log, "retry whole device flow in %ss (%s/%s)" % (delay, attempt, retries))
                time.sleep(delay)
                continue
            raise

    raise SsoDeviceHttpError("device flow failed: %s" % (last_error or "unknown"))
