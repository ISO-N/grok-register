"""协调浏览器授权、CPA 管理端 Device Flow、HTTP 路径与凭证导出。"""

from .browser_confirm import mint_via_cpa_remote, mint_with_browser
from .schema import DEFAULT_BASE_URL, build_cpa_xai_auth
from .session_warmup import prepare_oauth_session
from .writer import write_cpa_xai_auth

VALID_MINT_MODES = (
    "cpa_remote",
    "browser",
    "http",
    "browser_then_http",
    "cpa_remote_then_browser",
)


def _tokens_from_http(
    sso,
    proxy=None,
    log=None,
    cancel=None,
    request_timeout_sec=15.0,
    poll_timeout_sec=15.0,
    max_retries=5,
):
    from .sso_device_http import sso_to_token

    return sso_to_token(
        sso_cookie=sso,
        proxy=proxy,
        log=log,
        cancel=cancel,
        max_retries=int(max_retries or 5),
        request_timeout_sec=float(request_timeout_sec),
        poll_timeout_sec=float(poll_timeout_sec),
    )


def _export_tokens(email, tokens, auth_dir, base_url, log=None):
    logger = log or (lambda message: None)
    payload = build_cpa_xai_auth(
        email=email,
        access_token=tokens["access_token"],
        refresh_token=tokens["refresh_token"],
        id_token=tokens.get("id_token"),
        expires_in=tokens.get("expires_in"),
        base_url=base_url,
        token_endpoint=tokens.get("token_endpoint") or "",
    )
    path = write_cpa_xai_auth(auth_dir, payload)
    logger("wrote %s" % path)
    return {
        "ok": True,
        "email": email,
        "path": str(path),
        "user_code": tokens.get("user_code"),
        "base_url": str(base_url or DEFAULT_BASE_URL),
        "mint_mode": tokens.get("mint_mode") or "",
    }


def mint_and_export(
    email,
    password,
    auth_dir,
    page=None,
    proxy=None,
    headless=False,
    base_url=DEFAULT_BASE_URL,
    browser_timeout_sec=240.0,
    force_standalone=True,
    cookies=None,
    reuse_browser=True,
    recycle_every=15,
    log=None,
    cancel=None,
    request_timeout_sec=15.0,
    poll_timeout_sec=15.0,
    sso=None,
    mint_mode="browser",
    settle_sec=None,
    oauth_warmup=True,
    http_max_retries=5,
    cpa_remote_url="",
    cpa_management_key="",
    cpa_poll_interval_sec=2.0,
):
    """生成 OIDC token 并写出 CPA xAI auth 文件（或远端入库）。

    mint_mode:
      - cpa_remote: 调 CPA /xai-auth-url → 浏览器授权 → 轮询 /get-auth-status
      - browser: 本地 Device Flow + 浏览器确认 + token poll
      - http: 纯 HTTP SSO Device Flow
      - browser_then_http: 浏览器失败后回退 HTTP
      - cpa_remote_then_browser: CPA 远端失败后回退本地 browser
    """
    logger = log or (lambda message: None)
    email = str(email or "").strip()
    password = str(password or "")
    sso_value = str(sso or "").strip()
    remote_url = str(cpa_remote_url or "").strip()
    management_key = str(cpa_management_key or "").strip()
    mode = str(mint_mode or "browser").strip().lower() or "browser"
    if mode not in VALID_MINT_MODES:
        mode = "browser"

    # 配置了远端但未显式选模式时，优先 cpa_remote（与 CPA 官方 device 流程对齐）
    if mode == "browser" and remote_url and management_key:
        mode = "cpa_remote"
        logger("auto mint_mode=cpa_remote (remote_url configured)")

    if mode in ("cpa_remote", "cpa_remote_then_browser"):
        if not remote_url or not management_key:
            if mode == "cpa_remote_then_browser":
                logger("cpa_remote skipped: missing remote_url/management_key")
                mode = "browser"
            else:
                return {
                    "ok": False,
                    "email": email,
                    "error": "cpa_remote requires cpa_remote_url and cpa_management_key",
                }
    elif mode == "http":
        if not sso_value:
            return {"ok": False, "email": email, "error": "missing sso for http mint"}
    elif not email or not password:
        if mode == "browser_then_http" and sso_value:
            mode = "http"
        elif cookies:
            pass
        else:
            return {"ok": False, "email": email, "error": "missing email/password"}

    if not prepare_oauth_session(
        sso=sso_value,
        proxy=proxy,
        settle_sec=settle_sec,
        cancel=cancel,
        log=logger,
        do_warmup=bool(oauth_warmup),
    ):
        return {"ok": False, "email": email, "error": "cancelled"}

    errors = []

    if mode in ("cpa_remote", "cpa_remote_then_browser"):
        try:
            result = mint_via_cpa_remote(
                email=email,
                password=password,
                remote_url=remote_url,
                management_key=management_key,
                page=None if force_standalone else page,
                proxy=proxy,
                headless=bool(headless),
                browser_timeout_sec=float(browser_timeout_sec),
                poll_log=logger,
                cancel=cancel,
                force_standalone=bool(force_standalone),
                cookies=cookies,
                reuse_browser=bool(reuse_browser),
                recycle_every=int(recycle_every or 0),
                request_timeout_sec=float(request_timeout_sec),
                poll_interval_sec=float(cpa_poll_interval_sec or 2.0),
            )
            result = dict(result or {})
            result.setdefault("ok", True)
            result["email"] = email
            result["mint_mode"] = "cpa_remote"
            result["path"] = result.get("path") or ""
            logger(
                "CPA remote ingest ok state=%s user_code=%s"
                % (result.get("state"), result.get("user_code"))
            )
            return result
        except Exception as exc:
            logger("cpa_remote mint failed: %s" % exc)
            errors.append("cpa_remote: %s" % exc)
            if mode != "cpa_remote_then_browser":
                return {"ok": False, "email": email, "error": str(exc)}
            logger("falling back to local browser Device Flow ...")
            mode = "browser"

    if mode in ("browser", "browser_then_http"):
        try:
            tokens = mint_with_browser(
                email=email,
                password=password,
                page=None if force_standalone else page,
                proxy=proxy,
                headless=bool(headless),
                browser_timeout_sec=float(browser_timeout_sec),
                poll_log=logger,
                cancel=cancel,
                force_standalone=bool(force_standalone),
                cookies=cookies,
                reuse_browser=bool(reuse_browser),
                recycle_every=int(recycle_every or 0),
                request_timeout_sec=float(request_timeout_sec),
                poll_timeout_sec=float(poll_timeout_sec),
            )
            tokens = dict(tokens)
            tokens["mint_mode"] = "browser"
            return _export_tokens(email, tokens, auth_dir, base_url, log=logger)
        except Exception as exc:
            logger("browser mint failed: %s" % exc)
            errors.append("browser: %s" % exc)
            if mode != "browser_then_http":
                return {"ok": False, "email": email, "error": " | ".join(errors) if errors else str(exc)}
            if not sso_value:
                return {
                    "ok": False,
                    "email": email,
                    "error": "%s; http fallback skipped (no sso)" % (" | ".join(errors)),
                }
            logger("falling back to HTTP Device Flow ...")

    if mode in ("http", "browser_then_http"):
        try:
            tokens = _tokens_from_http(
                sso=sso_value,
                proxy=proxy,
                log=logger,
                cancel=cancel,
                request_timeout_sec=request_timeout_sec,
                poll_timeout_sec=poll_timeout_sec,
                max_retries=http_max_retries,
            )
            tokens = dict(tokens)
            tokens["mint_mode"] = "http"
            return _export_tokens(email, tokens, auth_dir, base_url, log=logger)
        except Exception as exc:
            logger("http mint failed: %s" % exc)
            errors.append("http: %s" % exc)
            return {
                "ok": False,
                "email": email,
                "error": " | ".join(errors) if errors else str(exc),
            }

    return {"ok": False, "email": email, "error": " | ".join(errors) or "mint failed"}
