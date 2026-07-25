"""协调浏览器授权、HTTP Device Flow、OAuth 轮询和 CPA 凭证导出流程。"""

from .browser_confirm import mint_with_browser
from .schema import DEFAULT_BASE_URL, build_cpa_xai_auth
from .session_warmup import prepare_oauth_session
from .writer import write_cpa_xai_auth


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
):
    """生成 OIDC token 并写出 CPA xAI auth 文件。

    mint_mode:
      - browser: 仅浏览器 Device Flow（默认，实测更稳）
      - http: 仅纯 HTTP SSO Device Flow（device/token 无 SSO）
      - browser_then_http: 浏览器失败后回退 HTTP
    """
    logger = log or (lambda message: None)
    email = str(email or "").strip()
    password = str(password or "")
    sso_value = str(sso or "").strip()
    mode = str(mint_mode or "browser").strip().lower() or "browser"
    if mode not in ("browser", "http", "browser_then_http"):
        mode = "browser"

    if mode == "http":
        if not sso_value:
            return {"ok": False, "email": email, "error": "missing sso for http mint"}
    elif not email or not password:
        # browser 路径需要账密；若同时给了 sso 且允许回退，可只走 http
        if mode == "browser_then_http" and sso_value:
            mode = "http"
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
                return {"ok": False, "email": email, "error": str(exc)}
            if not sso_value:
                return {
                    "ok": False,
                    "email": email,
                    "error": "%s; http fallback skipped (no sso)" % exc,
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
