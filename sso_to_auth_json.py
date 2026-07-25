#!/usr/bin/env python3
"""CLI：SSO cookie → CPA xAI auth.json（纯 HTTP Device Flow）。

用法示例:
  python sso_to_auth_json.py --sso-cookie 'eyJ...' --email user@example.com --cpa-auth-dir ./cpa_auths
  python sso_to_auth_json.py --sso accounts.txt --cpa-auth-dir ./cpa_auths --proxy http://127.0.0.1:7890

accounts 行格式:
  email----password----sso
  email----sso
  sso
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from cpa_xai.schema import build_cpa_xai_auth
from cpa_xai.session_warmup import prepare_oauth_session
from cpa_xai.sso_device_http import SsoDeviceHttpError, sso_to_token
from cpa_xai.writer import write_cpa_xai_auth


def parse_sso_line(line: str) -> tuple[str, str]:
    text = str(line or "").strip()
    if not text or text.startswith("#"):
        return "", ""
    parts = [part.strip() for part in text.split("----") if part.strip()]
    if not parts:
        return "", ""
    if len(parts) == 1:
        return "", parts[0]
    if len(parts) == 2:
        # email----sso 或 password----sso；邮箱含 @ 时当 email
        if "@" in parts[0]:
            return parts[0], parts[1]
        return "", parts[1]
    # email----password----sso（取首尾）
    return parts[0], parts[-1]


def _load_lines(path: str) -> list[str]:
    return Path(path).read_text(encoding="utf-8", errors="replace").splitlines()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="SSO → CPA xAI auth via HTTP Device Flow")
    parser.add_argument("--sso", help="SSO 列表文件（每行一条）")
    parser.add_argument("--sso-cookie", help="单条 SSO cookie")
    parser.add_argument("--email", default="", help="单条 SSO 对应邮箱")
    parser.add_argument("--cpa-auth-dir", default="./cpa_auths", help="CPA auth 输出目录")
    parser.add_argument("--proxy", default="", help="HTTP 代理")
    parser.add_argument("--settle-sec", type=float, default=None, help="OAuth 前等待秒数")
    parser.add_argument("--no-warmup", action="store_true", help="跳过 accounts/TOS 预热")
    parser.add_argument("--max-retries", type=int, default=5, help="换 device code 重试次数")
    parser.add_argument("--skip-existing", action="store_true", help="跳过已有 xai-<email>.json")
    args = parser.parse_args(argv)

    proxy = (args.proxy or os.environ.get("HTTPS_PROXY") or os.environ.get("HTTP_PROXY") or "").strip()
    auth_dir = Path(args.cpa_auth_dir).expanduser()
    if not auth_dir.is_absolute():
        auth_dir = (Path.cwd() / auth_dir).resolve()
    auth_dir.mkdir(parents=True, exist_ok=True)

    jobs: list[tuple[str, str]] = []
    if args.sso_cookie:
        jobs.append((str(args.email or "").strip(), str(args.sso_cookie).strip()))
    if args.sso:
        for line in _load_lines(args.sso):
            email, sso = parse_sso_line(line)
            if sso:
                jobs.append((email, sso))
    if not jobs:
        parser.error("需要 --sso-cookie 或 --sso")

    ok = 0
    fail = 0
    for email, sso in jobs:
        label = email or sso[:24]
        print("[*] %s" % label)
        if args.skip_existing and email:
            existing = auth_dir / ("xai-%s.json" % email)
            if existing.is_file():
                print("  skip existing %s" % existing.name)
                ok += 1
                continue
        if not prepare_oauth_session(
            sso=sso,
            proxy=proxy or None,
            settle_sec=args.settle_sec,
            log=lambda m: print("  %s" % m),
            do_warmup=not args.no_warmup,
        ):
            print("  cancelled")
            fail += 1
            continue
        try:
            tokens = sso_to_token(
                sso,
                proxy=proxy or None,
                log=lambda m: print("  %s" % m),
                max_retries=args.max_retries,
            )
            payload = build_cpa_xai_auth(
                email=email,
                access_token=tokens["access_token"],
                refresh_token=tokens["refresh_token"],
                id_token=tokens.get("id_token"),
                expires_in=tokens.get("expires_in"),
                token_endpoint=tokens.get("token_endpoint") or "",
            )
            path = write_cpa_xai_auth(auth_dir, payload)
            print("  wrote %s" % path)
            ok += 1
        except (SsoDeviceHttpError, Exception) as exc:
            print("  FAILED: %s" % exc)
            fail += 1
    print("[done] ok=%s fail=%s dir=%s" % (ok, fail, auth_dir))
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
