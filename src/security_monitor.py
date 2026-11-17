#!/usr/bin/env python3
"""Conservative local-only service monitoring and configuration checks.

Only loopback addresses are accepted. No exploitation or remote network scanning.
"""
import argparse
import json
import socket
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

def validate_target(url):
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https") or parsed.hostname not in ("localhost", "127.0.0.1", "::1"):
        raise ValueError("Only local loopback HTTP(S) targets are allowed")
    if parsed.username or parsed.password or parsed.fragment:
        raise ValueError("Credentials and fragments are not supported")
    return url

def check_headers(headers, scheme):
    normalized = {k.lower(): v for k, v in headers.items()}
    findings = []
    if scheme == "https" and "strict-transport-security" not in normalized:
        findings.append({"id": "missing-hsts", "severity": "info", "status": "potential", "detail": "HSTS header not observed"})
    if "x-content-type-options" not in normalized:
        findings.append({"id": "missing-nosniff", "severity": "low", "status": "potential", "detail": "X-Content-Type-Options not observed"})
    if "content-security-policy" not in normalized:
        findings.append({"id": "missing-csp", "severity": "info", "status": "potential", "detail": "CSP header not observed; relevance depends on application"})
    return findings

class NoRedirect:
    def __init__(self):
        pass

def probe(url, timeout=3):
    validate_target(url)
    from urllib.request import build_opener, HTTPRedirectHandler
    class RejectRedirect(HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            raise ValueError("Redirects are disabled to prevent out-of-scope requests")
    opener = build_opener(RejectRedirect)
    started = time.monotonic()
    try:
        response = opener.open(Request(url, method="HEAD", headers={"User-Agent": "Network-Security-Lab/1.0"}), timeout=timeout)
        with response:
            status = response.status
            headers = dict(response.headers.items())
    except HTTPError as exc:
        status = exc.code
        headers = dict(exc.headers.items())
    except (URLError, OSError, ValueError) as exc:
        return {"timestamp": datetime.now(timezone.utc).isoformat(), "url": url, "available": False, "error": type(exc).__name__, "latency_ms": round((time.monotonic()-started)*1000, 2), "findings": []}
    return {"timestamp": datetime.now(timezone.utc).isoformat(), "url": url, "available": status < 500, "http_status": status, "latency_ms": round((time.monotonic()-started)*1000, 2), "findings": check_headers(headers, urlsplit(url).scheme)}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:8000")
    parser.add_argument("--interval", type=float, default=10)
    parser.add_argument("--count", type=int, default=1, help="Number of checks; 0 means continuous")
    parser.add_argument("--output", default="reports/monitor.jsonl")
    args = parser.parse_args()
    validate_target(args.url)
    if args.interval < 1 or args.count < 0:
        parser.error("interval must be >=1 second and count must be >=0")
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    index = 0
    while args.count == 0 or index < args.count:
        result = probe(args.url)
        with output.open("a", encoding="utf-8") as file:
            file.write(json.dumps(result, ensure_ascii=False) + "\n")
        print(json.dumps(result, ensure_ascii=False), flush=True)
        index += 1
        if args.count == 0 or index < args.count:
            time.sleep(args.interval)

if __name__ == "__main__":
    main()
