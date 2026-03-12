#!/usr/bin/env python3
"""
MCP server for HTTP Security Headers analysis.
No API key required — makes direct HTTP requests.
"""

import sys
import json
import urllib.request
import urllib.parse
import ssl


def send(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()

def respond(id, result):
    send({"jsonrpc": "2.0", "id": id, "result": result})

def error(id, code, message):
    send({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})

def text_result(data):
    return {"content": [{"type": "text", "text": json.dumps(data, ensure_ascii=False, indent=2)}]}


TOOLS = [
    {
        "name": "http_check_headers",
        "description": "Check HTTP security headers for a URL: HSTS, CSP, X-Frame-Options, CORS, Referrer-Policy, etc. Grades each header as present/missing/weak.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url":            {"type": "string", "description": "URL to check (e.g. 'https://example.com')"},
                "follow_redirects": {"type": "boolean", "description": "Follow HTTP redirects (default true)"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "http_request",
        "description": "Make an HTTP GET or POST request and return status, headers and body preview.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url":     {"type": "string", "description": "URL to request"},
                "method":  {"type": "string", "description": "HTTP method: GET or POST (default GET)"},
                "headers": {"type": "object", "description": "Additional request headers as key-value pairs"},
                "body":    {"type": "string", "description": "Request body (POST only)"},
                "timeout": {"type": "integer", "description": "Timeout in seconds (default 10)"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "http_check_redirects",
        "description": "Trace the full redirect chain for a URL, showing each hop, status code and final destination.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Starting URL"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "http_bulk_status",
        "description": "Check HTTP status and response time for multiple URLs at once.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "urls": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of URLs to check",
                },
                "timeout": {"type": "integer", "description": "Timeout per request in seconds (default 5)"},
            },
            "required": ["urls"],
        },
    },
]


# Security headers to check and their analysis
SECURITY_HEADERS = {
    "strict-transport-security": {
        "name": "HSTS",
        "desc": "HTTP Strict Transport Security",
        "check": lambda v: ("strong" if "max-age" in v and int(
            next((p.split("=")[1] for p in v.split(";") if "max-age" in p), "0").strip()
        ) >= 31536000 else "weak"),
    },
    "content-security-policy": {
        "name": "CSP",
        "desc": "Content Security Policy",
        "check": lambda v: "weak" if "unsafe-inline" in v or "unsafe-eval" in v else "present",
    },
    "x-frame-options": {
        "name": "X-Frame-Options",
        "desc": "Clickjacking protection",
        "check": lambda v: "strong" if v.upper() in ("DENY", "SAMEORIGIN") else "weak",
    },
    "x-content-type-options": {
        "name": "X-Content-Type-Options",
        "desc": "MIME sniffing protection",
        "check": lambda v: "strong" if v.lower() == "nosniff" else "weak",
    },
    "referrer-policy": {
        "name": "Referrer-Policy",
        "desc": "Referrer information control",
        "check": lambda v: "strong" if v.lower() in (
            "no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"
        ) else "weak",
    },
    "permissions-policy": {
        "name": "Permissions-Policy",
        "desc": "Browser feature permissions",
        "check": lambda v: "present",
    },
    "x-xss-protection": {
        "name": "X-XSS-Protection",
        "desc": "XSS filter (deprecated but common)",
        "check": lambda v: "present",
    },
    "cross-origin-opener-policy": {
        "name": "COOP",
        "desc": "Cross-Origin Opener Policy",
        "check": lambda v: "present",
    },
    "cross-origin-embedder-policy": {
        "name": "COEP",
        "desc": "Cross-Origin Embedder Policy",
        "check": lambda v: "present",
    },
    "cache-control": {
        "name": "Cache-Control",
        "desc": "Caching directives",
        "check": lambda v: "present",
    },
}

MISSING_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]


def fetch_headers(url, follow_redirects=True, timeout=10):
    ctx = ssl.create_default_context()
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
    if not follow_redirects:
        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ctx),
            urllib.request.HTTPRedirectHandler(),
        )
        # Disable redirects
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None
        opener = urllib.request.build_opener(NoRedirect)

    req = urllib.request.Request(url, headers={"User-Agent": "mcp-httpheaders/1.0"})
    try:
        with opener.open(req, timeout=timeout) as r:
            return dict(r.headers), r.geturl(), r.status, None
    except urllib.error.HTTPError as e:
        return dict(e.headers), url, e.code, None
    except Exception as ex:
        return {}, url, None, str(ex)


def handle_http_check_headers(args):
    url  = args["url"]
    if not url.startswith("http"):
        url = "https://" + url
    follow = args.get("follow_redirects", True)
    headers, final_url, status, err = fetch_headers(url, follow_redirects=follow)
    if err:
        return {"url": url, "error": err}

    lower_headers = {k.lower(): v for k, v in headers.items()}
    analysis      = {}
    missing       = []
    score         = 0
    max_score     = len(SECURITY_HEADERS)

    for header_key, meta in SECURITY_HEADERS.items():
        value = lower_headers.get(header_key)
        if value:
            try:
                rating = meta["check"](value)
            except Exception:
                rating = "present"
            analysis[meta["name"]] = {
                "present": True,
                "value":   value[:200],
                "rating":  rating,
                "desc":    meta["desc"],
            }
            score += 1
        else:
            analysis[meta["name"]] = {
                "present": False,
                "value":   None,
                "rating":  "missing",
                "desc":    meta["desc"],
            }
            if header_key in MISSING_HEADERS:
                missing.append(meta["name"])

    grade_pct = score / max_score
    grade = "A" if grade_pct >= 0.9 else "B" if grade_pct >= 0.7 else "C" if grade_pct >= 0.5 else "D" if grade_pct >= 0.3 else "F"

    return {
        "url":        url,
        "final_url":  final_url,
        "status":     status,
        "grade":      grade,
        "score":      f"{score}/{max_score}",
        "headers":    analysis,
        "missing_critical": missing,
        "server":     lower_headers.get("server"),
        "powered_by": lower_headers.get("x-powered-by"),
    }


def handle_http_request(args):
    import time
    url     = args["url"]
    method  = args.get("method", "GET").upper()
    timeout = int(args.get("timeout", 10))
    extra   = args.get("headers", {})
    body    = args.get("body", "").encode() if args.get("body") else None

    req_headers = {"User-Agent": "mcp-http/1.0"}
    req_headers.update(extra)

    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, data=body, method=method, headers=req_headers)
    t0  = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            elapsed = round((time.time() - t0) * 1000, 1)
            body_preview = r.read(2000).decode(errors="replace")
            return {
                "url":          url,
                "method":       method,
                "status":       r.status,
                "elapsed_ms":   elapsed,
                "headers":      dict(r.headers),
                "body_preview": body_preview,
                "body_length":  len(body_preview),
            }
    except urllib.error.HTTPError as e:
        elapsed = round((time.time() - t0) * 1000, 1)
        return {
            "url":        url,
            "method":     method,
            "status":     e.code,
            "elapsed_ms": elapsed,
            "headers":    dict(e.headers),
            "error":      e.reason,
        }
    except Exception as ex:
        return {"url": url, "method": method, "error": str(ex)}


def handle_http_check_redirects(args):
    url   = args["url"]
    if not url.startswith("http"):
        url = "https://" + url
    chain = []
    current = url
    ctx   = ssl.create_default_context()

    class RedirectRecorder(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            chain.append({"url": req.full_url, "status": code, "location": newurl})
            return super().redirect_request(req, fp, code, msg, headers, newurl)

    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ctx),
        RedirectRecorder(),
    )
    try:
        req = urllib.request.Request(current, headers={"User-Agent": "mcp-http/1.0"})
        with opener.open(req, timeout=10) as r:
            chain.append({"url": r.geturl(), "status": r.status, "location": None})
    except urllib.error.HTTPError as e:
        chain.append({"url": current, "status": e.code, "location": None, "error": e.reason})
    except Exception as ex:
        chain.append({"url": current, "status": None, "error": str(ex)})

    return {
        "start_url":   url,
        "final_url":   chain[-1]["url"] if chain else url,
        "hops":        len(chain),
        "chain":       chain,
        "https":       chain[-1]["url"].startswith("https") if chain else False,
    }


def handle_http_bulk_status(args):
    import time
    urls    = args.get("urls", [])
    timeout = int(args.get("timeout", 5))
    results = []
    ctx     = ssl.create_default_context()
    for url in urls:
        if not url.startswith("http"):
            url = "https://" + url
        t0 = time.time()
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "mcp-http/1.0"})
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                elapsed = round((time.time() - t0) * 1000, 1)
                results.append({"url": url, "status": r.status, "elapsed_ms": elapsed, "ok": True})
        except urllib.error.HTTPError as e:
            elapsed = round((time.time() - t0) * 1000, 1)
            results.append({"url": url, "status": e.code, "elapsed_ms": elapsed, "ok": False})
        except Exception as ex:
            elapsed = round((time.time() - t0) * 1000, 1)
            results.append({"url": url, "status": None, "elapsed_ms": elapsed, "ok": False, "error": str(ex)})
    return {"total": len(results), "results": results}


HANDLERS = {
    "http_check_headers":   handle_http_check_headers,
    "http_request":         handle_http_request,
    "http_check_redirects": handle_http_check_redirects,
    "http_bulk_status":     handle_http_bulk_status,
}


def handle_call(id, name, args):
    handler = HANDLERS.get(name)
    if not handler:
        error(id, -32601, f"Unknown tool: {name}")
        return
    try:
        result = handler(args)
        respond(id, text_result(result))
    except Exception as e:
        respond(id, {"content": [{"type": "text", "text": f"[error]: {e}"}], "isError": True})


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        method = msg.get("method")
        id     = msg.get("id")
        if method == "initialize":
            respond(id, {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "httpheaders-mcp", "version": "1.0.0"},
            })
        elif method == "notifications/initialized":
            pass
        elif method == "tools/list":
            respond(id, {"tools": TOOLS})
        elif method == "tools/call":
            params = msg.get("params", {})
            handle_call(id, params.get("name"), params.get("arguments", {}))
        elif id is not None:
            error(id, -32601, f"Method not found: {method}")

if __name__ == "__main__":
    main()
