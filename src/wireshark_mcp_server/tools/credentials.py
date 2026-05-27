"""extract_credentials — 5 parallel tshark passes, credential report formatter."""
import asyncio
import base64
import re
from typing import Annotated

from pydantic import Field

from ..server import mcp
from ..core import (
    _tshark, _parse_tsv,
    _is_benign_domain, _is_private, _is_suspicious_tld,
    _decode_file_data, _IP_RE,
)

# ---------------------------------------------------------------------------
# Credential regex constants
# ---------------------------------------------------------------------------

_PASS_RE = re.compile(
    r'(?:^|[&?;\s{,"\'])(?:password|passwd|pwd|pass(?:word)?|credentials?)'
    r'(?:\s*[=:]\s*|"?\s*:\s*"?)([^\s"\'&;{}]{3,64})',
    re.IGNORECASE,
)
_USER_RE = re.compile(
    r'(?:^|[&?;\s{,"\'])(?:username|user_?name|login|email|uname|acct)'
    r'(?:\s*[=:]\s*|"?\s*:\s*"?)([^\s"\'&;{}]{3,128})',
    re.IGNORECASE,
)
_TOKEN_RE = re.compile(
    r'(?:^|[&?;\s{,"\'])(?:api_?key|apikey|access_?token|auth_?token|'
    r'secret_?key|client_?secret|refresh_?token|private_?key)'
    r'(?:\s*[=:]\s*|"?\s*:\s*"?)([A-Za-z0-9_\-\.+/=]{16,})',
    re.IGNORECASE,
)
_B64_BLOB_RE = re.compile(r'(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{32,}={0,2}(?![A-Za-z0-9+/=])')
_AUTH_BASIC_RE = re.compile(r'Basic\s+([A-Za-z0-9+/=]{4,})', re.IGNORECASE)
_AUTH_BEARER_RE = re.compile(r'Bearer\s+([A-Za-z0-9\-._~+/=]{16,})', re.IGNORECASE)
_CUSTOM_AUTH_RE = re.compile(
    r'(?:X-API-Key|X-Auth(?:entication)?|X-Access-Token|X-Authorization|'
    r'X-Secret(?:-Key)?|X-Token|X-Client-Token)'
    r':\s*([^\r\n,\\]{8,})',
    re.IGNORECASE,
)
# Non-standard short-name headers carrying token-length values (≥20 chars)
# sent to non-whitelisted hosts. Catches malware patterns like:
#   user: <base64-token>   BuildID: <base64-token>
# tshark separates request.line values with commas; each header ends with literal \r\n.
_MALWARE_TOKEN_HDR_RE = re.compile(
    r'(?:^|,)([A-Za-z][A-Za-z0-9\-]{1,30}):\s+([A-Za-z0-9_\-\.+/=]{20,})\\r\\n',
)
_STANDARD_HEADERS: frozenset[str] = frozenset({
    "host", "content-type", "content-length", "content-encoding",
    "accept", "accept-encoding", "accept-language", "accept-charset",
    "connection", "user-agent", "authorization", "cookie",
    "referer", "origin", "cache-control", "pragma", "te", "via",
    "expect", "transfer-encoding", "upgrade", "if-match", "if-none-match",
    "if-modified-since", "if-unmodified-since", "if-range", "range",
    "x-forwarded-for", "x-real-ip", "x-requested-with",
    "date", "server", "last-modified", "etag", "expires",
    "location", "content-disposition",
})
_QUERY_TOKEN_RE = re.compile(
    r'[?&](?:apikey|api_key|access_token|auth_token|token|key|secret)'
    r'=([A-Za-z0-9_\-\.+/=%]{8,})',
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _decode_b64_safe(b64_str: str) -> str:
    """Attempt to decode a base64 string; return decoded text if printable, else ''."""
    try:
        padded = b64_str + "=" * (-len(b64_str) % 4)
        decoded = base64.b64decode(padded).decode("utf-8", errors="replace")
        printable = sum(1 for c in decoded if 32 <= ord(c) < 127)
        if printable / max(len(decoded), 1) > 0.75:
            return decoded.strip()
    except Exception:
        pass
    return ""


def _scan_post_body(body: str) -> dict:
    """
    Scan a decoded POST body for credential patterns.
    Returns a dict with 'user', 'password', 'token', 'b64_creds'.
    Only returns non-empty dict when at least one high-confidence match is found.
    """
    result: dict = {}
    user_m  = _USER_RE.search(body)
    pass_m  = _PASS_RE.search(body)
    token_m = _TOKEN_RE.search(body)

    if user_m:
        result["user"] = user_m.group(1)[:80]
    if pass_m:
        result["password"] = pass_m.group(1)[:80]
    if token_m:
        result["token"] = token_m.group(1)[:80]

    b64_creds: list[str] = []
    for m in _B64_BLOB_RE.finditer(body):
        decoded = _decode_b64_safe(m.group(0))
        if decoded and any(kw in decoded.lower() for kw in
                           ("password", "passwd", "secret", "token", "apikey",
                            "key", "pass", "user", "login", "cred", ":")):
            b64_creds.append(f"{m.group(0)[:40]}… → {decoded[:80]}")
    if b64_creds:
        result["b64_creds"] = b64_creds

    return result


def _score_credential(
    cred_type: str,
    host: str,
    server_ip: str,
    has_user: bool = False,
    has_pass: bool = False,
) -> tuple[int, str]:
    """
    Score a credential entry (3=CRITICAL, 2=SUSPICIOUS, 1=NOTABLE, 0=skip).
    Low-FP design: benign hosts default to 0 unless explicitly included.
    """
    is_benign  = _is_benign_domain(host)
    # Bare-IP: either no Host header, or the Host header contains a raw IP (not a hostname)
    _host_is_ip = bool(host and _IP_RE.fullmatch(host.strip()))
    is_bare    = bool((not host or _host_is_ip) and server_ip and not _is_private(server_ip))
    is_sus_tld = _is_suspicious_tld(host)

    base = 0
    if cred_type == "FTP_PASS":
        base = 3
    elif cred_type == "BASIC_AUTH":
        base = 0 if is_benign else 2
    elif cred_type == "POST_FORM":
        if has_user and has_pass:
            base = 0 if is_benign else 3
        elif has_pass:
            base = 0 if is_benign else 2
    elif cred_type == "POST_BODY":
        base = 0 if is_benign else 2
    elif cred_type == "POST_TOKEN":
        base = 0 if is_benign else 1
    elif cred_type == "BEARER":
        base = 0 if is_benign else 1
    elif cred_type == "CUSTOM_HEADER":
        base = 0 if is_benign else 1
    elif cred_type == "QUERY_TOKEN":
        base = 0 if is_benign else 1
    elif cred_type == "B64_CRED":
        base = 0 if is_benign else 2
    elif cred_type == "NTLM":
        base = 1

    if base > 0:
        if is_bare:
            base = min(base + 1, 3)
        if is_sus_tld:
            base = min(base + 1, 3)

    label = {3: "CRITICAL", 2: "SUSPICIOUS", 1: "NOTABLE", 0: "normal"}[base]
    return base, label


# ---------------------------------------------------------------------------
# Tool
# ---------------------------------------------------------------------------

@mcp.tool()
async def extract_credentials(
    file_path: Annotated[str, Field(description="Absolute path to a .pcap or .pcapng file")],
    include_benign_hosts: Annotated[bool, Field(
        description="Include credentials sent to known-benign hosts (Microsoft, Google, CDNs). Default: False"
    )] = False,
    min_score: Annotated[int, Field(
        description="Minimum score to report: 1=notable, 2=suspicious, 3=critical (default: 1)",
        ge=0, le=3,
    )] = 1,
) -> str:
    """
    Extract credential material from a pcap file.

    Five parallel tshark passes covering:
      1. HTTP auth headers (Basic decoded, Bearer token, custom X-* headers)
      2. URL-encoded form POST bodies (username/password field detection)
      3. HTTP raw/JSON POST bodies (file_data regex scan + base64 blob detection)
      4. FTP USER/PASS commands (always cleartext)
      5. NTLM authentication hashes (from HTTP or SMB NTLM challenge)

    Low-FP design:
    - Credentials to whitelisted domains (Microsoft, Google, CDNs) suppressed by default
    - POST body requires a confirmed credential keyword match, not just any POST
    - Bearer tokens and custom headers only flagged against non-whitelisted hosts
    - Base64 blobs require ≥32 chars AND decode to printable ASCII with a credential keyword
    - Score gating: set min_score=2 to see only suspicious+critical findings
    """
    (
        http_auth_raw,
        form_raw,
        post_body_raw,
        ftp_raw,
        ntlm_raw,
    ) = await asyncio.gather(
        _tshark("-r", file_path, "-Y", "http.request", "-T", "fields",
                "-e", "frame.time_relative",
                "-e", "ip.src", "-e", "ip.dst",
                "-e", "http.host",
                "-e", "http.request.uri",
                "-e", "http.user_agent",
                "-e", "http.authbasic",
                "-e", "http.authorization",
                "-e", "http.request.line"),
        _tshark("-r", file_path, "-Y", "urlencoded-form", "-T", "fields",
                "-e", "frame.time_relative",
                "-e", "ip.src", "-e", "ip.dst",
                "-e", "http.host",
                "-e", "http.request.uri",
                "-e", "http.user_agent",
                "-e", "urlencoded-form.key",
                "-e", "urlencoded-form.value"),
        _tshark("-r", file_path,
                "-Y", 'http.request.method == "POST" && http.file_data',
                "-T", "fields",
                "-e", "frame.time_relative",
                "-e", "ip.src", "-e", "ip.dst",
                "-e", "http.host",
                "-e", "http.request.uri",
                "-e", "http.user_agent",
                "-e", "http.file_data",
                "-e", "http.content_type"),
        _tshark("-r", file_path, "-Y", "ftp.request.command", "-T", "fields",
                "-e", "frame.time_relative",
                "-e", "ip.src", "-e", "ip.dst",
                "-e", "ftp.request.command",
                "-e", "ftp.request.arg"),
        _tshark("-r", file_path, "-Y", "ntlmssp.auth.username", "-T", "fields",
                "-e", "frame.time_relative",
                "-e", "ip.src", "-e", "ip.dst",
                "-e", "ntlmssp.auth.username",
                "-e", "ntlmssp.auth.domain"),
    )

    entries: list[dict] = []

    # ── Pass 1: HTTP auth + custom headers ────────────────────────────────
    for row in _parse_tsv(http_auth_raw, 9):
        t, src, dst, host, uri, ua, authbasic, auth_hdr, req_lines = row

        if not include_benign_hosts and _is_benign_domain(host):
            continue

        if authbasic and ":" in authbasic:
            user_part, _, pass_part = authbasic.partition(":")
            score, label = _score_credential("BASIC_AUTH", host, dst)
            if score >= min_score:
                entries.append({
                    "kind": "HTTP Basic Auth", "time": t, "client": src, "server": dst,
                    "host": host, "uri": uri, "ua": ua,
                    "details": f"user={user_part!r}  pass={pass_part!r}",
                    "score": score, "label": label,
                })

        elif auth_hdr and not auth_hdr.lower().startswith("basic"):
            bearer_m = _AUTH_BEARER_RE.search(auth_hdr)
            if bearer_m:
                tok = bearer_m.group(1)
                score, label = _score_credential("BEARER", host, dst)
                if score >= min_score:
                    is_jwt = tok.count(".") == 2
                    display = f"Bearer {tok[:40]}…" + ("  [JWT]" if is_jwt else "")
                    entries.append({
                        "kind": "Bearer Token", "time": t, "client": src, "server": dst,
                        "host": host, "uri": uri, "ua": ua,
                        "details": display, "score": score, "label": label,
                    })

        if req_lines:
            m = _CUSTOM_AUTH_RE.search(req_lines)
            if m:
                score, label = _score_credential("CUSTOM_HEADER", host, dst)
                if score >= min_score:
                    entries.append({
                        "kind": "Custom Auth Header", "time": t, "client": src, "server": dst,
                        "host": host, "uri": uri, "ua": ua,
                        "details": m.group(0)[:100], "score": score, "label": label,
                    })

            # Catch malware-style non-standard headers (e.g. "user:", "BuildID:") with
            # token-length values sent to non-whitelisted hosts. These won't start with X-.
            if not _is_benign_domain(host):
                for hm in _MALWARE_TOKEN_HDR_RE.finditer(req_lines):
                    hname = hm.group(1).lower()
                    if hname in _STANDARD_HEADERS or hname.startswith("x-"):
                        continue
                    score, label = _score_credential("CUSTOM_HEADER", host, dst)
                    if score >= min_score:
                        entries.append({
                            "kind": "Malware Auth Header", "time": t, "client": src, "server": dst,
                            "host": host, "uri": uri, "ua": ua,
                            "details": f"{hm.group(1)}: {hm.group(2)[:60]}",
                            "score": score, "label": label,
                        })
                    break  # one entry per request to avoid duplicates

        if uri:
            q_m = _QUERY_TOKEN_RE.search(uri)
            if q_m:
                score, label = _score_credential("QUERY_TOKEN", host, dst)
                if score >= min_score:
                    entries.append({
                        "kind": "Query-String Token", "time": t, "client": src, "server": dst,
                        "host": host, "uri": uri[:100], "ua": ua,
                        "details": f"{q_m.group(0)[:80]}", "score": score, "label": label,
                    })

    # ── Pass 2: URL-encoded form fields ───────────────────────────────────
    for row in _parse_tsv(form_raw, 8):
        t, src, dst, host, uri, ua, keys_raw, vals_raw = row

        if not include_benign_hosts and _is_benign_domain(host):
            continue
        if not keys_raw:
            continue

        keys = [k.strip() for k in keys_raw.split(",")]
        vals = [v.strip() for v in vals_raw.split(",")] if vals_raw else []
        form: dict[str, str] = {k.lower(): (vals[i] if i < len(vals) else "") for i, k in enumerate(keys)}

        pass_keys  = [k for k in form if _PASS_RE.match(k + "=x")]
        user_keys  = [k for k in form if _USER_RE.match(k + "=x")]
        token_keys = [k for k in form if _TOKEN_RE.match(k + "=x")]

        has_pass  = bool(pass_keys)
        has_user  = bool(user_keys)
        has_token = bool(token_keys)

        if not (has_pass or has_token):
            continue

        cred_type = "POST_TOKEN" if (has_token and not has_pass) else "POST_FORM"
        score, label = _score_credential(cred_type, host, dst, has_user=has_user, has_pass=has_pass)
        if score < min_score:
            continue

        parts = []
        for k in user_keys:
            parts.append(f"user={form[k]!r}")
        for k in pass_keys:
            v = form[k]
            parts.append(f"pass={'*' * min(len(v), 8)!r} (len={len(v)})")
        for k in token_keys:
            parts.append(f"token={form[k][:32]}…")

        entries.append({
            "kind": "Form POST", "time": t, "client": src, "server": dst,
            "host": host, "uri": uri, "ua": ua,
            "details": "  ".join(parts), "score": score, "label": label,
        })

    # ── Pass 3: Raw / JSON POST bodies ────────────────────────────────────
    for row in _parse_tsv(post_body_raw, 8):
        t, src, dst, host, uri, ua, file_data_hex, ctype = row

        if not include_benign_hosts and _is_benign_domain(host):
            continue
        if not file_data_hex:
            continue

        body = _decode_file_data(file_data_hex)
        if not body:
            continue

        scan = _scan_post_body(body)
        if not scan:
            continue

        has_pass  = "password" in scan
        has_user  = "user" in scan
        has_token = "token" in scan

        if has_pass or has_user:
            cred_type = "POST_BODY"
        elif has_token:
            cred_type = "POST_TOKEN"
        elif scan.get("b64_creds"):
            cred_type = "B64_CRED"
        else:
            continue

        score, label = _score_credential(cred_type, host, dst, has_user=has_user, has_pass=has_pass)
        if score < min_score:
            continue

        parts = []
        if "user"      in scan: parts.append(f"user={scan['user']!r}")
        if "password"  in scan:
            p = scan["password"]
            parts.append(f"pass={'*'*min(len(p),8)!r} (len={len(p)})")
        if "token"     in scan: parts.append(f"token={scan['token'][:32]}…")
        if "b64_creds" in scan:
            for b in scan["b64_creds"][:2]:
                parts.append(f"b64={b}")

        entries.append({
            "kind": f"POST Body ({ctype.split(';')[0].strip() if ctype else 'raw'})",
            "time": t, "client": src, "server": dst,
            "host": host, "uri": uri, "ua": ua,
            "details": "  ".join(parts), "score": score, "label": label,
        })

    # ── Pass 4: FTP credentials ───────────────────────────────────────────
    ftp_state: dict[str, dict] = {}
    for row in _parse_tsv(ftp_raw, 5):
        t, src, dst, cmd, arg = row
        if not cmd:
            continue
        cmd = cmd.upper()
        key = f"{src}->{dst}"
        if cmd == "USER":
            ftp_state[key] = {"time": t, "src": src, "dst": dst, "user": arg}
        elif cmd == "PASS":
            session = ftp_state.pop(key, {})
            score, label = _score_credential("FTP_PASS", "", dst)
            if score >= min_score:
                user = session.get("user", "?")
                entries.append({
                    "kind": "FTP Credentials", "time": session.get("time", t),
                    "client": src, "server": dst, "host": dst, "uri": "", "ua": "",
                    "details": f"user={user!r}  pass={arg!r}", "score": score, "label": label,
                })

    # Handle orphaned PASS commands
    for row in _parse_tsv(ftp_raw, 5):
        t, src, dst, cmd, arg = row
        if cmd and cmd.upper() == "PASS" and f"{src}->{dst}" not in ftp_state:
            score, label = _score_credential("FTP_PASS", "", dst)
            if score >= min_score:
                entries.append({
                    "kind": "FTP Password", "time": t,
                    "client": src, "server": dst, "host": dst, "uri": "", "ua": "",
                    "details": f"pass={arg!r}", "score": score, "label": label,
                })

    # ── Pass 5: NTLM hashes ───────────────────────────────────────────────
    seen_ntlm: set[str] = set()
    for row in _parse_tsv(ntlm_raw, 5):
        t, src, dst, username, domain = row
        if not username:
            continue
        key = f"{username}@{domain}"
        if key in seen_ntlm:
            continue
        seen_ntlm.add(key)
        score, label = _score_credential("NTLM", "", dst)
        if score >= min_score:
            entries.append({
                "kind": "NTLM Hash", "time": t,
                "client": src, "server": dst, "host": dst, "uri": "", "ua": "",
                "details": f"user={username!r}  domain={domain!r}  [hash — use hashcat -m 5600]",
                "score": score, "label": label,
            })

    # Deduplicate
    seen: dict[str, dict] = {}
    for e in entries:
        dedup_key = f"{e['kind']}|{e['host']}|{e['details'][:40]}"
        if dedup_key not in seen or e["score"] > seen[dedup_key]["score"]:
            seen[dedup_key] = e
    entries = sorted(seen.values(), key=lambda x: (-x["score"], x["time"]))

    return _format_credentials(entries, file_path, min_score, include_benign_hosts)


def _format_credentials(
    entries: list[dict],
    file_path: str,
    min_score: int,
    include_benign: bool,
) -> str:
    w = 66
    total      = len(entries)
    critical   = sum(1 for e in entries if e["score"] == 3)
    suspicious = sum(1 for e in entries if e["score"] == 2)
    notable    = sum(1 for e in entries if e["score"] == 1)

    lines: list[str] = [
        "=" * w,
        "  CREDENTIAL EXTRACTION REPORT",
        f"  File        : {file_path}",
        f"  Found       : {total} entries  "
        f"({critical} critical / {suspicious} suspicious / {notable} notable)",
        f"  Filter      : min_score≥{min_score}"
        + ("  include_benign=True" if include_benign else ""),
        "=" * w,
    ]

    if not entries:
        lines += [
            "", "  No credential material found.", "  Tips:",
            "    • Try include_benign_hosts=True to see all auth traffic",
            "    • Try min_score=0 to see all matches including normal traffic",
            "=" * w,
        ]
        return "\n".join(lines)

    for idx, e in enumerate(entries, 1):
        score = e["score"]
        verdict = {3: "⚠⚠⚠ CRITICAL", 2: "⚠⚠  SUSPICIOUS", 1: "⚠   NOTABLE"}.get(score, "    normal")
        lines += [
            "", f"{'─'*w}",
            f"  #{idx}  [{e['kind']}]  t={e['time']}  {verdict}",
            f"{'─'*w}",
            f"  Server  : {e['server']}" + (f"  ({e['host']})" if e["host"] and e["host"] != e["server"] else ""),
            f"  Client  : {e['client']}",
        ]
        if e["uri"]:
            lines.append(f"  URI     : {e['uri'][:100]}")
        if e["ua"]:
            lines.append(f"  UA      : {e['ua'][:90]}")
        lines.append(f"  Creds   : {e['details'][:120]}")

    lines += ["", "=" * w]
    return "\n".join(lines)
