"""
http_sessions — reconstruct HTTP sessions grouped by server (domain or IP).

Two parallel tshark passes: requests + responses joined on tcp.stream.
Groups unique paths per host, records user agents, server headers, response codes.
Flags suspicious domains, bare-IP servers, and suspicious user agents.
"""
import asyncio
import re
from collections import Counter, defaultdict
from typing import Annotated

from pydantic import Field

from ..server import mcp
from ..core import (
    _tshark, _parse_tsv,
    _is_private, _is_benign_domain, _is_suspicious_tld,
    _SUSPICIOUS_UA_RE, _IP_RE,
)

_SERVER_HEADER_RE = re.compile(r"Server:\s*(.*?)(?:\\r\\n|$)", re.IGNORECASE)

# Cloud C2 URI patterns — match regardless of whether the domain is whitelisted
_TELEGRAM_BOT_RE = re.compile(
    r"/bot[A-Za-z0-9_:]{10,}/(?:getUpdates|sendMessage|sendDocument|sendPhoto"
    r"|sendVideo|sendAudio|sendFile|forwardMessage|copyMessage|answerCallbackQuery)",
    re.IGNORECASE,
)
_DISCORD_WEBHOOK_RE = re.compile(r"/api/webhooks/\d{15,}/[\w-]{20,}", re.IGNORECASE)
_SLACK_WEBHOOK_RE   = re.compile(r"/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+", re.IGNORECASE)

# Cloud domains where we always show the session if UA is suspicious
_CLOUD_INFRA_SUFFIXES: frozenset[str] = frozenset({
    ".amazonaws.com", ".googleapis.com", ".sharepoint.com",
    ".live.com", ".onmicrosoft.com", ".azure.com",
    ".s3.amazonaws.com",
})


@mcp.tool()
async def http_sessions(
    file_path: Annotated[str, Field(description="Absolute path to a .pcap or .pcapng file")],
    domain: Annotated[str, Field(
        description="Partial match on HTTP Host header to filter (e.g. 'example')"
    )] = "",
    target_ip: Annotated[str, Field(
        description="Filter by server IP address (leave empty for all)"
    )] = "",
    exclude_benign: Annotated[bool, Field(
        description="Hide Microsoft/Google/CDN hosts (default: True)"
    )] = True,
    max_paths_per_host: Annotated[int, Field(
        description="Max unique paths to show per host (default: 20)",
        ge=1, le=100,
    )] = 20,
) -> str:
    """
    Reconstruct HTTP sessions grouped by server domain or IP.

    Two parallel tshark passes (requests + responses) joined on tcp.stream.

    For each server/domain shows:
    - Unique request paths (method + URI), capped at max_paths_per_host
    - Unique User-Agent strings observed
    - Server identification header (if present)
    - Response code distribution (200, 302, 404, …)
    - Content-type variety
    - Flags: suspicious TLD, bare-IP server, suspicious user agent

    Use after pcap_summary to map the attack surface before diving into
    extract_iocs or find_downloads.
    """
    # Build tshark filters
    req_filter = "http.request"
    resp_filter = "http.response"
    if target_ip:
        req_filter  += f" && ip.addr == {target_ip}"
        resp_filter += f" && ip.addr == {target_ip}"
    if domain:
        req_filter += f' && http.host contains "{domain}"'

    req_raw, resp_raw = await asyncio.gather(
        _tshark("-r", file_path, "-Y", req_filter, "-T", "fields",
                "-e", "tcp.stream",
                "-e", "frame.time_relative",
                "-e", "ip.src",
                "-e", "ip.dst",
                "-e", "http.host",
                "-e", "http.request.uri",
                "-e", "http.user_agent",
                "-e", "http.request.method"),
        _tshark("-r", file_path, "-Y", resp_filter, "-T", "fields",
                "-e", "tcp.stream",
                "-e", "ip.src",
                "-e", "http.response.code",
                "-e", "http.content_type",
                "-e", "http.response.line"),
    )

    # Build stream → request metadata map
    stream_to_req: dict[str, dict] = {}

    # Per-host session accumulator
    # host key → session dict
    sessions: dict[str, dict] = {}

    def _get_session(key: str) -> dict:
        if key not in sessions:
            sessions[key] = {
                "server_ip":     "",
                "first_seen":    "?",
                "request_count": 0,
                "paths":         [],        # list of {"method": ..., "uri": ...}
                "seen_paths":    set(),
                "user_agents":   set(),
                "response_codes": Counter(),
                "content_types": set(),
                "server_header": "",
            }
        return sessions[key]

    for row in _parse_tsv(req_raw, 8):
        stream, t, src, dst, host, uri, ua, method = row
        if not stream:
            continue

        # Determine host key: prefer Host header, fall back to server IP
        key = host.strip() if host.strip() else dst

        # Skip benign hosts when filtering — BUT always keep:
        #  a) suspicious UAs hitting cloud infra (e.g. PowerShell → SharePoint/S3)
        #  b) cloud C2 URI patterns (Telegram Bot API, Discord webhooks, Slack webhooks)
        _uri_is_cloud_c2 = bool(
            _TELEGRAM_BOT_RE.search(uri or "")
            or _DISCORD_WEBHOOK_RE.search(uri or "")
            or _SLACK_WEBHOOK_RE.search(uri or "")
        )
        _is_susp_ua = bool(ua and _SUSPICIOUS_UA_RE.search(ua))
        _is_cloud_infra = any(key.lower().endswith(s) for s in _CLOUD_INFRA_SUFFIXES)
        if exclude_benign and _is_benign_domain(key):
            if not _uri_is_cloud_c2 and not (_is_susp_ua and _is_cloud_infra):
                continue

        stream_to_req[stream] = {
            "host": key, "host_raw": host, "server_ip": dst,
            "method": method, "uri": uri, "ua": ua, "time": t,
        }

        sess = _get_session(key)
        if sess["first_seen"] == "?":
            sess["first_seen"] = t
        if dst and not sess["server_ip"]:
            sess["server_ip"] = dst
        sess["request_count"] += 1

        path_key = f"{method}\x00{uri}"
        if path_key not in sess["seen_paths"] and len(sess["paths"]) < max_paths_per_host:
            sess["seen_paths"].add(path_key)
            sess["paths"].append({"method": method or "?", "uri": uri or "/"})

        if ua:
            sess["user_agents"].add(ua)

    # Join responses
    for row in _parse_tsv(resp_raw, 5):
        stream, server_ip, code, content_type, resp_lines = row
        req = stream_to_req.get(stream)
        if not req:
            continue
        key = req["host"]
        if key not in sessions:
            continue
        sess = sessions[key]
        if code:
            sess["response_codes"][code] += 1
        if content_type:
            ct = content_type.split(";")[0].strip()
            if ct:
                sess["content_types"].add(ct)
        if resp_lines and not sess["server_header"]:
            m = _SERVER_HEADER_RE.search(resp_lines)
            if m:
                sess["server_header"] = m.group(1).strip()

    if not sessions:
        tip = " Try exclude_benign=False to include CDN/Microsoft/Google traffic." if exclude_benign else ""
        return f"No HTTP sessions found in {file_path}.{tip}"

    return _format_http_sessions(sessions, file_path, exclude_benign, max_paths_per_host)


def _flag_host(host: str, server_ip: str, user_agents: set, paths: list | None = None) -> list[str]:
    flags: list[str] = []
    if _IP_RE.fullmatch(host.strip()):
        flags.append("BARE_IP_HOST")
    elif _is_suspicious_tld(host):
        flags.append("SUSPICIOUS_TLD")
    elif not _is_benign_domain(host):
        flags.append("NON_WHITELISTED")
    if any(_SUSPICIOUS_UA_RE.search(ua) for ua in user_agents):
        flags.append("SUSPICIOUS_UA")

    # Cloud C2 URI patterns in the recorded paths
    for p in (paths or []):
        uri = p.get("uri", "")
        if _TELEGRAM_BOT_RE.search(uri):
            flags.append("TELEGRAM_BOT_API")
            break
        if _DISCORD_WEBHOOK_RE.search(uri):
            flags.append("DISCORD_WEBHOOK")
            break
        if _SLACK_WEBHOOK_RE.search(uri):
            flags.append("SLACK_WEBHOOK")
            break

    # Suspicious UA hitting whitelisted cloud infra = possible cloud exfil
    if _is_benign_domain(host) and any(_SUSPICIOUS_UA_RE.search(ua) for ua in user_agents):
        if any(host.lower().endswith(s) for s in _CLOUD_INFRA_SUFFIXES):
            flags.append("CLOUD_EXFIL_CANDIDATE")

    return flags


def _format_http_sessions(
    sessions: dict,
    file_path: str,
    exclude_benign: bool,
    max_paths: int,
) -> str:
    # Sort: suspicious hosts first, then by request count
    def _sort_key(item: tuple) -> tuple:
        host, sess = item
        flags = _flag_host(host, sess["server_ip"], sess["user_agents"], sess["paths"])
        return (not bool(flags), -sess["request_count"])

    sorted_sessions = sorted(sessions.items(), key=_sort_key)

    w = 70
    lines: list[str] = [
        "=" * w,
        "  HTTP SESSION MAP",
        f"  File           : {file_path}",
        f"  Unique servers : {len(sessions)}",
        f"  Benign filter  : {'ON' if exclude_benign else 'OFF'}",
        "=" * w,
    ]

    for host, sess in sorted_sessions:
        flags    = _flag_host(host, sess["server_ip"], sess["user_agents"], sess["paths"])
        flag_str = "  [" + " | ".join(flags) + "]" if flags else ""
        marker   = "⚠ " if flags else "  "

        lines += [
            "",
            f"{'─'*w}",
            f"  {marker}{host}{flag_str}",
            f"{'─'*w}",
            f"  Server IP  : {sess['server_ip']}",
            f"  First seen : {sess['first_seen']}",
            f"  Requests   : {sess['request_count']}",
        ]

        if sess["server_header"]:
            lines.append(f"  Server hdr : {sess['server_header'][:80]}")

        # Response code summary
        if sess["response_codes"]:
            code_summary = "  ".join(
                f"{code}×{cnt}"
                for code, cnt in sorted(sess["response_codes"].items())
            )
            lines.append(f"  Resp codes : {code_summary}")

        # Content types
        if sess["content_types"]:
            cts = ", ".join(sorted(sess["content_types"])[:6])
            lines.append(f"  Cont-Types : {cts}")

        # User agents
        for ua in sorted(sess["user_agents"])[:3]:
            susp = "⚠ " if _SUSPICIOUS_UA_RE.search(ua) else "  "
            lines.append(f"  UA{susp}      : {ua[:100]}")
        if len(sess["user_agents"]) > 3:
            lines.append(f"             … +{len(sess['user_agents']) - 3} more user agents")

        # Paths
        lines.append(f"  Paths ({len(sess['paths'])} unique{'+' if len(sess['seen_paths']) >= max_paths else ''}):")
        for p in sess["paths"]:
            lines.append(f"    {p['method']:<8} {p['uri'][:90]}")

    lines += ["", "=" * w]
    return "\n".join(lines)
