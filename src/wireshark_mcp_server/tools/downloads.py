"""find_downloads — HTTP + HTTPS-estimate download detection."""
import asyncio
import re
from collections import defaultdict
from typing import Annotated

from pydantic import Field

from ..server import mcp
from ..core import (
    _tshark, _parse_tsv,
    _is_private, _is_benign_domain, _is_suspicious_tld,
    _human_bytes, _SUSPICIOUS_UA_RE, _IP_RE,
)

# ---------------------------------------------------------------------------
# Content-type maps and constants
# ---------------------------------------------------------------------------

_CT_TO_EXT: dict[str, str] = {
    "application/zip":                                    ".zip",
    "application/x-zip":                                  ".zip",
    "application/x-zip-compressed":                       ".zip",
    "application/octet-stream":                           ".bin",
    "application/x-msdownload":                           ".exe",
    "application/x-dosexec":                              ".exe",
    "application/vnd.microsoft.portable-executable":      ".exe",
    "application/x-msdos-program":                        ".exe",
    "application/x-sh":                                   ".sh",
    "application/x-powershell":                           ".ps1",
    "text/x-powershell":                                  ".ps1",
    "application/pdf":                                    ".pdf",
    "application/msword":                                 ".doc",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx",
    "application/vnd.ms-excel":                           ".xls",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": ".xlsx",
    "application/x-rar-compressed":                       ".rar",
    "application/x-7z-compressed":                        ".7z",
    "application/x-tar":                                  ".tar",
    "application/gzip":                                   ".gz",
    "application/java-archive":                           ".jar",
    "application/x-chrome-extension":                     ".crx",
    "application/x-shockwave-flash":                      ".swf",
    "text/plain":                                         ".txt",
    "text/html":                                          ".html",
    "image/png":                                          ".png",
    "image/jpeg":                                         ".jpg",
    "image/gif":                                          ".gif",
}

_DROPPER_TYPES: frozenset[str] = frozenset({
    "application/zip", "application/x-zip", "application/x-zip-compressed",
    "application/octet-stream", "application/x-msdownload", "application/x-dosexec",
    "application/vnd.microsoft.portable-executable", "application/x-msdos-program",
    "application/x-sh", "application/x-powershell", "text/x-powershell",
    "application/x-rar-compressed", "application/x-7z-compressed",
    "application/java-archive",
})

_CD_FILENAME_RE = re.compile(
    r"filename\*?=(?:UTF-8''|\")?([^\";\r\n\\]+)", re.IGNORECASE
)
# tshark outputs response header lines with literal \r\n escape sequences
_CD_HEADER_RE = re.compile(r"Content-Disposition:\s*(.*?)(?:\\r\\n|$)", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_filename(content_disposition: str, uri: str, content_type: str) -> str:
    if content_disposition:
        m = _CD_FILENAME_RE.search(content_disposition)
        if m:
            name = m.group(1).strip().strip('"\'')
            if name:
                return name
    if uri:
        segment = uri.split("?")[0].rstrip("/").split("/")[-1]
        if segment and "." in segment and len(segment) < 120:
            return segment
    if content_type:
        ct = content_type.split(";")[0].strip().lower()
        ext = _CT_TO_EXT.get(ct, "")
        if ext:
            return f"[unnamed]{ext}"
    return "[unnamed]"


def _score_download(
    content_type: str,
    content_disposition: str,
    ua: str,
    host: str,
    server_ip: str,
    is_https_estimate: bool,
) -> tuple[int, list[str]]:
    score = 0
    flags: list[str] = []
    ct = (content_type or "").split(";")[0].strip().lower()
    if ct in _DROPPER_TYPES:
        score += 1
        flags.append("DROPPER_CONTENT_TYPE")
    if content_disposition and "attachment" in content_disposition.lower():
        score += 1
        flags.append("FORCED_DOWNLOAD")
    if ua and _SUSPICIOUS_UA_RE.search(ua):
        score += 1
        flags.append("SUSPICIOUS_UA")
    if server_ip and not host:
        score += 1
        flags.append("BARE_IP_SERVER")
    if host and _is_suspicious_tld(host):
        score += 1
        flags.append("SUSPICIOUS_TLD")
    if host and not _is_benign_domain(host):
        score += 1
        flags.append("NON_WHITELISTED_DOMAIN")
    if is_https_estimate:
        flags.append("HTTPS_ESTIMATE")
    return score, flags


# ---------------------------------------------------------------------------
# Tool
# ---------------------------------------------------------------------------

@mcp.tool()
async def find_downloads(
    file_path: Annotated[str, Field(description="Absolute path to a .pcap or .pcapng file")],
    target_ip: Annotated[str, Field(
        description="Filter by server IP address (leave empty for all)"
    )] = "",
    domain: Annotated[str, Field(
        description="Partial match on HTTP Host header (e.g. 'northernbridgeworks')"
    )] = "",
    user_agent: Annotated[str, Field(
        description="Partial match on User-Agent string (e.g. 'powershell')"
    )] = "",
    min_size_bytes: Annotated[int, Field(
        description="Minimum file size to report in bytes (default: 1024 = 1KB)",
        ge=0,
    )] = 1024,
    include_https_estimates: Annotated[bool, Field(
        description="Also detect large HTTPS transfers where headers are encrypted (default: True)"
    )] = True,
    suspicious_only: Annotated[bool, Field(
        description="Only show downloads with at least one suspicious flag"
    )] = False,
) -> str:
    """
    Detect and analyze file downloads AND large outbound uploads (exfil) from a pcap.

    Joins HTTP request + response by tcp.stream to produce complete download records.
    Extracts filename from Content-Disposition, URI path, or Content-Type mapping.
    Scores each download for suspiciousness: dropper content types, PowerShell UA,
    bare-IP servers, forced attachments, suspicious TLDs.

    Also detects:
    - Large HTTPS transfers (>1MB inbound) from non-whitelisted domains as likely
      encrypted downloads.
    - Large HTTP POST uploads (≥100KB) to non-whitelisted hosts as exfil candidates.

    Filters: combine target_ip, domain, user_agent to narrow results.
    """
    ip_filter = f"ip.addr == {target_ip}" if target_ip else ""

    req_parts = ["http.request"]
    if ip_filter:
        req_parts.append(ip_filter)
    if domain:
        req_parts.append(f'http.host contains "{domain}"')
    req_filter = " && ".join(req_parts)

    resp_parts = ["http.response"]
    if ip_filter:
        resp_parts.append(ip_filter)
    resp_filter = " && ".join(resp_parts)

    gather_args = [
        _tshark("-r", file_path, "-Y", req_filter, "-T", "fields",
                "-e", "tcp.stream",
                "-e", "frame.time_relative",
                "-e", "ip.src", "-e", "ip.dst",
                "-e", "http.host",
                "-e", "http.request.uri",
                "-e", "http.user_agent"),
        _tshark("-r", file_path, "-Y", resp_filter, "-T", "fields",
                "-e", "tcp.stream",
                "-e", "ip.src", "-e", "ip.dst",
                "-e", "http.response.code",
                "-e", "http.content_type",
                "-e", "http.content_length_header",
                "-e", "http.response.line"),
    ]

    # Pass: detect large HTTP POST uploads (exfil candidates)
    upload_parts = ['http.request.method == "POST" && http.content_length >= 102400']
    if ip_filter:
        upload_parts.append(ip_filter)
    if domain:
        upload_parts.append(f'http.host contains "{domain}"')
    gather_args.append(
        _tshark("-r", file_path, "-Y", " && ".join(upload_parts), "-T", "fields",
                "-e", "frame.time_relative",
                "-e", "ip.src", "-e", "ip.dst",
                "-e", "http.host",
                "-e", "http.request.uri",
                "-e", "http.user_agent",
                "-e", "http.content_length",
                "-e", "http.content_type")
    )

    if include_https_estimates:
        inbound_filter = "tcp && ip.dst != 255.255.255.255"
        if target_ip:
            inbound_filter = f"ip.src == {target_ip} && ip.dst != 255.255.255.255"
        gather_args.append(
            _tshark("-r", file_path, "-Y", inbound_filter, "-T", "fields",
                    "-e", "tcp.stream",
                    "-e", "ip.src", "-e", "ip.dst",
                    "-e", "frame.len",
                    "-e", "frame.time_relative")
        )
        gather_args.append(
            _tshark("-r", file_path, "-Y", "tls.handshake.type == 1",
                    "-T", "fields",
                    "-e", "tcp.stream",
                    "-e", "ip.dst",
                    "-e", "tls.handshake.extensions_server_name")
        )

    results_raw = await asyncio.gather(*gather_args)
    req_raw, resp_raw = results_raw[0], results_raw[1]
    upload_raw = results_raw[2]
    tcp_raw = results_raw[3] if include_https_estimates else ""
    tls_raw = results_raw[4] if include_https_estimates else ""

    # Parse requests: stream_id → request info
    stream_to_req: dict[str, dict] = {}
    for row in _parse_tsv(req_raw, 7):
        stream, rel_time, src, dst, host, uri, ua = row
        if not stream:
            continue
        if user_agent and not re.search(user_agent, ua or "", re.IGNORECASE):
            continue
        stream_to_req[stream] = {
            "time_rel": rel_time, "client_ip": src, "server_ip": dst,
            "host": host, "uri": uri, "user_agent": ua,
        }

    # Parse responses: join to request by stream
    http_downloads: list[dict] = []
    seen_streams: set[str] = set()

    for row in _parse_tsv(resp_raw, 7):
        stream, server_ip, client_ip, code, content_type, content_len, resp_lines = row
        if not stream or stream in seen_streams:
            continue
        seen_streams.add(stream)

        content_disp = ""
        if resp_lines:
            m = _CD_HEADER_RE.search(resp_lines)
            if m:
                content_disp = m.group(1).strip()

        try:
            size = int(content_len.strip()) if content_len and content_len.strip() else 0
        except ValueError:
            size = 0

        if size < min_size_bytes and size != 0:
            continue
        if code and code not in ("200", "206"):
            continue
        if size == 0 and content_len.strip() == "0":
            continue

        req = stream_to_req.get(stream, {})
        if user_agent and not req:
            continue

        host      = req.get("host", "")
        uri       = req.get("uri", "")
        ua        = req.get("user_agent", "")
        rel_time  = req.get("time_rel", "?")
        client_ip = req.get("client_ip", client_ip)

        if domain and domain.lower() not in (host or "").lower():
            continue

        filename = _extract_filename(content_disp, uri, content_type)
        score, flags = _score_download(content_type, content_disp, ua, host, server_ip, False)

        if suspicious_only and score == 0:
            continue

        http_downloads.append({
            "kind": "HTTP", "time_rel": rel_time, "filename": filename,
            "content_type": content_type or "unknown", "size_bytes": size,
            "response_code": code,
            "url": f"http://{host}{uri}" if host else uri,
            "server_ip": server_ip, "host": host, "client_ip": client_ip,
            "user_agent": ua, "content_disposition": content_disp,
            "score": score, "flags": flags, "stream": stream,
        })

    http_downloads.sort(key=lambda x: (-x["score"], -x["size_bytes"]))

    # HTTP large-upload / exfil candidates
    upload_detections: list[dict] = []
    for row in _parse_tsv(upload_raw, 8):
        t, src, dst, host, uri, ua, content_len, ctype = row
        if not content_len:
            continue
        try:
            size = int(content_len.strip())
        except ValueError:
            continue
        if size < min_size_bytes:
            continue
        if _is_benign_domain(host):
            continue
        if user_agent and not re.search(user_agent, ua or "", re.IGNORECASE):
            continue
        if domain and domain.lower() not in (host or "").lower():
            continue

        flags: list[str] = ["LARGE_POST_UPLOAD"]
        if not host or _IP_RE.fullmatch(host.strip()):
            flags.append("BARE_IP_SERVER")
        if host and _is_suspicious_tld(host):
            flags.append("SUSPICIOUS_TLD")
        score = len(flags)

        if suspicious_only and score == 0:
            continue

        upload_detections.append({
            "kind": "HTTP_UPLOAD", "time_rel": t,
            "filename": f"[outbound POST — {ctype or 'unknown'}]",
            "content_type": ctype or "unknown", "size_bytes": size,
            "response_code": "—",
            "url": f"http://{host}{uri}" if host else uri,
            "server_ip": dst, "host": host, "client_ip": src,
            "user_agent": ua, "content_disposition": "",
            "score": score, "flags": flags, "stream": "",
        })

    upload_detections.sort(key=lambda x: (-x["score"], -x["size_bytes"]))

    # HTTPS large-transfer estimates
    https_estimates: list[dict] = []

    if include_https_estimates and tcp_raw and tls_raw:
        stream_sni: dict[str, str] = {}
        stream_dst: dict[str, str] = {}
        for row in _parse_tsv(tls_raw, 3):
            stream, dst_ip, sni = row
            if stream:
                stream_sni[stream] = sni
                stream_dst[stream] = dst_ip

        stream_inbound: dict[str, int]     = defaultdict(int)
        stream_times:   dict[str, str]     = {}
        stream_ips:     dict[str, set[str]] = defaultdict(set)

        for row in _parse_tsv(tcp_raw, 5):
            stream, src_ip, dst_ip, length, rel_time = row
            if not stream or not length:
                continue
            try:
                stream_inbound[stream] += int(length)
            except ValueError:
                pass
            if src_ip:
                stream_ips[stream].add(src_ip)
            if dst_ip:
                stream_ips[stream].add(dst_ip)
            if stream not in stream_times:
                stream_times[stream] = rel_time

        for stream, total_bytes in stream_inbound.items():
            if total_bytes < max(min_size_bytes, 1024 * 1024):
                continue
            ips       = stream_ips.get(stream, set())
            ext_ips   = [ip for ip in ips if not _is_private(ip)]
            int_ips   = [ip for ip in ips if _is_private(ip)]
            server_ip = ext_ips[0] if ext_ips else ""
            client_ip = int_ips[0] if int_ips else ""
            sni       = stream_sni.get(stream, "")
            rel_time  = stream_times.get(stream, "?")

            if not server_ip or _is_private(server_ip):
                continue
            if stream in seen_streams:
                continue
            if target_ip and server_ip != target_ip:
                continue
            if domain and domain.lower() not in (sni or "").lower():
                continue

            score, flags = _score_download("", "", "", sni, server_ip, True)
            if suspicious_only and score == 0:
                continue
            if _is_benign_domain(sni) and score == 0:
                continue

            https_estimates.append({
                "kind": "HTTPS_ESTIMATE", "time_rel": rel_time,
                "filename": "[encrypted — cannot determine]",
                "content_type": "unknown (TLS)", "size_bytes": total_bytes,
                "url": f"https://{sni}" if sni else f"https://{server_ip}",
                "server_ip": server_ip, "host": sni, "client_ip": client_ip,
                "user_agent": "", "score": score, "flags": flags, "stream": stream,
            })

        https_estimates.sort(key=lambda x: (-x["score"], -x["size_bytes"]))

    all_downloads = http_downloads + upload_detections + https_estimates

    if not all_downloads:
        filters_used = []
        if target_ip:   filters_used.append(f"ip={target_ip}")
        if domain:      filters_used.append(f"domain={domain}")
        if user_agent:  filters_used.append(f"ua={user_agent}")
        fstr = f" with filters ({', '.join(filters_used)})" if filters_used else ""
        return f"No downloads found{fstr} in {file_path}"

    return _format_downloads(all_downloads, file_path, target_ip, domain, user_agent, min_size_bytes)


def _format_downloads(
    downloads: list[dict],
    file_path: str,
    target_ip: str,
    domain: str,
    user_agent: str,
    min_size: int,
) -> str:
    lines: list[str] = [
        "=" * 66,
        "  FILE DOWNLOADS & EXFIL REPORT",
        f"  File        : {file_path}",
    ]
    filters = []
    if target_ip:   filters.append(f"server_ip={target_ip}")
    if domain:      filters.append(f"domain contains '{domain}'")
    if user_agent:  filters.append(f"ua contains '{user_agent}'")
    if min_size:    filters.append(f"min_size={_human_bytes(min_size)}")
    if filters:
        lines.append(f"  Filters     : {' | '.join(filters)}")

    susp   = sum(1 for d in downloads if d["score"] >= 2)
    notable = sum(1 for d in downloads if d["score"] == 1)
    lines += [
        f"  Found       : {len(downloads)} downloads  "
        f"({susp} suspicious / {notable} notable / "
        f"{len(downloads)-susp-notable} normal)",
        "=" * 66,
    ]

    for idx, dl in enumerate(downloads, 1):
        score = dl["score"]
        verdict = {True: "⚠⚠ SUSPICIOUS"}.get(score >= 2, "⚠  NOTABLE" if score == 1 else "   normal")
        if dl["kind"] == "HTTPS_ESTIMATE":
            kind_label = "HTTPS (estimate)"
        elif dl["kind"] == "HTTP_UPLOAD":
            kind_label = "HTTP UPLOAD (exfil?)"
        else:
            kind_label = "HTTP"

        lines += [
            "", f"{'─'*66}",
            f"  #{idx}  [{kind_label}]  t={dl['time_rel']}  {verdict}",
            f"{'─'*66}",
            f"  Filename  : {dl['filename']}",
            f"  Type      : {dl['content_type']}",
            f"  Size      : {_human_bytes(dl['size_bytes'])}",
            f"  URL       : {dl['url'][:100]}",
            f"  Server    : {dl['server_ip']}"
            + (f"  ({dl['host']})" if dl["host"] and dl["host"] != dl["server_ip"] else ""),
            f"  Client    : {dl['client_ip']}",
        ]
        if dl["user_agent"]:
            lines.append(f"  UA        : {dl['user_agent'][:100]}")
        if dl.get("content_disposition"):
            lines.append(f"  Disposition: {dl['content_disposition'][:100]}")
        if dl["flags"]:
            lines.append(f"  Flags     : {' | '.join(dl['flags'])}")

    lines += ["", "=" * 66]
    return "\n".join(lines)
