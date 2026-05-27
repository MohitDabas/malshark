"""extract_iocs — 6 parallel tshark passes, IOC report formatter."""
import asyncio
import json
import re
from collections import defaultdict
from typing import Annotated

from pydantic import Field

from ..server import mcp
from ..core import (
    _tshark, _parse_tsv,
    _is_private, _is_benign_domain, _is_suspicious_tld,
    _decode_file_data, _scan_payload,
    _DROPPER_CT, _IP_RE, _SUSPICIOUS_UA_RE,
)

# tshark field lists for each pass
_IP_FIELDS = ["-e", "ip.src", "-e", "ip.dst"]
_DNS_FIELDS = ["-e", "frame.time_relative", "-e", "dns.qry.name"]
_HTTP_REQ_FIELDS = [
    "-e", "frame.time_relative",
    "-e", "ip.src", "-e", "ip.dst",
    "-e", "http.request.method",
    "-e", "http.host",
    "-e", "http.request.uri",
    "-e", "http.user_agent",
]
_HTTP_RESP_FIELDS = [
    "-e", "ip.src", "-e", "ip.dst",
    "-e", "http.response.code",
    "-e", "http.content_type",
    "-e", "http.content_length",
    "-e", "http.file_data",
]
_TLS_FIELDS = [
    "-e", "ip.dst",
    "-e", "tcp.dstport",
    "-e", "tls.handshake.extensions_server_name",
]
_C2_ON_443_FILTER = (
    # tcp.len > 0 excludes handshake-only packets (SYN/ACK with no payload)
    # which were previously causing 4-5x inflated false-positive counts.
    "tcp.dstport == 443 && !tls && !ssl && !quic && tcp.len > 0 "
    "&& !(ip.dst == 10.0.0.0/8) "
    "&& !(ip.dst == 172.16.0.0/12) "
    "&& !(ip.dst == 192.168.0.0/16)"
)

# Detect C2 servers that are down/unreachable — many SYN attempts with no established session.
# e.g. NetSupport RAT C2 that didn't respond during capture.
_SYN_ONLY_443_FILTER = (
    "tcp.dstport == 443 && tcp.flags.syn == 1 && tcp.flags.ack == 0 "
    "&& !(ip.dst == 10.0.0.0/8) "
    "&& !(ip.dst == 172.16.0.0/12) "
    "&& !(ip.dst == 192.168.0.0/16)"
)
_SYN_ONLY_MIN_COUNT = 5  # require ≥5 SYN packets to avoid ephemeral noise


@mcp.tool()
async def extract_iocs(
    file_path: Annotated[str, Field(description="Absolute path to a .pcap or .pcapng file")],
    exclude_benign: Annotated[bool, Field(
        description="Filter out known-good Microsoft/Google/CDN traffic (default: True)"
    )] = True,
    output_format: Annotated[str, Field(
        description="'text' for a readable report, 'json' for raw structured data"
    )] = "text",
) -> str:
    """
    Extract all Indicators of Compromise (IOCs) from a pcap in parallel tshark passes.

    Covers:
    - All external IPs with packet counts
    - Suspicious DNS queries (unusual TLDs, non-whitelisted domains)
    - HTTP requests: PowerShell/tool User-Agents, bare-IP hosts, dropper downloads
    - TLS connections with NO SNI (possible custom C2 protocol)
    - Embedded IOCs inside HTTP response bodies (IPs, URLs, PowerShell patterns)
    """
    (
        ip_raw,
        dns_raw,
        http_req_raw,
        http_resp_raw,
        tls_raw,
        c2_443_raw,
        syn_only_raw,
    ) = await asyncio.gather(
        _tshark("-r", file_path, "-T", "fields", *_IP_FIELDS),
        _tshark("-r", file_path, "-Y", "dns.flags.response == 0",
                "-T", "fields", *_DNS_FIELDS),
        _tshark("-r", file_path, "-Y", "http.request",
                "-T", "fields", *_HTTP_REQ_FIELDS),
        _tshark("-r", file_path, "-Y", "http.response",
                "-T", "fields", *_HTTP_RESP_FIELDS),
        _tshark("-r", file_path,
                "-Y", "tls.handshake.type == 1 || ssl.handshake.type == 1",
                "-T", "fields", *_TLS_FIELDS),
        _tshark("-r", file_path, "-Y", _C2_ON_443_FILTER,
                "-T", "fields", "-e", "ip.dst"),
        _tshark("-r", file_path, "-Y", _SYN_ONLY_443_FILTER,
                "-T", "fields", "-e", "ip.dst"),
    )

    # Parse IP pass → victim + external IP counts
    dst_counts: dict[str, int] = defaultdict(int)
    src_counts: dict[str, int] = defaultdict(int)
    for src, dst in _parse_tsv(ip_raw, 2):
        if src:
            src_counts[src] += 1
        if dst:
            dst_counts[dst] += 1

    victim_ip = max(
        (ip for ip in src_counts if _is_private(ip)),
        key=lambda ip: src_counts[ip],
        default="unknown",
    )
    external_ips = sorted(
        ((ip, cnt) for ip, cnt in dst_counts.items() if not _is_private(ip)),
        key=lambda x: x[1],
        reverse=True,
    )

    # Parse DNS
    dns_iocs: list[dict] = []
    seen_domains: set[str] = set()
    for rel_time, domain in _parse_tsv(dns_raw, 2):
        if not domain or domain in seen_domains:
            continue
        seen_domains.add(domain)
        benign = _is_benign_domain(domain)
        if exclude_benign and benign:
            continue
        flags: list[str] = []
        if not benign:
            flags.append("SUSPICIOUS")
        if _is_suspicious_tld(domain):
            flags.append("suspicious_tld")
        dns_iocs.append({
            "domain": domain,
            "first_seen_rel": rel_time,
            "flags": flags,
            "benign": benign,
        })

    # Parse HTTP requests
    http_req_iocs: list[dict] = []
    last_req_by_dst: dict[str, str] = {}
    ua_inventory: dict[str, set[str]] = defaultdict(set)

    for row in _parse_tsv(http_req_raw, 7):
        rel_time, src, dst, method, host, uri, ua = row
        if not method:
            continue
        flags = []
        if host and _IP_RE.fullmatch(host.strip()):
            flags.append("BARE_IP_HOST")
        if ua and _SUSPICIOUS_UA_RE.search(ua):
            flags.append("SUSPICIOUS_UA")
        if ua:
            ua_inventory[ua].add(src)
        last_req_by_dst[dst] = uri
        if flags or not exclude_benign:
            http_req_iocs.append({
                "time_rel": rel_time, "src": src, "dst": dst,
                "method": method, "host": host, "uri": uri,
                "user_agent": ua, "flags": flags,
            })

    ua_report: list[dict] = sorted(
        [
            {
                "user_agent": ua,
                "seen_from": sorted(ips),
                "suspicious": bool(_SUSPICIOUS_UA_RE.search(ua)),
            }
            for ua, ips in ua_inventory.items()
        ],
        key=lambda x: (not x["suspicious"], x["user_agent"]),
    )

    # Parse HTTP responses
    http_resp_iocs: list[dict] = []
    payload_iocs: list[dict] = []

    for row in _parse_tsv(http_resp_raw, 6):
        src, dst, code, content_type, content_len, file_data = row
        resp_flags: list[str] = []
        ct_lower = content_type.lower() if content_type else ""
        if any(ct in ct_lower for ct in _DROPPER_CT):
            resp_flags.append(f"DROPPER:{content_type}")
        if resp_flags:
            uri = last_req_by_dst.get(dst, "/")
            http_resp_iocs.append({
                "server_ip": src, "client_ip": dst,
                "response_code": code, "content_type": content_type,
                "content_length": content_len, "uri": uri, "flags": resp_flags,
            })
        if file_data and len(file_data) < 20000:
            decoded = _decode_file_data(file_data)
            if decoded:
                uri = last_req_by_dst.get(dst, "/")
                ioc = _scan_payload(decoded, src, uri)
                if ioc:
                    payload_iocs.append(ioc)

    # Parse TLS (SNI)
    tls_seen: dict[str, dict] = {}
    for dst_ip, dstport, sni in _parse_tsv(tls_raw, 3):
        if not dst_ip or _is_private(dst_ip):
            continue
        key = f"{dst_ip}:{dstport}"
        if key not in tls_seen:
            flags = []
            if not sni:
                flags.append("NO_SNI")
            elif not _is_benign_domain(sni):
                flags.append("SUSPICIOUS_DOMAIN")
            tls_seen[key] = {
                "ip": dst_ip, "port": dstport, "sni": sni or "",
                "count": 1, "flags": flags,
            }
        else:
            tls_seen[key]["count"] += 1
            if sni and not tls_seen[key]["sni"]:
                tls_seen[key]["sni"] = sni
    tls_iocs = sorted(
        [v for v in tls_seen.values() if v["flags"]],
        key=lambda x: x["count"],
        reverse=True,
    )

    # Build SNI→IP map from TLS pass so we can exclude benign IPs from C2-443
    # (e.g. Microsoft Update IPs that have some non-TLS payload packets)
    benign_sni_ips: set[str] = set()
    for dst_ip, _, sni in _parse_tsv(tls_raw, 3):
        if sni and _is_benign_domain(sni):
            benign_sni_ips.add(dst_ip)

    # Parse C2-on-443 — exclude IPs that have a confirmed benign SNI in TLS
    c2_on_443: dict[str, int] = defaultdict(int)
    for (dst_ip,) in _parse_tsv(c2_443_raw, 1):
        if dst_ip and not _is_private(dst_ip) and dst_ip not in benign_sni_ips:
            c2_on_443[dst_ip] += 1
    c2_on_443_list = sorted(c2_on_443.items(), key=lambda x: x[1], reverse=True)

    # Parse SYN-only pass — detect unreachable C2 servers (many SYN, no established session)
    syn_only_counts: dict[str, int] = defaultdict(int)
    for (dst_ip,) in _parse_tsv(syn_only_raw, 1):
        if dst_ip and not _is_private(dst_ip):
            syn_only_counts[dst_ip] += 1
    # Only report IPs with ≥ threshold SYNs AND no matching active non-TLS session
    c2_unreachable_list = sorted(
        [
            (ip, cnt) for ip, cnt in syn_only_counts.items()
            if cnt >= _SYN_ONLY_MIN_COUNT
            and ip not in {ip for ip, _ in c2_on_443_list}
            and ip not in benign_sni_ips
        ],
        key=lambda x: x[1],
        reverse=True,
    )

    result = {
        "file": file_path,
        "victim_ip": victim_ip,
        "external_ips": [{"ip": ip, "packets": cnt} for ip, cnt in external_ips[:30]],
        "dns_iocs": dns_iocs,
        "http_request_iocs": http_req_iocs,
        "http_response_iocs": http_resp_iocs,
        "user_agents": ua_report,
        "tls_iocs": tls_iocs,
        "c2_on_443": [{"ip": ip, "packets": cnt} for ip, cnt in c2_on_443_list],
        "c2_unreachable": [{"ip": ip, "syn_count": cnt} for ip, cnt in c2_unreachable_list],
        "payload_iocs": payload_iocs,
    }

    if output_format == "json":
        return json.dumps(result, indent=2)
    return _format_ioc_report(result)


def _format_ioc_report(r: dict) -> str:
    lines: list[str] = [
        "=" * 62,
        "  IOC EXTRACTION REPORT",
        f"  File   : {r['file']}",
        f"  Victim : {r['victim_ip']}",
        "=" * 62,
    ]

    if r["external_ips"]:
        lines += ["", f"[IPs]  {len(r['external_ips'])} external IPs contacted"]
        for e in r["external_ips"]:
            lines.append(f"  {e['ip']:<22} {e['packets']} pkts")

    if r["dns_iocs"]:
        susp = [d for d in r["dns_iocs"] if d["flags"]]
        lines += ["", f"[DNS]  {len(r['dns_iocs'])} domains queried  ({len(susp)} flagged)"]
        for d in r["dns_iocs"]:
            flag_str = " ".join(d["flags"]) if d["flags"] else ""
            lines.append(
                f"  {'⚠ ' if d['flags'] else '  '}"
                f"{d['domain']:<42} t={d['first_seen_rel']:<8}  {flag_str}"
            )

    if r["http_request_iocs"]:
        lines += ["", f"[HTTP-REQ]  {len(r['http_request_iocs'])} suspicious requests"]
        for req in r["http_request_iocs"]:
            url = f"http://{req['host']}{req['uri']}" if req["host"] else req["uri"]
            lines.append(f"  [{req['method']}] {url}")
            if req["user_agent"]:
                lines.append(f"       UA  : {req['user_agent'][:90]}")
            lines.append(f"       FLAGS: {' | '.join(req['flags'])}")

    if r.get("user_agents"):
        susp_uas = [u for u in r["user_agents"] if u["suspicious"]]
        normal_uas = [u for u in r["user_agents"] if not u["suspicious"]]
        lines += [
            "",
            f"[USER AGENTS]  {len(r['user_agents'])} unique  "
            f"({len(susp_uas)} suspicious / {len(normal_uas)} normal)",
        ]
        for entry in r["user_agents"]:
            marker = "⚠ " if entry["suspicious"] else "  "
            label  = "SUSPICIOUS" if entry["suspicious"] else "normal"
            lines.append(f"  {marker}[{label}]  {entry['user_agent'][:100]}")
            lines.append(f"       from: {', '.join(entry['seen_from'])}")

    if r["http_response_iocs"]:
        lines += ["", f"[HTTP-RESP]  {len(r['http_response_iocs'])} dropper/suspicious responses"]
        for resp in r["http_response_iocs"]:
            lines.append(
                f"  {resp['server_ip']}  HTTP {resp['response_code']}  "
                f"{resp['content_type']}  len={resp['content_length']}"
            )
            lines.append(f"       URI   : {resp['uri']}")
            lines.append(f"       FLAGS : {' | '.join(resp['flags'])}")

    if r["tls_iocs"]:
        lines += ["", f"[TLS]  {len(r['tls_iocs'])} suspicious TLS connections"]
        for t in r["tls_iocs"]:
            lines.append(
                f"  {t['ip']:<22} :{t['port']:<6} "
                f"sni={t['sni'] or 'NONE':<30} pkts={t['count']}  "
                + " ".join(t["flags"])
            )

    if r["c2_on_443"]:
        lines += ["", f"[C2-443]  {len(r['c2_on_443'])} IPs using port 443 WITHOUT TLS/SSL  ← high-confidence C2"]
        for e in r["c2_on_443"]:
            lines.append(f"  ⚠ {e['ip']:<22} {e['packets']} non-TLS pkts on :443")

    if r.get("c2_unreachable"):
        lines += [
            "",
            f"[C2-UNREACHABLE]  {len(r['c2_unreachable'])} IPs — many SYN attempts, server never responded",
            "  (possible offline/backup C2 — server was down during capture)",
        ]
        for e in r["c2_unreachable"]:
            lines.append(f"  ⚠ {e['ip']:<22} {e['syn_count']} SYN attempts with no response")

    if r["payload_iocs"]:
        lines += ["", f"[PAYLOAD]  {len(r['payload_iocs'])} HTTP bodies with embedded IOCs"]
        for p in r["payload_iocs"]:
            lines.append(f"  Source : {p['source']}")
            if p["embedded_ips"]:
                lines.append(f"  IPs    : {', '.join(p['embedded_ips'])}")
            if p["embedded_urls"]:
                lines.append(f"  URLs   : {', '.join(p['embedded_urls'][:4])}")
            if p["powershell_patterns"]:
                lines.append(f"  PS IOC : {', '.join(p['powershell_patterns'])}")
            lines.append(f"  Snippet: {p['snippet'][:120]}")
            lines.append("")

    if not any([r["dns_iocs"], r["http_request_iocs"], r["http_response_iocs"],
                r.get("user_agents"), r["tls_iocs"], r["c2_on_443"],
                r.get("c2_unreachable"), r["payload_iocs"]]):
        lines.append("\nNo IOCs found. Try exclude_benign=false to see all traffic.")

    return "\n".join(lines)
