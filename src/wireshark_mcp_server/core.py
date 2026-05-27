"""
Shared constants, async tshark runner, and filtering/formatting helpers.
Imported by every tool module — no circular dependencies.
"""
import asyncio
import ipaddress
import re

# ---------------------------------------------------------------------------
# Private network ranges (RFC 1918 + link-local + multicast + broadcast)
# ---------------------------------------------------------------------------

_PRIVATE_NETS = [
    ipaddress.ip_network(n)
    for n in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "255.255.255.255/32",
    )
]

# ---------------------------------------------------------------------------
# Domain whitelists
# ---------------------------------------------------------------------------

_BENIGN_SUFFIXES: frozenset[str] = frozenset({
    # Microsoft
    ".microsoft.com", ".windows.com", ".windowsupdate.com",
    ".msftconnecttest.com", ".msn.com", ".live.com", ".bing.com",
    ".azure.com", ".azureedge.net", ".msedge.net", ".xboxlive.com",
    ".nelreports.net", ".delivery.mp.microsoft.com",
    ".s-microsoft.com",
    ".microsoftonline.com",
    ".office.com", ".office365.com", ".sharepoint.com",
    ".outlook.com", ".onmicrosoft.com",
    # Google
    ".google.com", ".googleapis.com", ".gstatic.com", ".gvt1.com",
    ".googleusercontent.com", ".google-analytics.com",
    # Amazon / CDN
    ".amazonaws.com", ".akamaized.net", ".cloudfront.net", ".amazontrust.com",
    ".akamaiedge.net", ".akadns.net", ".akamai.net",
    # Misc benign
    ".apple.com", ".icloud.com", ".getfiddler.com",
    ".keyshot.com",
    # Apple infrastructure (macOS captures) — CDN, DNS, software update
    ".aaplimg.com",           # Apple CDN (software updates, assets)
    ".apple-dns.net",         # Apple private DNS
    ".cdn-apple.com",         # Apple CDN (software updates via Akamai)
    ".apple-cloudkit.com",    # Apple iCloud CloudKit API
    ".apple",                 # Apple's own TLD (tether.edge.apple, etc.) — seen in 2+ macOS captures
    ".ls.apple.com",
    ".push.apple.com",
    ".appleiphoneactivation.com",
    # CDN / infrastructure
    ".cloudflareinsights.com",
    ".jquery.com",
    # Twitter / Meta / Cloudflare common infrastructure
    ".twimg.com", ".twitter.com",
    ".facebook.com", ".fbcdn.net",
    ".cloudflare.com",
    # Windows virtual network / Hyper-V host-only domain — never C2
    ".mshome.net",
})

_BENIGN_EXACT: frozenset[str] = frozenset({
    "dns.google", "wpad.localdomain", "localdomain.localdomain",
    "ocsp.rootg2.amazontrust.com", "ocsp.rootca1.amazontrust.com",
    "ocsp.r2m04.amazontrust.com",
    # macOS mDNS/Bonjour discovery — always local, never malicious
    "b._dns-sd._udp.mshome.net",
    "db._dns-sd._udp.mshome.net",
    "lb._dns-sd._udp.mshome.net",
})

# ---------------------------------------------------------------------------
# Shared regex patterns
# ---------------------------------------------------------------------------

_SUSPICIOUS_UA_RE = re.compile(
    r"(powershell|windowspowershell|python-requests|go-http-client"
    r"|curl/|wget/|nmap|masscan|nuclei|zgrab|libwww-perl"
    r"|headlesschrome|phantomjs|selenium)",
    re.IGNORECASE,
)

_DROPPER_CT: frozenset[str] = frozenset({
    "application/zip", "application/x-zip", "application/octet-stream",
    "application/x-msdownload", "application/x-dosexec",
    "application/vnd.microsoft.portable-executable",
})

_IP_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
_URL_RE = re.compile(r"https?://[^\s\"'<>\\]{4,}", re.IGNORECASE)
_PS_PATTERN_RE = re.compile(
    r"(Invoke-Expression|Invoke-WebRequest|IEX\s*\(|iex\s*\("
    r"|DownloadString|DownloadFile|Start-Process|Net\.WebClient)",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Core async tshark runner
# ---------------------------------------------------------------------------

async def _tshark(*args: str, timeout: int = 120) -> str:
    """Run tshark with the given args and return stdout as a string."""
    proc = await asyncio.create_subprocess_exec(
        "tshark", *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        return ""
    return stdout.decode("utf-8", errors="replace")


def _parse_tsv(raw: str, expected_cols: int) -> list[list[str]]:
    """Split tshark -T fields tab output into rows of fixed column count."""
    rows = []
    for line in raw.splitlines():
        cols = line.split("\t")
        while len(cols) < expected_cols:
            cols.append("")
        rows.append(cols[:expected_cols])
    return rows


# ---------------------------------------------------------------------------
# Filtering helpers
# ---------------------------------------------------------------------------

def _is_private(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _PRIVATE_NETS)
    except ValueError:
        return True


def _is_benign_domain(domain: str) -> bool:
    if not domain:
        return True
    d = domain.lower().rstrip(".")
    if "." not in d:
        return True
    if d.endswith(".localdomain") or d.endswith(".local") or d.endswith(".lan"):
        return True
    # Reverse-DNS lookups (.arpa) — always infrastructure, never C2
    if d.endswith(".arpa"):
        return True
    # mDNS service-discovery records (_dns-sd, _tcp, _udp)
    if d.startswith("_"):
        return True
    if d in _BENIGN_EXACT:
        return True
    return any(d == s.lstrip(".") or d.endswith(s) for s in _BENIGN_SUFFIXES)


def _is_suspicious_tld(domain: str) -> bool:
    suspicious = {".top", ".xyz", ".pw", ".cc", ".su", ".tk", ".buzz",
                  ".click", ".monster", ".cyou", ".bond"}
    return any(domain.lower().endswith(t) for t in suspicious)


def _decode_file_data(hex_str: str) -> str:
    """tshark returns http.file_data as a colon-separated hex string. Decode to text."""
    if not hex_str:
        return ""
    try:
        clean = hex_str.replace(":", "").replace(" ", "")
        return bytes.fromhex(clean).decode("utf-8", errors="replace")
    except Exception:
        return ""


def _scan_payload(payload: str, server_ip: str, uri: str) -> dict | None:
    """Regex scan an HTTP response body. Returns IOC dict or None."""
    found_ips = [ip for ip in _IP_RE.findall(payload) if not _is_private(ip)]
    found_urls = _URL_RE.findall(payload)
    found_ps = _PS_PATTERN_RE.findall(payload)
    if not (found_ips or found_urls or found_ps):
        return None
    return {
        "source": f"{server_ip}{uri}",
        "embedded_ips": list(dict.fromkeys(found_ips)),
        "embedded_urls": list(dict.fromkeys(found_urls))[:10],
        "powershell_patterns": list(dict.fromkeys(found_ps)),
        "snippet": payload[:300].replace("\r", "").replace("\n", " "),
    }


# ---------------------------------------------------------------------------
# Human-readable formatters
# ---------------------------------------------------------------------------

def _human_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f}{unit}"
        n //= 1024
    return f"{n:.1f}TB"


def _human_duration(seconds: float) -> str:
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    m, s = divmod(seconds, 60)
    if m < 60:
        return f"{m}m {s}s"
    h, m = divmod(m, 60)
    return f"{h}h {m}m {s}s"
