"""Harvest recipes from the installed nmap NSE script library.

Parses each .nse file for:
  - description  (long-form English)
  - categories   (auth, brute, default, discovery, dos, exploit, external,
                  fuzzer, intrusive, malware, safe, version, vuln, broadcast)
  - @usage       (canonical command line when the author provided one)

From the script name we also infer likely ports via a protocol->port map, so
`smb-vuln-ms17-010` becomes a recipe scoped to ports 139,445 even when the
.nse file doesn't spell that out.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

NSE_DIRS = [
    Path(r"C:\Program Files (x86)\Nmap\scripts"),
    Path(r"C:\Program Files\Nmap\scripts"),
    Path("/usr/share/nmap/scripts"),
    Path("/usr/local/share/nmap/scripts"),
    Path("/opt/homebrew/share/nmap/scripts"),
]

# Protocol prefix -> default port(s). Covers the common cases; when a script
# doesn't match any prefix we leave the port unscoped (the --script runs
# against whatever -p specifies, typically default top-1000).
PROTO_PORTS: dict[str, str] = {
    "http": "80,443,8080,8443",
    "https": "443,8443",
    "ssl": "443,8443,993,995,465",
    "tls": "443,8443",
    "smb": "139,445",
    "smb2": "445",
    "ms-sql": "1433",
    "mssql": "1433",
    "mysql": "3306",
    "pgsql": "5432",
    "mongodb": "27017",
    "redis": "6379",
    "memcached": "11211",
    "oracle": "1521",
    "cassandra": "9160",
    "couchdb": "5984",
    "elasticsearch": "9200",
    "ssh": "22",
    "ftp": "21",
    "tftp": "69",
    "telnet": "23",
    "smtp": "25,465,587",
    "pop3": "110,995",
    "imap": "143,993",
    "snmp": "161",
    "ldap": "389,636",
    "dns": "53",
    "dhcp": "67,68",
    "ntp": "123",
    "rdp": "3389",
    "vnc": "5900,5901",
    "rpc": "111",
    "rpcinfo": "111",
    "nfs": "2049",
    "afp": "548",
    "rsync": "873",
    "kerberos": "88",
    "ipmi": "623",
    "modbus": "502",
    "mqtt": "1883,8883",
    "stun": "3478",
    "sip": "5060,5061",
    "upnp": "1900",
    "xmpp": "5222,5269",
    "ajp": "8009",
    "ike": "500",
    "isns": "3205",
    "iscsi": "3260",
    "jdwp": "8000,8787",
    "drda": "50000",
    "informix": "9088",
    "sybase": "5000",
    "weblogic": "7001",
    "distcc": "3632",
    "finger": "79",
    "ident": "113",
    "whois": "43",
    "irc": "6667,6697",
    "freelancer": "2302",
    "citrix": "1494",
    "rtsp": "554",
    "gopher": "70",
    "bjnp": "8612",
    "cups": "631",
    "x11": "6000,6001,6002",
    "nrpe": "5666",
    "teamspeak2": "51234",
    "db2": "50000",
    "netbus": "12345",
    "socks": "1080",
    "sshv1": "22",
}


@dataclass(frozen=True)
class NseScript:
    name: str
    description: str
    categories: tuple[str, ...]
    port_hint: str | None
    usage: str | None


_DESC_RE = re.compile(r"description\s*=\s*\[\[(.*?)\]\]", re.DOTALL)
_CATS_RE = re.compile(r"categories\s*=\s*\{([^}]*)\}", re.DOTALL)
_USAGE_RE = re.compile(r"@usage\s+(nmap[^\n]+)")
_WS = re.compile(r"\s+")


def _clean(text: str) -> str:
    return _WS.sub(" ", text.strip())


def _infer_port(name: str) -> str | None:
    # Longest-prefix match against PROTO_PORTS
    candidates = sorted(PROTO_PORTS.keys(), key=len, reverse=True)
    for proto in candidates:
        if name == proto or name.startswith(proto + "-") or name.startswith(proto + "2-"):
            return PROTO_PORTS[proto]
    return None


def parse_script(path: Path) -> NseScript | None:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    desc_m = _DESC_RE.search(text)
    cats_m = _CATS_RE.search(text)
    usage_m = _USAGE_RE.search(text)
    if not desc_m:
        return None
    description = _clean(desc_m.group(1))
    categories: tuple[str, ...] = ()
    if cats_m:
        raw = cats_m.group(1)
        categories = tuple(
            s.strip().strip('"').strip("'")
            for s in raw.split(",")
            if s.strip().strip('"').strip("'")
        )
    name = path.stem
    return NseScript(
        name=name,
        description=description,
        categories=categories,
        port_hint=_infer_port(name),
        usage=_clean(usage_m.group(1)) if usage_m else None,
    )


def find_nse_dir() -> Path | None:
    for d in NSE_DIRS:
        if d.is_dir():
            return d
    return None


def load_all(limit: int | None = None) -> list[NseScript]:
    d = find_nse_dir()
    if not d:
        return []
    out: list[NseScript] = []
    for p in sorted(d.glob("*.nse")):
        s = parse_script(p)
        if s:
            out.append(s)
        if limit and len(out) >= limit:
            break
    return out
