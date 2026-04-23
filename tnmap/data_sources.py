"""External + embedded real-world query->command pairs.

Three layers, in priority order:
  1. EMBEDDED_PAIRS - hand-curated ground truth, offline-safe
  2. cache on disk under data_cache/ for scraped pages
  3. best-effort scrape of HackTricks and public cheat sheets

harvest() returns a combined list, dedup'd by command+query.
"""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

CACHE_DIR = Path(__file__).with_name("data_cache")
CACHE_DIR.mkdir(exist_ok=True)

USER_AGENT = "Mozilla/5.0 (compatible; tnmap/0.1; +local)"
TIMEOUT = 8.0


@dataclass(frozen=True)
class Pair:
    query: str
    command: str


# 120 hand-curated real-world pairs mirroring how operators actually speak.
# These are the ground truth the retrieval model learns from.
EMBEDDED_PAIRS: list[Pair] = [
    # recon / first contact
    Pair("first look at a host", "nmap -sV -sC -oN initial.txt {target}"),
    Pair("initial reconnaissance of a server", "nmap -sC -sV -oN initial.txt {target}"),
    Pair("what is this server running", "nmap -sV --version-intensity 9 {target}"),
    Pair("identify the operating system", "nmap -O --osscan-guess {target}"),
    Pair("is this host alive", "nmap -sn {target}"),
    Pair("which hosts are up in my subnet", "nmap -sn {target}"),
    Pair("map my local network", "nmap -sn -PR {target}"),
    Pair("quick recon against a target", "nmap -F -T4 {target}"),
    Pair("quick port check", "nmap -F {target}"),
    Pair("full deep scan take your time", "nmap -sS -sV -sC -O -p- -T3 -oA full {target}"),
    Pair("as thorough as possible", "nmap -A -p- --script 'default and safe' -T4 {target}"),

    # ports
    Pair("every single tcp port", "nmap -p- {target}"),
    Pair("all ports", "nmap -p- {target}"),
    Pair("65535 ports scan", "nmap -p- {target}"),
    Pair("just the top 10 ports", "nmap --top-ports 10 {target}"),
    Pair("most common 100 ports", "nmap --top-ports 100 {target}"),
    Pair("scan port 8080", "nmap -p 8080 {target}"),
    Pair("scan a list of ports", "nmap -p 22,80,443,3306,5432,6379 {target}"),
    Pair("scan udp and tcp together", "nmap -sS -sU -p T:1-1000,U:53,67,123,161,500 {target}"),
    Pair("only open ports please", "nmap --open -sV {target}"),
    Pair("show state reasons", "nmap --reason {target}"),

    # service ID and banners
    Pair("banner grab", "nmap -sV --script banner {target}"),
    Pair("grab service banners", "nmap -sV --script banner {target}"),
    Pair("what version is running on open ports", "nmap -sV {target}"),
    Pair("light service probe", "nmap -sV --version-light {target}"),
    Pair("aggressive service fingerprinting", "nmap -sV --version-intensity 9 --version-all {target}"),

    # stealth / evasion
    Pair("be as quiet as possible", "nmap -sS -T0 -f --scan-delay 10s {target}"),
    Pair("avoid ids detection", "nmap -T1 -f --data-length 25 --randomize-hosts {target}"),
    Pair("fragment packets to evade firewall", "nmap -f {target}"),
    Pair("mtu 24 fragmentation", "nmap --mtu 24 {target}"),
    Pair("use decoys to hide my ip", "nmap -D RND:10 {target}"),
    Pair("spoof my source port", "nmap --source-port 53 -sS {target}"),
    Pair("spoof mac address", "nmap --spoof-mac 0 {target}"),
    Pair("use a proxy chain", "nmap --proxies http://proxy:8080 {target}"),
    Pair("send garbage data with probes", "nmap --data-length 50 {target}"),
    Pair("bad tcp checksum", "nmap --badsum {target}"),

    # timing
    Pair("go as fast as possible", "nmap -T5 --min-rate 10000 {target}"),
    Pair("polite scan do not hammer", "nmap -T2 --max-rate 50 {target}"),
    Pair("one packet per second", "nmap --max-rate 1 {target}"),
    Pair("minimum packet rate", "nmap --min-rate 1000 {target}"),

    # web / http
    Pair("find login pages", "nmap -p 80,443,8080,8443 --script http-auth-finder {target}"),
    Pair("discover login forms on a website", "nmap -p 80,443 --script http-auth-finder,http-form-fuzzer {target}"),
    Pair("web admin panel discovery", "nmap -p 80,443,8080,8443 --script http-enum,http-auth-finder {target}"),
    Pair("find admin interfaces", "nmap -p 80,443,8080,8443 --script http-enum,http-auth-finder {target}"),
    Pair("crawl web directories", "nmap -p 80,443 --script http-enum {target}"),
    Pair("brute force basic auth", "nmap -p 80,443 --script http-brute {target}"),
    Pair("brute force a login form", "nmap -p 80,443 --script http-form-brute {target}"),
    Pair("wordpress scan", "nmap -p 80,443 --script http-wordpress-enum,http-wordpress-users {target}"),
    Pair("wordpress user enumeration", "nmap -p 80,443 --script http-wordpress-users {target}"),
    Pair("drupal scan", "nmap -p 80,443 --script http-drupal-enum {target}"),
    Pair("joomla admin scan", "nmap -p 80,443 --script http-joomla-brute {target}"),
    Pair("check http methods allowed", "nmap -p 80,443 --script http-methods {target}"),
    Pair("http security headers audit", "nmap -p 80,443 --script http-security-headers {target}"),
    Pair("check for clickjacking", "nmap -p 80,443 --script http-security-headers {target}"),
    Pair("http cors check", "nmap -p 80,443 --script http-cors {target}"),
    Pair("robots txt", "nmap -p 80,443 --script http-robots.txt {target}"),
    Pair("sitemap disclosure", "nmap -p 80,443 --script http-sitemap-generator {target}"),
    Pair("detect web application firewall", "nmap -p 80,443 --script http-waf-detect,http-waf-fingerprint {target}"),
    Pair("test for sql injection over http", "nmap -p 80 --script http-sql-injection {target}"),
    Pair("shellshock bash cgi check", "nmap -p 80 --script http-shellshock {target}"),
    Pair("tomcat manager default creds", "nmap -p 8080 --script http-default-accounts,http-tomcat-brute {target}"),
    Pair("jenkins exposed", "nmap -p 8080,8443 --script http-enum {target}"),

    # ssl / tls
    Pair("heartbleed check", "nmap -p 443 --script ssl-heartbleed {target}"),
    Pair("check ssl ciphers", "nmap -p 443 --script ssl-enum-ciphers {target}"),
    Pair("tls security audit", "nmap -p 443,8443 --script ssl-enum-ciphers,ssl-cert,ssl-dh-params {target}"),
    Pair("certificate info", "nmap -p 443 --script ssl-cert {target}"),
    Pair("check for poodle", "nmap -p 443 --script ssl-poodle {target}"),
    Pair("check for freak and logjam", "nmap -p 443 --script ssl-dh-params {target}"),
    Pair("drown attack check", "nmap -p 443 --script sslv2-drown {target}"),
    Pair("sweet32 check", "nmap -p 443 --script ssl-enum-ciphers {target}"),

    # smb / windows
    Pair("eternalblue ms17-010", "nmap -p 445 --script smb-vuln-ms17-010 {target}"),
    Pair("find windows file shares", "nmap -p 139,445 --script smb-enum-shares {target}"),
    Pair("enumerate smb users", "nmap -p 139,445 --script smb-enum-users {target}"),
    Pair("smb os discovery", "nmap -p 139,445 --script smb-os-discovery {target}"),
    Pair("smb double pulsar backdoor", "nmap -p 445 --script smb-double-pulsar-backdoor {target}"),
    Pair("bluekeep cve-2019-0708", "nmap -p 3389 --script rdp-vuln-ms12-020 {target}"),
    Pair("rdp encryption check", "nmap -p 3389 --script rdp-enum-encryption {target}"),
    Pair("ntlm info", "nmap -p 80,443,139,445 --script http-ntlm-info,smb-enum-domains {target}"),
    Pair("kerberos user enumeration", "nmap -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm=EXAMPLE.COM {target}"),
    Pair("ldap anonymous bind", "nmap -p 389,636 --script ldap-rootdse,ldap-search {target}"),

    # databases
    Pair("find mysql servers", "nmap -p 3306 --script mysql-info,mysql-empty-password {target}"),
    Pair("mysql default credentials", "nmap -p 3306 --script mysql-empty-password,mysql-brute {target}"),
    Pair("mssql info", "nmap -p 1433 --script ms-sql-info,ms-sql-empty-password {target}"),
    Pair("mssql brute force", "nmap -p 1433 --script ms-sql-brute {target}"),
    Pair("postgres enum", "nmap -p 5432 --script pgsql-brute {target}"),
    Pair("mongodb exposed", "nmap -p 27017 --script mongodb-info,mongodb-databases {target}"),
    Pair("redis unauthenticated", "nmap -p 6379 --script redis-info,redis-brute {target}"),
    Pair("memcached exposed", "nmap -p 11211 --script memcached-info {target}"),
    Pair("elasticsearch exposed", "nmap -p 9200 --script http-elasticsearch-head {target}"),
    Pair("couchdb exposed", "nmap -p 5984 --script couchdb-databases,couchdb-stats {target}"),
    Pair("oracle tns listener", "nmap -p 1521 --script oracle-tns-version,oracle-sid-brute {target}"),

    # mail / ftp / ssh
    Pair("open smtp relay check", "nmap -p 25 --script smtp-open-relay {target}"),
    Pair("smtp user enum", "nmap -p 25 --script smtp-enum-users {target}"),
    Pair("check ftp anonymous access", "nmap -p 21 --script ftp-anon {target}"),
    Pair("ftp bounce attack", "nmap -p 21 --script ftp-bounce {target}"),
    Pair("vsftpd backdoor", "nmap -p 21 --script ftp-vsftpd-backdoor {target}"),
    Pair("ssh supported algorithms", "nmap -p 22 --script ssh2-enum-algos {target}"),
    Pair("ssh host key", "nmap -p 22 --script ssh-hostkey {target}"),
    Pair("ssh weak credentials", "nmap -p 22 --script ssh-brute {target}"),
    Pair("telnet default creds", "nmap -p 23 --script telnet-brute,telnet-encryption {target}"),

    # dns / network protocols
    Pair("dns zone transfer", "nmap -p 53 --script dns-zone-transfer --script-args dns-zone-transfer.domain=example.com {target}"),
    Pair("subdomain brute force via dns", "nmap --script dns-brute --script-args dns-brute.domain=example.com {target}"),
    Pair("dns cache snooping", "nmap -p 53 --script dns-cache-snoop {target}"),
    Pair("snmp community string", "nmap -sU -p 161 --script snmp-brute {target}"),
    Pair("snmp full info dump", "nmap -sU -p 161 --script snmp-info,snmp-interfaces,snmp-processes,snmp-win32-software {target}"),
    Pair("ntp monlist amplification", "nmap -sU -p 123 --script ntp-monlist {target}"),
    Pair("dhcp discover", "nmap --script broadcast-dhcp-discover {target}"),
    Pair("upnp info", "nmap -sU -p 1900 --script upnp-info {target}"),
    Pair("sip voip enumeration", "nmap -sU -p 5060 --script sip-enum-users,sip-methods {target}"),
    Pair("mqtt broker info", "nmap -p 1883 --script mqtt-subscribe {target}"),
    Pair("modbus industrial control", "nmap -p 502 --script modbus-discover {target}"),
    Pair("ipmi exposed", "nmap -sU -p 623 --script ipmi-version,ipmi-cipher-zero {target}"),

    # cloud / container / k8s
    Pair("kubernetes api exposed", "nmap -p 6443,8443,10250 --script http-title,http-headers {target}"),
    Pair("docker api exposed", "nmap -p 2375,2376 --script http-title {target}"),
    Pair("etcd exposed", "nmap -p 2379,2380 --script http-title {target}"),
    Pair("consul exposed", "nmap -p 8500 --script http-enum {target}"),
    Pair("rabbitmq management", "nmap -p 15672 --script http-title,http-auth-finder {target}"),

    # iot / printers / misc
    Pair("network printers", "nmap --script broadcast-jet-direct-discover,snmp-info -p 161,9100 {target}"),
    Pair("vnc no authentication", "nmap -p 5900 --script vnc-info,realvnc-auth-bypass {target}"),
    Pair("nfs exports", "nmap -p 111,2049 --script nfs-ls,nfs-showmount,nfs-statfs {target}"),
    Pair("rpc endpoints", "nmap -p 111 --script rpcinfo {target}"),

    # output
    Pair("save to xml", "nmap -oX scan.xml {target}"),
    Pair("save all formats", "nmap -oA scan {target}"),
    Pair("grepable output", "nmap -oG scan.gnmap {target}"),
    Pair("verbose", "nmap -v {target}"),
    Pair("super verbose with reasons", "nmap -vv --reason {target}"),
]


_COMMAND_LINE = re.compile(r"(?:^|\n|>)\s*(?:\$|#|>)?\s*(nmap\s+[^\n<]+)")
_CODE_BLOCK = re.compile(r"<code[^>]*>(.*?)</code>", re.IGNORECASE | re.DOTALL)
_PRE_BLOCK = re.compile(r"<pre[^>]*>(.*?)</pre>", re.IGNORECASE | re.DOTALL)
_HEADING = re.compile(r"<h[1-6][^>]*>(.*?)</h[1-6]>", re.IGNORECASE | re.DOTALL)
_INLINE_CMD = re.compile(r"nmap\s+(?:-[A-Za-z0-9]+[^<\s]*\s*)+", re.IGNORECASE)


def _fetch(url: str) -> str | None:
    """Cached HTTP GET. Returns html text or None on failure."""
    cache = CACHE_DIR / (re.sub(r"[^A-Za-z0-9]+", "_", url)[:120] + ".html")
    if cache.exists():
        try:
            return cache.read_text(encoding="utf-8", errors="replace")
        except OSError:
            pass
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            body = resp.read().decode("utf-8", errors="replace")
        cache.write_text(body, encoding="utf-8")
        return body
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError):
        return None


def _strip_tags(html: str) -> str:
    return re.sub(r"<[^>]+>", "", html)


def _nearest_heading_before(html: str, pos: int) -> str | None:
    pre = html[:pos]
    matches = list(_HEADING.finditer(pre))
    if not matches:
        return None
    return _strip_tags(matches[-1].group(1)).strip() or None


def _clean_cmd(raw: str) -> str:
    cmd = _strip_tags(raw)
    cmd = re.sub(r"&amp;", "&", cmd)
    cmd = re.sub(r"&lt;", "<", cmd)
    cmd = re.sub(r"&gt;", ">", cmd)
    cmd = re.sub(r"&quot;", '"', cmd)
    cmd = re.sub(r"&#[0-9]+;", " ", cmd)
    cmd = re.sub(r"\s+", " ", cmd).strip()
    # Replace concrete ip/host arguments with our placeholder
    cmd = re.sub(r"\b(?:scanme\.nmap\.org|\d+\.\d+\.\d+\.\d+(?:/\d+)?)\b", "{target}", cmd)
    return cmd


def _extract_pairs_from_html(html: str) -> list[Pair]:
    """Pair every nmap command found in the page with its nearest prior heading.

    Looks inside <code>, <pre>, and raw text. The nearest preceding
    <h1>-<h6> becomes the natural-language query for that command.
    """
    pairs: list[Pair] = []
    spans: list[tuple[int, str]] = []

    for block_re in (_CODE_BLOCK, _PRE_BLOCK):
        for m in block_re.finditer(html):
            inner = m.group(1)
            # inner may contain one or more nmap invocations
            for inv in _INLINE_CMD.finditer(inner):
                cmd = _clean_cmd(inv.group(0))
                if 8 <= len(cmd) <= 300 and cmd.lower().startswith("nmap"):
                    spans.append((m.start(), cmd))

    # also raw-text commands not wrapped in code (fallback)
    for m in _COMMAND_LINE.finditer(html):
        cmd = _clean_cmd(m.group(1))
        if 8 <= len(cmd) <= 300 and cmd.lower().startswith("nmap"):
            spans.append((m.start(), cmd))

    for pos, cmd in spans:
        heading = _nearest_heading_before(html, pos)
        if not heading:
            continue
        heading = _strip_tags(heading).strip().lower()
        heading = re.sub(r"\s+", " ", heading)
        if 4 <= len(heading) <= 160:
            pairs.append(Pair(heading, cmd))
    return pairs


SOURCES = [
    "https://book.hacktricks.xyz/generic-methodologies-and-resources/pentesting-network/nmap-summary-esp",
    "https://book.hacktricks.xyz/generic-methodologies-and-resources/pentesting-network/pentesting-ipv6",
    "https://www.stationx.net/nmap-cheat-sheet/",
    "https://nmap.org/book/man-briefoptions.html",
]


def scrape_all() -> list[Pair]:
    found: list[Pair] = []
    for url in SOURCES:
        html = _fetch(url)
        if not html:
            continue
        found.extend(_extract_pairs_from_html(html))
    return found


def harvest() -> list[Pair]:
    """Combined embedded + scraped pairs, deduplicated."""
    seen: set[tuple[str, str]] = set()
    out: list[Pair] = []
    for src in (EMBEDDED_PAIRS, scrape_all()):
        for p in src:
            key = (p.query.lower(), p.command)
            if key in seen:
                continue
            seen.add(key)
            out.append(p)
    return out


def save_snapshot(path: Path) -> None:
    pairs = harvest()
    path.write_text(
        json.dumps([{"query": p.query, "command": p.command} for p in pairs], indent=2),
        encoding="utf-8",
    )
