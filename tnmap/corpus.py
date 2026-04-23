"""Curated nmap recipe corpus.

Each entry pairs a natural-language description with a command template.
{target} is the placeholder the TUI substitutes with the user's target.

This corpus is training data for two models:
  1. Intent model (TF-IDF over descriptions) -> recipe match
  2. Flag bigram model (Markov over token sequences in commands) -> next-flag
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Recipe:
    description: str
    command: str
    tags: tuple[str, ...] = ()


RECIPES: list[Recipe] = [
    # --- discovery ---
    Recipe("ping sweep a subnet for live hosts", "nmap -sn {target}", ("discovery",)),
    Recipe("host discovery without port scan arp ping", "nmap -sn -PR {target}", ("discovery",)),
    Recipe("list scan do not send any packets", "nmap -sL {target}", ("discovery",)),
    Recipe("skip host discovery treat all hosts as online", "nmap -Pn {target}", ("discovery",)),
    Recipe("dns resolution only no scan", "nmap -sL -n {target}", ("discovery",)),
    Recipe("tcp syn ping on common ports", "nmap -PS22,80,443 {target}", ("discovery",)),
    Recipe("tcp ack ping bypass stateless firewall", "nmap -PA80,443 {target}", ("discovery",)),
    Recipe("icmp echo ping sweep", "nmap -PE -sn {target}", ("discovery",)),
    Recipe("udp ping discovery", "nmap -PU53,161 -sn {target}", ("discovery",)),

    # --- tcp port scans ---
    Recipe("quick top 100 tcp port scan", "nmap -F {target}", ("tcp", "fast")),
    Recipe("top 1000 tcp ports default scan", "nmap {target}", ("tcp",)),
    Recipe("full tcp port scan all 65535 ports", "nmap -p- {target}", ("tcp", "full")),
    Recipe("stealth syn scan half open", "nmap -sS {target}", ("tcp", "stealth")),
    Recipe("tcp connect scan no privileges needed", "nmap -sT {target}", ("tcp",)),
    Recipe("scan specific tcp ports", "nmap -p 22,80,443,3306,5432 {target}", ("tcp",)),
    Recipe("scan port range", "nmap -p 1-10000 {target}", ("tcp",)),
    Recipe("top 20 most common ports", "nmap --top-ports 20 {target}", ("tcp", "fast")),
    Recipe("top 200 most common ports", "nmap --top-ports 200 {target}", ("tcp",)),
    Recipe("show only open ports hide closed filtered", "nmap --open {target}", ("tcp",)),
    Recipe("fin scan evade firewall", "nmap -sF {target}", ("tcp", "evasion")),
    Recipe("null scan no flags set", "nmap -sN {target}", ("tcp", "evasion")),
    Recipe("xmas scan fin psh urg flags", "nmap -sX {target}", ("tcp", "evasion")),
    Recipe("maimon scan fin ack", "nmap -sM {target}", ("tcp", "evasion")),
    Recipe("tcp window scan distinguish open closed", "nmap -sW {target}", ("tcp",)),
    Recipe("idle zombie scan using another host", "nmap -sI zombie.example.com {target}", ("tcp", "evasion")),

    # --- udp ---
    Recipe("udp scan top ports", "nmap -sU --top-ports 100 {target}", ("udp",)),
    Recipe("full udp scan common protocols", "nmap -sU -sV -T4 {target}", ("udp",)),
    Recipe("udp dns port scan", "nmap -sU -p 53 {target}", ("udp",)),
    Recipe("udp snmp discovery", "nmap -sU -p 161,162 --script snmp-info {target}", ("udp",)),
    Recipe("combined tcp and udp scan", "nmap -sS -sU -p T:1-1000,U:53,161,500 {target}", ("tcp", "udp")),

    # --- service / os / fingerprint ---
    Recipe("service version detection", "nmap -sV {target}", ("service",)),
    Recipe("aggressive service detection higher intensity", "nmap -sV --version-intensity 9 {target}", ("service",)),
    Recipe("light version scan fast", "nmap -sV --version-light {target}", ("service", "fast")),
    Recipe("os fingerprint detection", "nmap -O {target}", ("os",)),
    Recipe("guess os when detection fails", "nmap -O --osscan-guess {target}", ("os",)),
    Recipe("aggressive scan os service scripts traceroute", "nmap -A {target}", ("aggressive",)),
    Recipe("full aggressive sweep with all ports", "nmap -A -p- -T4 {target}", ("aggressive", "full")),
    Recipe("banner grab with service detection", "nmap -sV --script banner {target}", ("service",)),

    # --- nse scripts ---
    Recipe("run default nse scripts", "nmap -sC {target}", ("scripts",)),
    Recipe("vulnerability scan nse vuln category", "nmap --script vuln {target}", ("scripts", "vuln")),
    Recipe("safe scripts only non intrusive", "nmap --script safe {target}", ("scripts",)),
    Recipe("discovery scripts", "nmap --script discovery {target}", ("scripts", "discovery")),
    Recipe("auth scripts test authentication", "nmap --script auth {target}", ("scripts", "auth")),
    Recipe("brute force common services", "nmap --script brute {target}", ("scripts", "brute")),
    Recipe("run default and vuln scripts", "nmap -sC --script vuln {target}", ("scripts", "vuln")),
    Recipe("check for common exploits", "nmap --script exploit {target}", ("scripts", "vuln")),
    Recipe("malware scan backdoor detection", "nmap --script malware {target}", ("scripts",)),

    # --- web / http ---
    Recipe("http enumeration scan", "nmap -p 80,443,8080,8443 --script http-enum {target}", ("web",)),
    Recipe("http title and headers", "nmap -p 80,443 --script http-title,http-headers {target}", ("web",)),
    Recipe("http methods allowed", "nmap -p 80,443 --script http-methods {target}", ("web",)),
    Recipe("http robots txt", "nmap -p 80,443 --script http-robots.txt {target}", ("web",)),
    Recipe("web application vulnerabilities", "nmap -p 80,443 --script http-vuln* {target}", ("web", "vuln")),
    Recipe("sql injection detection http", "nmap -p 80 --script http-sql-injection {target}", ("web", "vuln")),
    Recipe("http wordpress enumeration", "nmap -p 80,443 --script http-wordpress-enum {target}", ("web",)),
    Recipe("http slowloris dos check", "nmap -p 80 --script http-slowloris-check {target}", ("web", "vuln")),

    # --- web auth / login pages / admin panels ---
    Recipe("find login pages on a web server", "nmap -p 80,443,8080,8443 --script http-auth-finder {target}", ("web", "auth")),
    Recipe("discover admin login panels and forms", "nmap -p 80,443 --script http-auth-finder,http-form-fuzzer {target}", ("web", "auth")),
    Recipe("brute force http basic auth login", "nmap -p 80,443 --script http-brute {target}", ("web", "auth", "brute")),
    Recipe("brute force web form login page", "nmap -p 80,443 --script http-form-brute {target}", ("web", "auth", "brute")),
    Recipe("default credentials check on web apps", "nmap -p 80,443,8080 --script http-default-accounts {target}", ("web", "auth")),
    Recipe("wordpress login brute force", "nmap -p 80,443 --script http-wordpress-brute {target}", ("web", "auth", "brute")),
    Recipe("joomla admin login brute force", "nmap -p 80,443 --script http-joomla-brute {target}", ("web", "auth", "brute")),
    Recipe("enumerate web directories and common paths", "nmap -p 80,443 --script http-enum {target}", ("web", "auth")),
    Recipe("check for exposed admin interfaces", "nmap -p 80,443,8080,8443 --script http-enum,http-auth-finder {target}", ("web", "auth")),
    Recipe("http basic auth realm detection", "nmap -p 80,443 --script http-auth {target}", ("web", "auth")),
    Recipe("find csrf tokens on login forms", "nmap -p 80,443 --script http-csrf {target}", ("web", "auth")),
    Recipe("detect jwt tokens in web responses", "nmap -p 80,443 --script http-jwt {target}", ("web", "auth")),
    Recipe("oauth and sso endpoint discovery", "nmap -p 80,443 --script http-enum --script-args http-enum.basepath=/oauth {target}", ("web", "auth")),
    Recipe("sign in page and authentication portal scan", "nmap -p 80,443,8080,8443 -sV --script http-auth-finder,http-title {target}", ("web", "auth")),

    # --- ssl / tls ---
    Recipe("ssl tls cipher enumeration", "nmap -p 443 --script ssl-enum-ciphers {target}", ("ssl",)),
    Recipe("check heartbleed vulnerability", "nmap -p 443 --script ssl-heartbleed {target}", ("ssl", "vuln")),
    Recipe("ssl certificate inspection", "nmap -p 443 --script ssl-cert {target}", ("ssl",)),
    Recipe("tls version and cipher audit", "nmap -p 443,8443 --script ssl-enum-ciphers,ssl-cert {target}", ("ssl",)),
    Recipe("check poodle sslv3 vulnerability", "nmap -p 443 --script ssl-poodle {target}", ("ssl", "vuln")),

    # --- smb / windows ---
    Recipe("smb os discovery and shares", "nmap -p 139,445 --script smb-os-discovery,smb-enum-shares {target}", ("smb", "windows")),
    Recipe("smb vulnerability scan", "nmap -p 139,445 --script smb-vuln* {target}", ("smb", "vuln")),
    Recipe("check for eternalblue ms17 010", "nmap -p 445 --script smb-vuln-ms17-010 {target}", ("smb", "vuln")),
    Recipe("smb enumerate users", "nmap -p 139,445 --script smb-enum-users {target}", ("smb",)),
    Recipe("smb enumerate sessions", "nmap -p 139,445 --script smb-enum-sessions {target}", ("smb",)),
    Recipe("rdp security check", "nmap -p 3389 --script rdp-enum-encryption,rdp-vuln-ms12-020 {target}", ("windows", "vuln")),

    # --- db ---
    Recipe("mysql enumeration", "nmap -p 3306 --script mysql-info,mysql-enum {target}", ("db",)),
    Recipe("mysql brute force", "nmap -p 3306 --script mysql-brute {target}", ("db", "brute")),
    Recipe("postgres enumeration", "nmap -p 5432 --script pgsql-brute {target}", ("db",)),
    Recipe("mongodb info", "nmap -p 27017 --script mongodb-info,mongodb-databases {target}", ("db",)),
    Recipe("redis info", "nmap -p 6379 --script redis-info {target}", ("db",)),
    Recipe("mssql info and brute", "nmap -p 1433 --script ms-sql-info,ms-sql-brute {target}", ("db", "brute")),

    # --- mail / ftp / ssh ---
    Recipe("smtp enumeration users", "nmap -p 25 --script smtp-enum-users {target}", ("mail",)),
    Recipe("smtp open relay check", "nmap -p 25 --script smtp-open-relay {target}", ("mail",)),
    Recipe("pop3 imap capabilities", "nmap -p 110,143 --script pop3-capabilities,imap-capabilities {target}", ("mail",)),
    Recipe("ftp anonymous login check", "nmap -p 21 --script ftp-anon {target}", ("ftp",)),
    Recipe("ftp brute force", "nmap -p 21 --script ftp-brute {target}", ("ftp", "brute")),
    Recipe("ssh host key and algorithms", "nmap -p 22 --script ssh2-enum-algos,ssh-hostkey {target}", ("ssh",)),
    Recipe("ssh weak credentials brute force", "nmap -p 22 --script ssh-brute {target}", ("ssh", "brute")),

    # --- dns ---
    Recipe("dns zone transfer attempt", "nmap -p 53 --script dns-zone-transfer {target}", ("dns",)),
    Recipe("dns brute force subdomains", "nmap --script dns-brute {target}", ("dns",)),
    Recipe("dns cache snoop", "nmap -p 53 --script dns-cache-snoop {target}", ("dns",)),

    # --- snmp ---
    Recipe("snmp community string brute", "nmap -sU -p 161 --script snmp-brute {target}", ("snmp", "brute")),
    Recipe("snmp system information", "nmap -sU -p 161 --script snmp-sysdescr,snmp-info {target}", ("snmp",)),

    # --- timing / evasion ---
    Recipe("paranoid timing avoid ids", "nmap -T0 {target}", ("timing", "evasion")),
    Recipe("sneaky slow scan", "nmap -T1 {target}", ("timing", "evasion")),
    Recipe("polite timing less bandwidth", "nmap -T2 {target}", ("timing",)),
    Recipe("normal timing default", "nmap -T3 {target}", ("timing",)),
    Recipe("aggressive timing fast", "nmap -T4 {target}", ("timing", "fast")),
    Recipe("insane timing fastest", "nmap -T5 {target}", ("timing", "fast")),
    Recipe("minimum packet rate per second", "nmap --min-rate 1000 {target}", ("timing", "fast")),
    Recipe("maximum packet rate limit", "nmap --max-rate 100 {target}", ("timing",)),
    Recipe("fragment packets evasion", "nmap -f {target}", ("evasion",)),
    Recipe("specific mtu evasion", "nmap --mtu 16 {target}", ("evasion",)),
    Recipe("decoy scan hide real ip", "nmap -D RND:10 {target}", ("evasion",)),
    Recipe("source port spoof 53 bypass firewall", "nmap --source-port 53 {target}", ("evasion",)),
    Recipe("spoof mac address random", "nmap --spoof-mac 0 {target}", ("evasion",)),
    Recipe("randomize host order", "nmap --randomize-hosts {target}", ("evasion",)),
    Recipe("bad checksum detect stateful firewall", "nmap --badsum {target}", ("evasion",)),

    # --- output ---
    Recipe("normal output to file", "nmap -oN scan.txt {target}", ("output",)),
    Recipe("xml output for parsing", "nmap -oX scan.xml {target}", ("output",)),
    Recipe("grepable output", "nmap -oG scan.gnmap {target}", ("output",)),
    Recipe("all output formats at once", "nmap -oA scan {target}", ("output",)),
    Recipe("verbose output", "nmap -v {target}", ("output",)),
    Recipe("very verbose debugging output", "nmap -vv --reason {target}", ("output",)),
    Recipe("show reason ports are in state", "nmap --reason {target}", ("output",)),
    Recipe("packet trace debugging", "nmap --packet-trace {target}", ("output",)),

    # --- ipv6 / misc ---
    Recipe("ipv6 target scan", "nmap -6 {target}", ("ipv6",)),
    Recipe("ipv6 with aggressive detection", "nmap -6 -A {target}", ("ipv6",)),
    Recipe("scan from input file list", "nmap -iL targets.txt", ("input",)),
    Recipe("exclude hosts from scan", "nmap {target} --exclude 192.168.1.1,192.168.1.254", ("input",)),
    Recipe("resume previously aborted scan", "nmap --resume scan.txt", ("output",)),
    Recipe("traceroute to target", "nmap --traceroute {target}", ("discovery",)),

    # --- combined pentest workflows ---
    Recipe("initial recon full tcp fast", "nmap -sS -p- --min-rate 2000 -T4 -oA recon {target}", ("recon", "full")),
    Recipe("thorough pentest scan all ports scripts version", "nmap -sS -sV -sC -p- -T4 -oA full {target}", ("recon", "full")),
    Recipe("web server deep audit", "nmap -p 80,443,8080,8443 -sV --script 'http-* and not brute' {target}", ("web", "recon")),
    Recipe("internal network inventory", "nmap -sS -T4 --top-ports 1000 --open -oA internal {target}", ("recon",)),
    Recipe("external perimeter safe scan", "nmap -sS -T2 --top-ports 100 --open {target}", ("recon",)),
]


_VERBS = [
    "scan", "check", "detect", "find", "enumerate", "test for", "audit",
    "probe", "identify", "look for", "discover", "inspect", "investigate",
]

_CATEGORY_KEYWORDS: dict[str, tuple[str, ...]] = {
    "vuln": ("vulnerability", "exploit check", "cve", "security flaw", "weakness"),
    "brute": ("brute force", "password guessing", "credential attack", "dictionary attack"),
    "auth": ("authentication", "login", "credentials", "sign in", "access control"),
    "discovery": ("discovery", "enumeration", "recon", "reconnaissance"),
    "intrusive": ("intrusive", "aggressive", "risky"),
    "safe": ("safe", "non-intrusive", "passive"),
    "exploit": ("exploit", "attack", "payload delivery"),
    "dos": ("denial of service", "dos check", "availability impact"),
    "malware": ("malware", "backdoor", "trojan"),
    "fuzzer": ("fuzzing", "malformed input"),
    "default": ("default scripts", "basic scripts"),
    "version": ("service version", "software version"),
    "broadcast": ("broadcast discovery", "network wide"),
    "external": ("third-party lookup", "external query"),
}


def _paraphrase(description: str, categories: tuple[str, ...]) -> list[str]:
    """Return a short list of alt descriptions to improve TF-IDF recall.

    Deliberately conservative: 3-5 texts per recipe. More paraphrases inflate
    that recipe's TF-IDF mass and make it crowd out siblings in top-k.
    Category-keyword injection is limited to one synonym per recipe and only
    if the word is not already present, to avoid synthetic lexical bias.
    """
    base = description.strip().rstrip(".")
    out: list[str] = [base]
    lowered = base.lower()

    head = base[:90]
    if head:
        # two verb rewrites, not six - keeps per-recipe count low
        for v in _VERBS[:2]:
            out.append(f"{v} {head[0].lower() + head[1:]}")

    # inject at most one category synonym, and only if not already present
    for cat in categories:
        syns = _CATEGORY_KEYWORDS.get(cat, ())
        missing = [kw for kw in syns if kw not in lowered]
        if missing:
            out.append(f"{base} ({missing[0]})")
            break

    return [p[:220] for p in out]


def build_corpus() -> list[Recipe]:
    """Fuse hand-written recipes with NSE scripts, flag table, and external
    query->command pairs (embedded + scraped), with controlled paraphrasing."""
    from .data_sources import harvest
    from .flags import FLAGS
    from .nse_scraper import load_all

    recipes: list[Recipe] = []

    # 0. real-world query -> command pairs (highest-quality ground truth).
    # No paraphrasing - these are already natural phrasings.
    for pair in harvest():
        recipes.append(Recipe(pair.query, pair.command, ("real",)))

    # 1. hand-curated (authoritative, high quality descriptions)
    for r in RECIPES:
        for desc in _paraphrase(r.description, r.tags):
            recipes.append(Recipe(desc, r.command, r.tags))

    # 2. every flag from the man page
    for cmd, desc, cat in FLAGS:
        for paraphrase in _paraphrase(desc, (cat,)):
            recipes.append(Recipe(paraphrase, cmd, (cat,)))

    # 3. every installed NSE script
    for s in load_all():
        if s.usage:
            cmd = s.usage.replace("<target>", "{target}").replace("<host>", "{target}")
        elif s.port_hint:
            cmd = f"nmap -p {s.port_hint} --script {s.name} {{target}}"
        else:
            cmd = f"nmap --script {s.name} {{target}}"
        tags = s.categories
        # Strip the NSE description to something the TF-IDF can digest
        compact = s.description.split(".")[0][:200]
        full = f"{compact}. nse script {s.name}"
        for desc in _paraphrase(full, tags):
            recipes.append(Recipe(desc, cmd, tags))

    return recipes


def flag_tokens(command: str) -> list[str]:
    """Extract the ordered list of nmap-specific tokens from a command.

    Keeps flags and flag-values but strips the literal {target} placeholder
    and the program name. Used to train the bigram next-flag predictor.
    """
    parts = command.split()
    out: list[str] = []
    skip_program = True
    for p in parts:
        if skip_program and p == "nmap":
            skip_program = False
            continue
        if p == "{target}":
            continue
        out.append(p)
    return out
