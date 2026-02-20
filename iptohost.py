from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple


KEY_ALIASES: Dict[str, List[str]] = {
    "shodan": ["SHODAN_API_KEY", "shdapi", "shodan"],
    "virustotal": ["vtapi", "vtapi2", "virustotal"],
    "otx": ["otxapi", "otx"],
    "riskiq_user": ["riskiquser", "passivetotal_user"],
    "riskiq_key": ["riskiqkey", "passivetotal_key"],
    "urlscan": ["urlscanapi", "urlscan", "URLSCAN_API_KEY"],
    "securitytrails": ["securitytrailsapi", "securitytrails"],
    "censys": ["censysapi", "censys"],
    "netlas": ["netlasapi", "netlas"],
    "fofa_key": ["fofaapi", "fofa"],
    "fofa_email": ["fofamail"],
    "criminalip": ["criminalipapi", "criminalip"],
    "whoisjson": ["whoisjsonapi", "whoisjson"],
    "ipinfo": ["ipinfoapi", "ipinfo"],
    "ipapisis": ["ipapisisapi", "ipapisis"],
}

HOST_RE = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*$", re.IGNORECASE)
ASSIGNMENT_RE = re.compile(r'^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"?(.*?)"?\s*$')

DEBUG = False
HOST_LOCK = threading.Lock()

class Color:
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    MAGENTA = "\033[95m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    END = "\033[0m"

@dataclass
class HostRecord:
    hostname: str
    sources: Set[str] = field(default_factory=set)
    evidence: List[str] = field(default_factory=list)
    first_seen: Optional[int] = None
    last_seen: Optional[int] = None
    resolved_ips: Set[str] = field(default_factory=set)
    resolves_to_target: bool = False

    def add(self, source: str, evidence: Optional[str] = None, ts: Optional[int] = None) -> None:
        self.sources.add(source)
        if evidence:
            self.evidence.append(evidence)
        if ts is not None:
            if self.first_seen is None or ts < self.first_seen:
                self.first_seen = ts
            if self.last_seen is None or ts > self.last_seen:
                self.last_seen = ts


def eprint(msg: str) -> None:
    print(msg, file=sys.stderr)

def dprint(msg: str) -> None:
    if DEBUG:
        print(f"{Color.DIM}[DEBUG] {msg}{Color.END}", file=sys.stderr)


def load_key_file(path: Path) -> Dict[str, str]:
    result: Dict[str, str] = {}
    if not path.exists() or not path.is_file():
        return result
    for line in path.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = ASSIGNMENT_RE.match(line)
        if not m:
            continue
        result[m.group(1)] = m.group(2)
    return result


def collect_keys(explicit_file: Optional[str]) -> Dict[str, str]:
    merged: Dict[str, str] = {}
    candidates: List[Path] = []
    if explicit_file:
        candidates.append(Path(explicit_file))
    candidates.extend([Path("/root/Tools/apikeys.txt"), Path("apikeys.txt")])

    for path in candidates:
        if path.exists():
            dprint(f"Loading keys from {path}")
            merged.update(load_key_file(path))

    merged.update({k: v for k, v in os.environ.items() if v})

    normalized: Dict[str, str] = {}
    for canonical, aliases in KEY_ALIASES.items():
        for alias in aliases:
            if alias in merged and merged[alias]:
                normalized[canonical] = merged[alias]
                break
    return normalized


def run_curl(args: List[str], timeout: int = 25, insecure: bool = False) -> Tuple[int, str, str]:
    cmd = ["curl", "-sS", "--max-time", str(timeout)]
    if insecure:
        cmd.append("-k")
    cmd += args
    dprint(f"Executing: {' '.join(cmd)}")
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        dprint(f"Curl error: {proc.stderr.strip()}")
    return proc.returncode, proc.stdout, proc.stderr


def curl_json(url: str, headers: Optional[Dict[str, str]] = None, auth: Optional[str] = None, method: str = "GET", data: Optional[str] = None, timeout: int = 25, insecure: bool = False) -> Optional[Any]:
    args: List[str] = []
    if method and method.upper() != "GET":
        args += ["-X", method.upper()]
    if headers:
        for k, v in headers.items():
            args += ["-H", f"{k}: {v}"]
    if auth:
        args += ["-u", auth]
    if data is not None:
        args += ["--data", data]
    args.append(url)

    code, out, err = run_curl(args, timeout=timeout, insecure=insecure)
    if code != 0:
        return None
    out = out.strip()
    if not out:
        return None
    dprint(f"Response from {url}: {out[:500]}{'...' if len(out) > 500 else ''}")
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        dprint(f"Failed to decode JSON from {url}")
        return None


def curl_text(url: str, timeout: int = 25, insecure: bool = False) -> Optional[str]:
    code, out, err = run_curl([url], timeout=timeout, insecure=insecure)
    if code != 0:
        return None
    return out


def is_valid_hostname(value: str) -> bool:
    if not value:
        return False
    h = value.strip().lower().rstrip(".")
    if not h or len(h) > 253:
        return False
    try:
        ipaddress.ip_address(h)
        return False
    except ValueError:
        pass
    return HOST_RE.match(h) is not None and "." in h


def normalize_hostname(value: str) -> Optional[str]:
    h = value.strip().lower().rstrip(".")
    if not is_valid_hostname(h):
        return None
    return h


def rev_ptr_name(ip: str) -> str:
    obj = ipaddress.ip_address(ip)
    return obj.reverse_pointer


def to_unix_ts(value: Any) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        v = int(value)
        if v > 10_000_000_000:
            v = int(v / 1000)
        return v
    if isinstance(value, str):
        v = value.strip()
        if not v:
            return None
        if v.isdigit():
            return to_unix_ts(int(v))
        for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            try:
                return int(time.mktime(time.strptime(v, fmt)))
            except ValueError:
                continue
    return None


def add_host(hosts: Dict[str, HostRecord], hostname: str, source: str, evidence: Optional[str] = None, ts: Optional[int] = None) -> None:
    h = normalize_hostname(hostname)
    if not h:
        return
    with HOST_LOCK:
        if h not in hosts:
            hosts[h] = HostRecord(hostname=h)
        hosts[h].add(source=source, evidence=evidence, ts=ts)


def source_ptr_local(ip: str, hosts: Dict[str, HostRecord]) -> None:
    try:
        primary, aliases, _ = socket.gethostbyaddr(ip)
        add_host(hosts, primary, "ptr_local", evidence="socket.gethostbyaddr")
        for alias in aliases:
            add_host(hosts, alias, "ptr_local", evidence="socket.gethostbyaddr alias")
    except Exception:
        return


def source_ptr_google_doh(ip: str, hosts: Dict[str, HostRecord], timeout: int) -> None:
    ptr = rev_ptr_name(ip)
    url = f"https://dns.google/resolve?name={ptr}&type=PTR"
    data = curl_json(url, timeout=timeout)
    if not isinstance(data, dict):
        return
    for ans in data.get("Answer", []) or []:
        hostname = str(ans.get("data", "")).strip('"')
        add_host(hosts, hostname, "ptr_google_doh", evidence=f"PTR {ptr}")


def source_shodan(ip: str, shodan_key: str, hosts: Dict[str, HostRecord], timeout: int) -> None:
    url = f"https://api.shodan.io/shodan/host/{ip}?key={shodan_key}"
    data = curl_json(url, timeout=timeout)
    if not isinstance(data, dict) or data.get("error"):
        return
    for hn in data.get("hostnames", []) or []:
        add_host(hosts, str(hn), "shodan", evidence="hostnames[]")
    for dom in data.get("domains", []) or []:
        add_host(hosts, str(dom), "shodan", evidence="domains[]")
    for item in data.get("data", []) or []:
        http = item.get("http") or {}
        if isinstance(http, dict):
            host = http.get("host")
            if host:
                add_host(hosts, str(host), "shodan", evidence="data[].http.host")


def source_virustotal(ip: str, vt_key: str, hosts: Dict[str, HostRecord], timeout: int, limit: int) -> None:
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}/resolutions?limit={limit}"
    data = curl_json(url, headers={"x-apikey": vt_key, "accept": "application/json"}, timeout=timeout)
    if not isinstance(data, dict):
        return
    for item in data.get("data", []) or []:
        attrs = item.get("attributes") or {}
        host = attrs.get("host_name")
        ts = to_unix_ts(attrs.get("date"))
        if host:
            add_host(hosts, str(host), "virustotal", evidence="ip/resolutions", ts=ts)


def source_riskiq(ip: str, user: str, key: str, hosts: Dict[str, HostRecord], timeout: int, insecure: bool = False) -> None:
    url = "https://api.passivetotal.org/v2/dns/passive/unique"
    payload = json.dumps({"query": ip})
    data = curl_json(url, auth=f"{user}:{key}", method="GET", headers={"Content-Type": "application/json"}, data=payload, timeout=timeout, insecure=insecure)
    if not isinstance(data, dict):
        return
    results = data.get("results") or []
    if isinstance(results, list):
        for r in results:
            if isinstance(r, str):
                add_host(hosts, r, "riskiq", evidence="dns/passive/unique")
            elif isinstance(r, dict):
                host = r.get("resolve") or r.get("value") or r.get("hostname")
                if host:
                    add_host(hosts, str(host), "riskiq", evidence="dns/passive/unique")


def source_otx(ip: str, otx_key: Optional[str], hosts: Dict[str, HostRecord], timeout: int, insecure: bool = False) -> None:
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/passive_dns"
    headers = {"X-OTX-API-KEY": otx_key} if otx_key else None
    data = curl_json(url, headers=headers, timeout=timeout, insecure=insecure)
    if not isinstance(data, dict):
        return
    for row in data.get("passive_dns", []) or []:
        host = row.get("hostname")
        ts = to_unix_ts(row.get("first") or row.get("last") or row.get("first_seen") or row.get("last_seen"))
        if host:
            add_host(hosts, str(host), "otx", evidence="passive_dns", ts=ts)


def source_threatcrowd(ip: str, hosts: Dict[str, HostRecord], timeout: int, insecure: bool = False) -> None:
    url = f"https://www.threatcrowd.org/searchApi/v2/ip/report/?ip={ip}"
    data = curl_json(url, timeout=timeout, insecure=insecure)
    if not isinstance(data, dict):
        return
    for r in data.get("resolutions", []) or []:
        if isinstance(r, str):
            add_host(hosts, r, "threatcrowd", evidence="resolutions[]")
        elif isinstance(r, dict):
            host = r.get("domain") or r.get("hostname")
            ts = to_unix_ts(r.get("last_resolved") or r.get("date"))
            if host:
                add_host(hosts, str(host), "threatcrowd", evidence="resolutions[]", ts=ts)


def source_hackertarget(ip: str, hosts: Dict[str, HostRecord], timeout: int) -> None:
    url = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
    text = curl_text(url, timeout=timeout)
    if not text:
        return
    if "error" in text.lower() or "api count exceeded" in text.lower():
        return
    for line in text.splitlines():
        h = line.strip()
        if h:
            add_host(hosts, h, "hackertarget", evidence="reverseiplookup")


def source_crtsh(ip: str, hosts: Dict[str, HostRecord], timeout: int) -> None:
    url = f"https://crt.sh/?q={ip}&output=json"
    data = curl_json(url, timeout=timeout)
    if not isinstance(data, list):
        return
    for cert in data:
        if not isinstance(cert, dict):
            continue
        name_val = cert.get("name_value")
        if not name_val:
            continue
        entry_ts = to_unix_ts(cert.get("entry_timestamp"))
        for raw_name in str(name_val).splitlines():
            if raw_name.startswith("*."):
                raw_name = raw_name[2:]
            add_host(hosts, raw_name, "crtsh", evidence="name_value", ts=entry_ts)


def source_urlscan(ip: str, api_key: Optional[str], hosts: Dict[str, HostRecord], timeout: int, limit: int) -> None:
    query = f"ip:{ip}"
    url = f"https://urlscan.io/api/v1/search/?q={query}&size={limit}"
    headers = {"API-Key": api_key} if api_key else None
    data = curl_json(url, headers=headers, timeout=timeout)
    if not isinstance(data, dict):
        return
    for result in data.get("results", []) or []:
        page = result.get("page") or {}
        task = result.get("task") or {}
        host = page.get("domain") or page.get("hostname") or task.get("domain")
        ts = to_unix_ts(result.get("task", {}).get("time") or result.get("indexedAt"))
        if host:
            add_host(hosts, str(host), "urlscan", evidence="search ip", ts=ts)

def source_securitytrails(ip: str, api_key: str, hosts: Dict[str, HostRecord], timeout: int) -> None:
    url = "https://api.securitytrails.com/v1/search/list"
    headers = {"apikey": api_key, "content-type": "application/json"}
    payload = json.dumps({"filter": {"ipv4": ip}})
    data = curl_json(url, headers=headers, method="POST", data=payload, timeout=timeout)
    if not isinstance(data, dict):
        return
    for record in data.get("records", []) or []:
        host = record.get("hostname")
        if host:
            add_host(hosts, host, "securitytrails", evidence="search/list")

def source_censys(ip: str, api_key: str, hosts: Dict[str, HostRecord], timeout: int) -> None:
    url = f"https://search.censys.io/api/v2/hosts/{ip}"
    auth = None
    headers = {}
    if ":" in api_key:
        auth = api_key
    else:
        key_b64 = base64.b64encode(f"{api_key}:".encode()).decode()
        headers["Authorization"] = f"Basic {key_b64}"
    
    data = curl_json(url, auth=auth, headers=headers, timeout=timeout)
    if not isinstance(data, dict) or data.get("code") != 200:
        return
    result = data.get("result", {})
    for service in result.get("services", []):
        for name in service.get("names", []):
            add_host(hosts, name, "censys", evidence="services[].names")

def source_netlas(ip: str, api_key: str, hosts: Dict[str, HostRecord], timeout: int) -> None:
    url = f"https://app.netlas.io/api/v1/host/{ip}?api_key={api_key}"
    data = curl_json(url, timeout=timeout)
    if not isinstance(data, dict):
        return
    host = data.get("hostname")
    if host:
        add_host(hosts, host, "netlas", evidence="hostname")

def source_fofa(ip: str, email: Optional[str], key: str, hosts: Dict[str, HostRecord], timeout: int) -> None:
    query = f'ip="{ip}"'
    q_base64 = base64.b64encode(query.encode()).decode()
    url = f"https://fofa.info/api/v1/search/all?qbase64={q_base64}&key={key}"
    if email:
        url += f"&email={email}"
    data = curl_json(url, timeout=timeout)
    if not isinstance(data, dict) or data.get("error"):
        return
    for result in data.get("results", []) or []:
        if isinstance(result, list) and len(result) > 0:
            host = result[0]
            if "://" in host:
                host = host.split("://", 1)[1]
            if ":" in host:
                host = host.split(":", 1)[0]
            add_host(hosts, host, "fofa", evidence="results[]")

def source_criminalip(ip: str, api_key: str, hosts: Dict[str, HostRecord], timeout: int, insecure: bool = False) -> None:
    url = f"https://api.criminalip.io/v1/asset/ip/report?ip={ip}"
    headers = {"x-api-key": api_key}
    data = curl_json(url, headers=headers, timeout=timeout, insecure=insecure)
    if not isinstance(data, dict):
        return
    host_data = data.get("hostname")
    if isinstance(host_data, str):
        add_host(hosts, host_data, "criminalip", evidence="hostname")
    elif isinstance(host_data, dict):
        for item in host_data.get("data", []) or []:
            h = item.get("hostname")
            if h:
                add_host(hosts, h, "criminalip", evidence="hostname.data[]")

def source_whoisjson(ip: str, api_key: str, hosts: Dict[str, HostRecord], timeout: int) -> None:
    url = f"https://whoisjson.com/api/v1/reverse-ip?ip={ip}&api_key={api_key}"
    data = curl_json(url, timeout=timeout)
    if not isinstance(data, dict):
        return
    for entry in data.get("results", []) or []:
        host = entry.get("domain") or entry.get("name")
        if host:
            add_host(hosts, host, "whoisjson", evidence="reverse-ip")

def source_ipinfo(ip: str, api_key: str, hosts: Dict[str, HostRecord], timeout: int) -> None:
    url = f"https://ipinfo.io/{ip}?token={api_key}"
    data = curl_json(url, timeout=timeout)
    if not isinstance(data, dict):
        return
    host = data.get("hostname")
    if host:
        add_host(hosts, host, "ipinfo", evidence="hostname")

def source_ipapisis(ip: str, api_key: str, hosts: Dict[str, HostRecord], timeout: int) -> None:
    url = f"https://api.ipapi.is/?ip={ip}&key={api_key}"
    data = curl_json(url, timeout=timeout)
    if not isinstance(data, dict):
        return
    host = data.get("asn", {}).get("route")
    if host and is_valid_hostname(host):
        add_host(hosts, host, "ipapisis", evidence="asn.route")

def format_vt_score(mal: Optional[int], tot: Optional[int]) -> str:
    if mal is None:
        return f"{Color.DIM}(?/?){Color.END}"
    score_str = f"({mal}/{tot})"
    if mal == 0:
        return f"{Color.GREEN}{score_str}{Color.END}"
    elif mal <= 2:
        return f"{Color.YELLOW}{score_str}{Color.END}"
    else:
        return f"{Color.RED}{score_str}{Color.END}"

def get_vt_malicious_score(ip: str, vt_key: str, timeout: int) -> Tuple[Optional[int], Optional[int]]:
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    data = curl_json(url, headers={"x-apikey": vt_key, "accept": "application/json"}, timeout=timeout)
    if not isinstance(data, dict):
        return None, None
    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    if not stats:
        return None, None
    malicious = stats.get("malicious", 0)
    total = sum(stats.values())
    return malicious, total

def resolve_hostname(hostname: str, timeout: float = 4.0) -> Set[str]:
    resolved: Set[str] = set()
    previous = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        info = socket.getaddrinfo(hostname, None)
        for row in info:
            sockaddr = row[4]
            if not sockaddr:
                continue
            ip = sockaddr[0]
            try:
                ipaddress.ip_address(ip)
                resolved.add(ip)
            except ValueError:
                continue
    except Exception:
        pass
    finally:
        socket.setdefaulttimeout(previous)
    return resolved


def enrich_resolution(hosts: Dict[str, HostRecord], target_ip: str, threads: int) -> None:
    items = list(hosts.items())
    if not items:
        return
    with ThreadPoolExecutor(max_workers=max(2, threads)) as ex:
        futures = {ex.submit(resolve_hostname, h): h for h, _ in items}
        for fut in as_completed(futures):
            h = futures[fut]
            ips = fut.result()
            rec = hosts[h]
            rec.resolved_ips = ips
            rec.resolves_to_target = target_ip in ips


def fmt_ts(ts: Optional[int]) -> str:
    if ts is None:
        return "-"
    try:
        return time.strftime("%Y-%m-%d", time.gmtime(ts))
    except Exception:
        return "-"


def summarize(hosts: Dict[str, HostRecord], target_ip: str, include_unresolved: bool, vt_mal: Optional[int] = None, vt_tot: Optional[int] = None) -> Dict[str, Any]:
    current: List[Dict[str, Any]] = []
    historical: List[Dict[str, Any]] = []

    for h in sorted(hosts):
        rec = hosts[h]
        item = {
            "hostname": rec.hostname,
            "sources": sorted(rec.sources),
            "first_seen": rec.first_seen,
            "last_seen": rec.last_seen,
            "resolved_ips": sorted(rec.resolved_ips),
            "resolves_to_target": rec.resolves_to_target,
        }
        if rec.resolves_to_target:
            current.append(item)
        elif include_unresolved:
            historical.append(item)

    return {
        "target_ip": target_ip,
        "vt_score": {"malicious": vt_mal, "total": vt_tot},
        "totals": {
            "distinct_hostnames": len(hosts),
            "currently_resolve_to_target": len(current),
            "historical_or_other": len(historical),
        },
        "current": current,
        "historical": historical,
    }


def print_human(result: Dict[str, Any]) -> None:
    ip = result["target_ip"]
    totals = result["totals"]
    vt = result.get("vt_score") or {}
    vt_fmt = format_vt_score(vt.get("malicious"), vt.get("total"))

    print(f"{Color.BOLD}{Color.BLUE}Target IP:{Color.END} {Color.YELLOW}{ip}{Color.END} {vt_fmt}")
    print(f"{Color.DIM}Found {totals['distinct_hostnames']} unique hostnames.{Color.END}")
    print("")

    if result["current"]:
        print(f"{Color.BOLD}{Color.GREEN}>>> ACTIVE RESOLUTIONS (Primary) <<<{Color.END}")
        for item in result["current"]:
            srcs = f"{Color.DIM}({','.join(item['sources'])}){Color.END}"
            last = f" {Color.CYAN}[{fmt_ts(item['last_seen'])}]{Color.END}" if item['last_seen'] else ""
            print(f" {Color.BOLD}{Color.GREEN}* {item['hostname']}{Color.END}{last} {srcs}")
    else:
        print(f"{Color.RED}No active resolutions found.{Color.END}")

    print("")
    if result["historical"]:
        print(f"{Color.BOLD}{Color.MAGENTA}>>> HISTORICAL / PLAN B FINDINGS <<<{Color.END}")
        for item in result["historical"]:
            srcs = f"{Color.DIM}{','.join(item['sources'])}{Color.END}"
            res = f" {Color.RED}→ {','.join(item['resolved_ips'])}{Color.END}" if item['resolved_ips'] else ""
            print(f" {Color.DIM}- {item['hostname']}{Color.END}{res} {srcs}")


def run_source(func, *args):
    try:
        func(*args)
    except Exception as e:
        dprint(f"Source {func.__name__} failed: {e}")

def process_ip(ip: str, keys: Dict[str, str], args: argparse.Namespace, is_batch: bool = False) -> Optional[Dict[str, Any]]:
    try:
        ip_obj = ipaddress.ip_address(ip)
        target_ip = ip_obj.exploded
    except ValueError:
        if not is_batch:
            eprint(f"{Color.RED}[error] Invalid IP: {ip}{Color.END}")
        return None

    hosts: Dict[str, HostRecord] = {}
    vt_mal, vt_tot = None, None

    # Parallel source collection
    with ThreadPoolExecutor(max_workers=20) as executor:
        tasks = []
        tasks.append(executor.submit(run_source, source_ptr_local, target_ip, hosts))
        tasks.append(executor.submit(run_source, source_ptr_google_doh, target_ip, hosts, args.timeout))
        tasks.append(executor.submit(run_source, source_hackertarget, target_ip, hosts, args.timeout))
        
        if k := keys.get("shodan"):
            tasks.append(executor.submit(run_source, source_shodan, target_ip, k, hosts, args.timeout))
        
        if k := keys.get("virustotal"):
            # Get malicious score
            def run_vt_score():
                nonlocal vt_mal, vt_tot
                vt_mal, vt_tot = get_vt_malicious_score(target_ip, k, args.timeout)
            tasks.append(executor.submit(run_vt_score))

        if not is_batch:
            # Full source list for single IP
            tasks.append(executor.submit(run_source, source_threatcrowd, target_ip, hosts, args.timeout, args.insecure))
            tasks.append(executor.submit(run_source, source_crtsh, target_ip, hosts, args.timeout))
            tasks.append(executor.submit(run_source, source_urlscan, target_ip, keys.get("urlscan"), hosts, args.timeout, args.urlscan_limit))
            if k := keys.get("virustotal"):
                tasks.append(executor.submit(run_source, source_virustotal, target_ip, k, hosts, args.timeout, args.vt_limit))
            if k := keys.get("otx"):
                tasks.append(executor.submit(run_source, source_otx, target_ip, k, hosts, args.timeout, args.insecure))
            if (u := keys.get("riskiq_user")) and (k := keys.get("riskiq_key")):
                tasks.append(executor.submit(run_source, source_riskiq, target_ip, u, k, hosts, args.timeout, args.insecure))
            if k := keys.get("securitytrails"):
                tasks.append(executor.submit(run_source, source_securitytrails, target_ip, k, hosts, args.timeout))
            if k := keys.get("censys"):
                tasks.append(executor.submit(run_source, source_censys, target_ip, k, hosts, args.timeout))
            if k := keys.get("netlas"):
                tasks.append(executor.submit(run_source, source_netlas, target_ip, k, hosts, args.timeout))
            if k := keys.get("fofa_key"):
                tasks.append(executor.submit(run_source, source_fofa, target_ip, keys.get("fofa_email"), k, hosts, args.timeout))
            if k := keys.get("criminalip"):
                tasks.append(executor.submit(run_source, source_criminalip, target_ip, k, hosts, args.timeout, args.insecure))
            if k := keys.get("whoisjson"):
                tasks.append(executor.submit(run_source, source_whoisjson, target_ip, k, hosts, args.timeout))
            if k := keys.get("ipinfo"):
                tasks.append(executor.submit(run_source, source_ipinfo, target_ip, k, hosts, args.timeout))
            if k := keys.get("ipapisis"):
                tasks.append(executor.submit(run_source, source_ipapisis, target_ip, k, hosts, args.timeout))

        for _ in as_completed(tasks):
            pass

    enrich_resolution(hosts, target_ip=target_ip, threads=args.threads)
    return summarize(hosts, target_ip=target_ip, include_unresolved=not args.only_current, vt_mal=vt_mal, vt_tot=vt_tot)

def run(args: argparse.Namespace) -> int:
    global DEBUG
    DEBUG = args.debug

    keys = collect_keys(args.keyfile)
    ips: List[str] = []
    
    if args.ip:
        ips.append(args.ip)
    if args.file:
        p = Path(args.file)
        if p.exists():
            ips.extend([l.strip() for l in p.read_text().splitlines() if l.strip()])
    if args.range:
        try:
            net = ipaddress.ip_network(args.range, strict=False)
            ips.extend([str(ip) for ip in net.hosts()])
        except ValueError:
            eprint(f"{Color.RED}[error] Invalid range: {args.range}{Color.END}")

    if not ips:
        eprint(f"{Color.RED}[error] No IP or range specified. Use -ip, -f, or -r.{Color.END}")
        return 1

    if len(ips) == 1:
        res = process_ip(ips[0], keys, args, is_batch=False)
        if not res:
            return 2
        if args.json:
            print(json.dumps(res, indent=2))
        else:
            print_human(res)
    else:
        # Batch mode
        dprint(f"Starting batch lookup for {len(ips)} IPs...")
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(process_ip, ip, keys, args, is_batch=True): ip for ip in ips}
            for fut in as_completed(futures):
                ip = futures[fut]
                res = fut.result()
                if not res:
                    continue
                
                # Pick primary resolution
                if res["current"]:
                    hn = res["current"][0]["hostname"]
                    hostname = f"{Color.BOLD}{Color.GREEN}{hn:<40}{Color.END}"
                elif res["historical"]:
                    hn = res["historical"][0]["hostname"]
                    hostname = f"{Color.DIM}{hn:<40}{Color.END}"
                else:
                    hostname = f"{Color.RED}{'N/A':<40}{Color.END}"
                
                vt = res.get("vt_score") or {}
                vt_fmt = format_vt_score(vt.get("malicious"), vt.get("total"))
                
                print(f"{Color.YELLOW}{ip:<15}{Color.END} : {hostname} {vt_fmt}")

    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Find distinct current + historical hostnames related to an IP.")
    p.add_argument("-ip", "--ip", help="Target IPv4/IPv6 address")
    p.add_argument("-f", "--file", help="File containing list of IPs")
    p.add_argument("-r", "--range", help="CIDR range (e.g. 1.1.1.0/24)")
    p.add_argument("--keyfile", help="Path to key file")
    p.add_argument("--timeout", type=int, default=20, help="Curl timeout per source")
    p.add_argument("--threads", type=int, default=32, help="DNS resolution threads")
    p.add_argument("--vt-limit", type=int, default=40, help="VirusTotal limit")
    p.add_argument("--urlscan-limit", type=int, default=100, help="urlscan limit")
    p.add_argument("--only-current", action="store_true", help="Only show current resolutions")
    p.add_argument("--json", action="store_true", help="JSON output")
    p.add_argument("--debug", action="store_true", help="Debug mode")
    p.add_argument("--insecure", action="store_true", help="Insecure curl")
    return p


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return run(args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        eprint(f"\n{Color.RED}[!] Interrupted by user.{Color.END}")
        sys.exit(130)
