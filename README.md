# 🔍 SSRF Prober

> Professional SSRF detection tool for authorized penetration testing and bug bounty programs.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Kali-lightgrey?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![BugBounty](https://img.shields.io/badge/Use%20Case-Bug%20Bounty%20%7C%20Pentesting-red?style=flat-square)

---

## ⚠️ Legal Disclaimer

This tool is intended **exclusively for authorized security testing**.  
Only use it on systems you have **explicit written permission** to test.  
The author is not responsible for any misuse or damage caused by this tool.

---

## ✨ Features

- ⚡ **Async engine** — concurrent probes via `httpx` + `asyncio`
- 🎯 **50+ payloads** — localhost variants, cloud metadata (AWS/GCP/Azure), internal services
- 🔀 **Bypass techniques** — gopher/dict/file protocols, IP encoding, Unicode tricks
- 📡 **OOB support** — Burp Collaborator, interactsh, custom callback servers
- 💉 **Flexible injection** — GET params, JSON body, multiple params at once
- 🔍 **Smart detection** — response analysis with severity scoring (CRITICAL → INFO)
- 🌈 **Rich UI** — live progress bar with real-time findings
- 📤 **JSON output** — save results for reporting
- 🔀 **Proxy support** — route through Burp Suite

---

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/ssrf-prober.git
cd ssrf-prober

# Install dependencies
pip install -r requirements.txt

# (Optional) Make executable
chmod +x ssrf_prober.py
```

---

## 🚀 Usage

```bash
python3 ssrf_prober.py [options]
```

### Options

```
  -u URL        Target URL. Use FUZZ as injection point
  -l LIST       File with list of target URLs (one per line)
  -p PARAMS     Comma-separated params to inject (default: url)
  -d DATA       JSON body template with FUZZ placeholder
  --json        Send as JSON POST
  --oob HOST    OOB callback host (Burp Collaborator / interactsh)
  -H HEADER     Extra header (can repeat: -H "Name: Value")
  --cookie VAL  Cookie header value
  --proxy URL   HTTP proxy (e.g. http://127.0.0.1:8080)
  --timeout N   Request timeout in seconds (default: 8)
  -c N          Max concurrent requests (default: 20)
  --no-verify   Disable SSL verification
  --all         Include bypass payloads (gopher, dict, file://, encodings)
  -o FILE       Save results to JSON file
  -v            Verbose — show all requests including non-findings
```

---

## 📋 Examples

### Basic GET parameter injection
```bash
python3 ssrf_prober.py -u "https://target.com/fetch?url=FUZZ"
```

### Multiple parameters
```bash
python3 ssrf_prober.py -u "https://target.com/api" \
    -p "url,redirect,src,callback,endpoint,host,uri"
```

### JSON POST body
```bash
python3 ssrf_prober.py -u "https://api.target.com/proxy" \
    -d '{"endpoint":"FUZZ","method":"GET"}' --json
```

### With authentication + OOB server
```bash
python3 ssrf_prober.py -u "https://target.com/fetch?url=FUZZ" \
    -H "Authorization: Bearer YOUR_TOKEN" \
    --oob your-id.oastify.com \
    --all -o results.json
```

### Full engagement workflow (through Burp Suite)
```bash
python3 ssrf_prober.py -u "https://target.com/api?url=FUZZ" \
    --cookie "session=abc123" \
    --proxy http://127.0.0.1:8080 \
    --no-verify --all -c 10 \
    -o ssrf_results.json
```

### From URL list
```bash
python3 ssrf_prober.py -l targets.txt --all -o results.json
```

---

## 🎯 Payload Coverage

| Category | Count | Examples |
|---|---|---|
| Localhost variants | 10 | `127.0.0.1`, `0x7f000001`, `0177.0.0.1`, `2130706433`, `[::1]` |
| Cloud metadata | 8 | AWS IMDS, GCP metadata, Azure IMDS, Alibaba |
| Internal services | 15 | Redis, Elasticsearch, Docker daemon, Consul, Grafana, WebLogic |
| Bypass payloads (`--all`) | 15+ | `gopher://`, `dict://`, `file://`, Unicode IPs, double URL encoding |
| OOB callbacks | Dynamic | Generated from `--oob` host |

---

## 🔎 Detection Engine

The tool analyzes responses for indicators across multiple severity levels:

| Severity | Example Indicators |
|---|---|
| 🔴 CRITICAL | AWS credentials, `/etc/passwd` content, Redis info, Docker daemon |
| 🟠 HIGH | GCP/Azure metadata, Elasticsearch, internal IP ranges |
| 🟡 MEDIUM | Localhost references, redirect to internal resource |
| 🔵 LOW | Unusual status codes, generic error messages |
| ⚪ INFO | Timeouts (possible blind SSRF), connection errors |

---

## 📁 Project Structure

```
ssrf-prober/
├── ssrf_prober.py      # Main tool
├── requirements.txt    # Python dependencies
├── install.sh          # One-line installer for Linux/Kali
└── README.md
```

---

## 🤝 Contributing

Pull requests are welcome. For major changes, please open an issue first.

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.
