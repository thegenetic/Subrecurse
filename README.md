# Subrecurse

**Recursive subdomain enumeration with advanced wildcard detection, ENT awareness, HTTP verification, and cascade prevention.**

Subrecurse is a high‑performance DNS brute‑forcer that recursively discovers subdomains while intelligently filtering out false positives caused by wildcard DNS records and generic catch‑all pages. It combines multi‑threaded DNS resolution with optional HTTP fingerprinting to deliver clean, actionable results.

## Why Subrecurse?

Most subdomain enumeration tools either miss empty non‑terminals (ENTs) or drown in false positives from wildcard records. Subrecurse solves both problems:

- **Two‑tier wildcard detection** distinguishes between stable and rotating wildcards, applying the appropriate filtering.
- **Recursive result capping** prevents explosion on domains with many valid but uninteresting infrastructure entries (e.g., ISP‑specific reverse DNS records, load‑balancer pools).
- **HTTP verification** (optional) eliminates wildcard pages that serve generic 404s or identical content.

## Features

- **Recursive enumeration** - Automatically feeds discovered subdomains back into the queue for deeper discovery.
- **Smart wildcard filtering** - Uses multiple probes per record type, detects stable vs. rotating wildcards, and blocks false positives.
- **ENT (Empty Non‑Terminal) detection** - Identifies domains that exist in DNS but have no resource records (yellow output).
- **HTTP verification (optional)** - Validates subdomains by checking HTTP response status codes and content hashes to filter catch‑all pages.
- **Recursive cap with cascade prevention** - Limits results per recursive domain to avoid combinatorial noise.
- **Multi‑threaded** - Configurable concurrency for speed.
- **Progress indicator** - Real‑time word processing rate and ETA.
- **Flexible output** - Plain text and JSON formats.

## Installation

```bash
git clone https://github.com/thegenetic/Subrecurse.git
cd Subrecurse
pip install -r requirements.txt
```

## Usage

```bash
python subrecurse.py -t example.com -w wordlist.txt
```

### Basic Options

| Flag | Description |
|------|-------------|
| `-t, --target` | Target domain (required) |
| `-w, --wordlist` | Path to wordlist file (required) |
| `-T, --threads` | Number of threads (default: 20, max 100) |
| `-o, --output` | Save results to plain text file |
| `--json` | Save results to JSON file |
| `--delay` | Delay in seconds between DNS queries (default: 0) |
| `--depth` | Maximum recursion depth (default: 3) |
| `--exclude` | Skip subdomains whose labels match these strings (e.g., `dev staging`) |
| `-v, --verbose` | Show debug output |
| `--version` | Show version and exit |

### Recursive Limit

| Flag | Description |
|------|-------------|
| `--recursive-limit N` | Stop brute‑forcing a recursive domain after `N` results (default: 10; use `0` for unlimited). Prevents explosion on domains with many valid but uninteresting subdomains. |

### HTTP Verification (Optional)

| Flag | Description |
|------|-------------|
| `--http-verify` | Enable HTTP verification to filter wildcard pages. |
| `--http-ports` | Ports to check (default: `80 443`) |
| `--http-status` | Acceptable HTTP status codes (default: `200 201 204 301 302 307 308`) |
| `--http-fingerprint` | Strings that indicate a wildcard page (e.g., `"custom 404"` or `"Page not found"`). |

## Examples

**Basic enumeration:**
```bash
python subrecurse.py -t example.com -w subdomains.txt
```

**High‑speed scan with rate limiting:**
```bash
python subrecurse.py -t example.com -w subdomains.txt -T 50 --delay 0.01
```

**Exclude development and staging subdomains:**
```bash
python subrecurse.py -t example.com -w subdomains.txt --exclude dev staging
```

**Save results to text and JSON:**
```bash
python subrecurse.py -t example.com -w subdomains.txt -o results.txt --json results.json
```

**Enable HTTP verification with custom fingerprint:**
```bash
python subrecurse.py -t example.com -w subdomains.txt --http-verify --http-fingerprint "404 Not Found"
```

**Increase recursion depth and raise the recursive cap:**
```bash
python subrecurse.py -t example.com -w subdomains.txt --depth 5 --recursive-limit 20
```

## Output

- **Green** `[A]`, `[AAAA]`, `[CNAME]`, `[MX]`, etc. – Subdomain with valid DNS records.
- **Yellow** `[ENT]` – Empty Non‑Terminal (domain exists but has no records of any common type).

The tool prints results in real time and, if requested, writes them to a plain text file and/or a JSON file.

### JSON Output Example

```json
{
  "target": "example.com",
  "subdomains": [
    "api.example.com",
    "mail.example.com",
    "dev.example.com"
  ],
  "stats": {
    "total_queries": 1523,
    "found_subdomains": 12,
    "ent_found": 2,
    "wildcard_skipped": 87,
    "http_verified": 5,
    "http_filtered": 3,
    "recursive_capped": 1,
    "timeouts": 3,
    "servfails": 1,
    "errors": 0,
    "words_processed": 5000
  }
}
```

## How It Works

### 1. Wildcard Detection
Subrecurse probes multiple random subdomains for each record type (`A`, `AAAA`, `TXT`). It distinguishes:
- **Stable wildcards** – all probes return the same records. Candidates are skipped only if their records match the stable signature.
- **Rotating wildcards** – responses vary across probes (common with CDNs). Subrecurse blocks recursion from such domains to avoid false cascades.

### 2. ENT Detection
If a domain returns `NOERROR` but no records for any queried type, Subrecurse flags it as an **Empty Non‑Terminal** – a valid DNS node that simply lacks records.

### 3. Recursive Enumeration
Discovered subdomains are added to the work queue with an incremented depth counter, allowing discovery of deeper hierarchies (e.g., `api.staging.example.com`).

### 4. Recursive Cap & Cascade Prevention
When a recursive domain yields more than `--recursive-limit` results, Subrecurse marks it as *capped* and **stops further brute‑forcing of that domain** (and blocks recursion into its children). This prevents exponential growth on domains with thousands of infrastructure entries such as ISP‑specific reverse DNS names or load‑balancer pools.

### 5. HTTP Verification (Optional)
When `--http-verify` is enabled, Subrecurse performs a lightweight HTTP check on each discovered subdomain:
- Acceptable status codes (`--http-status`) allow the subdomain to pass.
- If `--http-fingerprint` strings are provided, the response body is scanned; a match causes rejection.
- Additionally, Subrecurse fetches a random subdomain of the parent to compute a **content hash**. If the candidate's hash and status code match the wildcard page, it is filtered out automatically.

## Contributing

Issues and pull requests are welcome! Please ensure your code passes basic linting and is compatible with Python 3.6+.
