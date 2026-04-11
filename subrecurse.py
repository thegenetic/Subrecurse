#!/usr/bin/env python3
"""
Subrecurse - Recursive Subdomain Enumeration with Wildcard, ENT & HTTP Verification
Author: Dipesh Paul
Version: 1.0.0
"""

import argparse
import dns.resolver
import threading
import queue
import uuid
import time
import signal
import sys
import json
import hashlib
import requests
import urllib3
from colorama import Fore, Style, init
from functools import lru_cache
from threading import Event, Thread

# Suppress SSL warnings from unverified requests used in HTTP wildcard probing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

init(autoreset=True)

# ----------------------------------------------------------------------
# Global Statistics and Locks
# ----------------------------------------------------------------------
stats = {
    'total_queries': 0,
    'found_subdomains': 0,
    'ent_found': 0,
    'errors': 0,
    'timeouts': 0,
    'servfails': 0,
    'words_processed': 0,
    'wildcard_skipped': 0,
    'http_verified': 0,
    'http_filtered': 0,
    'recursive_capped': 0,
}
stats_lock = threading.Lock()

# Per‑domain result counters (for recursive limit)
domain_hit_counts: dict = {}
domain_counts_lock = threading.Lock()

# Set of domains that have reached the recursive cap (to block deeper recursion)
capped_set = set()
capped_lock = threading.Lock()

# ----------------------------------------------------------------------
# Thread‑local Resolver & HTTP Session
# ----------------------------------------------------------------------
thread_local = threading.local()

def get_thread_resolver():
    if not hasattr(thread_local, 'resolver'):
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 2
        resolver.timeout = 2
        thread_local.resolver = resolver
    return thread_local.resolver

def get_thread_session():
    if not hasattr(thread_local, 'session'):
        session = requests.Session()
        session.headers.update({'User-Agent': 'Mozilla/5.0 (compatible; Subrecurse/2.1)'})
        session.timeout = 5
        thread_local.session = session
    return thread_local.session

# ----------------------------------------------------------------------
# Robust Wildcard Detection (with retries)
# ----------------------------------------------------------------------
def probe_wildcard(domain, record_type):
    resolver = get_thread_resolver()
    resolver.timeout = 3
    resolver.lifetime = 3
    for attempt in range(2):
        try:
            random_label = uuid.uuid4().hex
            test_domain = f"{random_label}.{domain}"
            answers = resolver.resolve(test_domain, record_type)
            return frozenset(str(r) for r in answers)
        except (dns.resolver.Timeout, dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            if attempt == 0:
                time.sleep(0.5)
            continue
        except Exception:
            return None
    return None

@lru_cache(maxsize=1000)
def get_wildcard_info(domain, record_type='A', num_probes=3):
    """
    Returns (is_wildcard, stable_sig).
    - is_wildcard: True if ANY random subdomain resolved.
    - stable_sig: frozenset if all probes returned identical records, else None.
    """
    sigs = []
    for _ in range(num_probes):
        sig = probe_wildcard(domain, record_type)
        if sig is not None:
            sigs.append(sig)

    if not sigs:
        return (False, None)

    if len(sigs) >= 2 and all(s == sigs[0] for s in sigs):
        return (True, sigs[0])

    return (True, None)   # rotating wildcard

# ----------------------------------------------------------------------
# HTTP Wildcard Fingerprinting
# ----------------------------------------------------------------------
@lru_cache(maxsize=500)
def get_http_wildcard_hash(domain, timeout=5):
    """
    Probe a random subdomain of *domain* over HTTPS then HTTP.
    Returns (status_code, content_md5_hex) if a catch‑all page exists,
    otherwise None.
    """
    probe = f"{uuid.uuid4().hex}.{domain}"
    for scheme in ('https', 'http'):
        url = f"{scheme}://{probe}"
        try:
            resp = requests.get(
                url, timeout=timeout, allow_redirects=True,
                headers={'User-Agent': 'Mozilla/5.0 (compatible; Subrecurse/2.1)'},
                verify=False
            )
            content_hash = hashlib.md5(resp.content[:8192]).hexdigest()
            return (resp.status_code, content_hash)
        except Exception:
            continue
    return None

# ----------------------------------------------------------------------
# ENT Detection
# ----------------------------------------------------------------------
def check_domain(domain, record_types=None, verbose=False):
    if record_types is None:
        record_types = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'PTR', 'SRV', 'CAA', 'DS', 'DNSKEY']

    resolver = get_thread_resolver()
    for rtype in record_types:
        try:
            answers = resolver.resolve(domain, rtype)
            if answers:
                if verbose:
                    print(Fore.CYAN + f"[DEBUG] {domain} has {rtype} records")
                return (True, False, rtype)
        except dns.resolver.NoAnswer:
            continue
        except dns.resolver.NXDOMAIN:
            return (False, False, None)
        except dns.resolver.Timeout:
            with stats_lock:
                stats['timeouts'] += 1
            continue
        except dns.resolver.SERVFAIL:
            with stats_lock:
                stats['servfails'] += 1
            continue
        except Exception as e:
            if verbose:
                print(Fore.RED + f"[DEBUG] {domain} error: {e}")
            continue

    try:
        resolver.resolve(domain, 'NS')
        return (True, False, 'NS')
    except dns.resolver.NoAnswer:
        return (True, True, None)
    except dns.resolver.NXDOMAIN:
        return (False, False, None)
    except Exception:
        return (False, False, None)

# ----------------------------------------------------------------------
# HTTP Verification
# ----------------------------------------------------------------------
def http_verify(subdomain, parent_domain=None, http_ports=(80, 443),
                verify_status=(200, 201, 204, 301, 302, 307, 308),
                wildcard_fingerprints=None, timeout=5, verbose=False):
    """
    Returns True if the subdomain appears legitimate.
    Uses both manual fingerprints and automatic content‑hash comparison.
    """
    if wildcard_fingerprints is None:
        wildcard_fingerprints = []

    http_wc_hash = None
    if parent_domain:
        http_wc_hash = get_http_wildcard_hash(parent_domain, timeout=timeout)

    session = get_thread_session()
    for scheme in ('https', 'http'):
        for port in http_ports:
            if (scheme == 'https' and port == 80) or (scheme == 'http' and port == 443):
                continue
            url = f"{scheme}://{subdomain}:{port}"
            try:
                resp = session.head(url, timeout=timeout, allow_redirects=True)
                if resp.status_code in verify_status:
                    # Manual fingerprints
                    if wildcard_fingerprints:
                        resp_get = session.get(url, timeout=timeout)
                        content = resp_get.text[:5000]
                        if any(fp in content for fp in wildcard_fingerprints):
                            if verbose:
                                print(Fore.MAGENTA + f"[DEBUG] HTTP fingerprint matched (wildcard): {subdomain}")
                            with stats_lock:
                                stats['http_filtered'] += 1
                            return False

                    # Automatic content‑hash comparison
                    if http_wc_hash is not None:
                        try:
                            resp_get = session.get(url, timeout=timeout, allow_redirects=True)
                            cand_hash = hashlib.md5(resp_get.content[:8192]).hexdigest()
                            if cand_hash == http_wc_hash[1] and resp.status_code == http_wc_hash[0]:
                                if verbose:
                                    print(Fore.MAGENTA + f"[DEBUG] HTTP content‑hash matches wildcard: {subdomain}")
                                with stats_lock:
                                    stats['http_filtered'] += 1
                                return False
                        except Exception:
                            pass

                    with stats_lock:
                        stats['http_verified'] += 1
                    return True
                else:
                    if verbose:
                        print(Fore.MAGENTA + f"[DEBUG] HTTP status {resp.status_code} filtered: {subdomain}")
                    return False
            except (requests.exceptions.Timeout, requests.exceptions.ConnectionError,
                    requests.exceptions.SSLError, requests.exceptions.TooManyRedirects):
                continue
            except Exception as e:
                if verbose:
                    print(Fore.RED + f"[DEBUG] HTTP error {subdomain}: {e}")
                continue
    with stats_lock:
        stats['http_filtered'] += 1
    return False

# ----------------------------------------------------------------------
# Progress Indicator
# ----------------------------------------------------------------------
class ProgressIndicator:
    def __init__(self, total_words, target):
        self.total = total_words
        self.target = target
        self.processed = 0
        self.found = 0
        self.start_time = time.time()
        self.running = Event()
        self.thread = None

    def update(self, processed=None, found=None):
        if processed is not None:
            self.processed = processed
        if found is not None:
            self.found = found

    def _run(self):
        while self.running.is_set():
            elapsed = time.time() - self.start_time
            rate = self.processed / elapsed if elapsed > 0 else 0
            eta = (self.total - self.processed) / rate if rate > 0 else 0
            status = (f"\r[*] {self.target}: {self.processed}/{self.total} words "
                      f"| Found: {self.found} | {rate:.1f} w/s | ETA: {eta/60:.1f}m   ")
            sys.stdout.write(status)
            sys.stdout.flush()
            time.sleep(1.0)

    def start(self):
        self.running.set()
        self.thread = Thread(target=self._run, daemon=True)
        self.thread.start()

    def stop(self):
        self.running.clear()
        if self.thread:
            self.thread.join(timeout=1)
        sys.stdout.write("\r" + " " * 80 + "\r")
        sys.stdout.flush()

# ----------------------------------------------------------------------
# Worker Thread
# ----------------------------------------------------------------------
def worker(work_queue, wordlist, seen_lock, seen_set, results_lock, results_set,
           stop_sentinel, output_file=None, output_lock=None, delay=0.0,
           max_depth=3, exclude_patterns=None, verbose=False,
           progress=None, progress_lock=None, base_domain=None,
           http_verify_flag=False, http_ports=(80, 443), verify_status=(200,),
           wildcard_fingerprints=None, recursive_limit=10):

    HIGH_CONFIDENCE_TYPES = ['CNAME', 'MX', 'NS', 'SOA']
    WILDCARD_CHECK_TYPES  = ['A', 'AAAA', 'TXT']

    while True:
        try:
            item = work_queue.get(timeout=1)
        except queue.Empty:
            continue

        if item is stop_sentinel:
            work_queue.task_done()
            break

        domain, current_depth = item

        if current_depth > max_depth:
            work_queue.task_done()
            continue

        is_base_domain = (domain == base_domain)

        # ------------------------------------------------------------------
        # Build per‑domain wildcard maps
        # ------------------------------------------------------------------
        wildcard_exists: dict = {}
        wildcard_sigs:   dict = {}

        for rec_type in WILDCARD_CHECK_TYPES:
            is_wc, stable_sig = get_wildcard_info(domain, rec_type)
            if is_wc:
                wildcard_exists[rec_type] = True
                if stable_sig is not None:
                    wildcard_sigs[rec_type] = stable_sig

        # Determine if the parent domain has any rotating wildcard (used to block recursion)
        parent_has_rotating = any(
            rt in wildcard_exists and rt not in wildcard_sigs
            for rt in WILDCARD_CHECK_TYPES
        )

        if verbose and wildcard_exists:
            stable_str = ', '.join(wildcard_sigs.keys()) or 'none'
            rotating_str = ', '.join(rt for rt in wildcard_exists if rt not in wildcard_sigs) or 'none'
            print(Fore.CYAN +
                  f"[DEBUG] Wildcard on {domain}: "
                  f"stable=[{stable_str}] rotating=[{rotating_str}]")

        for word in wordlist:
            # ------------------------------------------------------------------
            # Recursive result cap
            # ------------------------------------------------------------------
            if not is_base_domain and recursive_limit > 0:
                with domain_counts_lock:
                    hits = domain_hit_counts.get(domain, 0)
                if hits >= recursive_limit:
                    with capped_lock:
                        capped_set.add(domain)
                    if verbose:
                        print(Fore.CYAN +
                              f"[DEBUG] Recursive cap ({recursive_limit}) reached "
                              f"for {domain} — skipping remaining words")
                    with stats_lock:
                        stats['recursive_capped'] += 1
                    break   # exit word loop for this domain

            candidate = f"{word}.{domain}"

            # Exclude patterns (label‑based)
            if exclude_patterns:
                candidate_labels = candidate.lower().split('.')
                exclude_lower = [p.lower() for p in exclude_patterns]
                if any(label in exclude_lower for label in candidate_labels):
                    if verbose:
                        print(Fore.MAGENTA + f"[DEBUG] Excluded: {candidate}")
                    continue

            # Update progress (only for base domain)
            if is_base_domain:
                with progress_lock:
                    stats['words_processed'] += 1
                    if progress:
                        progress.update(processed=stats['words_processed'],
                                        found=stats['found_subdomains'])

            # ------------------------------------------------------------------
            # WILDCARD FILTERING
            # ------------------------------------------------------------------
            resolver = get_thread_resolver()
            skip = False

            if wildcard_exists:
                # Step 1: high‑confidence types
                has_high_confidence = False
                for rtype in HIGH_CONFIDENCE_TYPES:
                    try:
                        answers = resolver.resolve(candidate, rtype)
                        if answers:
                            has_high_confidence = True
                            break
                    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                        pass
                    except Exception:
                        pass

                if not has_high_confidence:
                    all_match_wildcard = True

                    for rtype in WILDCARD_CHECK_TYPES:
                        if rtype not in wildcard_exists:
                            try:
                                answers = resolver.resolve(candidate, rtype)
                                if answers:
                                    all_match_wildcard = False
                                    break
                            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                                pass
                            except Exception:
                                all_match_wildcard = False
                                break

                        elif rtype in wildcard_sigs:
                            # Stable wildcard
                            try:
                                answers = resolver.resolve(candidate, rtype)
                                cand_sig = frozenset(str(r) for r in answers)
                                if cand_sig != wildcard_sigs[rtype]:
                                    all_match_wildcard = False
                                    break
                            except dns.resolver.NXDOMAIN:
                                all_match_wildcard = False
                                break
                            except (dns.resolver.NoAnswer, dns.resolver.Timeout):
                                pass
                            except Exception:
                                all_match_wildcard = False
                                break

                        else:
                            # Rotating wildcard
                            try:
                                answers = resolver.resolve(candidate, rtype)
                                if answers:
                                    pass   # rotating hit; cannot distinguish
                            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                                all_match_wildcard = False
                                break
                            except Exception:
                                all_match_wildcard = False
                                break

                    skip = all_match_wildcard

            if skip:
                with stats_lock:
                    stats['wildcard_skipped'] += 1
                if verbose:
                    print(Fore.MAGENTA + f"[DEBUG] Wildcard skip: {candidate}")
                continue

            if delay > 0:
                time.sleep(delay)

            try:
                with stats_lock:
                    stats['total_queries'] += 1

                exists, is_ent, found_type = check_domain(candidate, verbose=verbose)
                if exists:
                    # HTTP verification (optional)
                    if http_verify_flag and not is_ent:
                        if not http_verify(
                            candidate,
                            parent_domain=domain,
                            http_ports=http_ports,
                            verify_status=verify_status,
                            wildcard_fingerprints=wildcard_fingerprints,
                            verbose=verbose
                        ):
                            if verbose:
                                print(Fore.MAGENTA + f"[DEBUG] HTTP filtered: {candidate}")
                            continue

                    line = f"[ENT] {candidate}" if is_ent else f"[{found_type}] {candidate}"
                    color = Fore.YELLOW if is_ent else Fore.GREEN
                    print(color + line)

                    if output_file and output_lock:
                        with output_lock:
                            output_file.write(line + '\n')
                            output_file.flush()

                    with results_lock:
                        results_set.add(candidate)

                    with stats_lock:
                        stats['found_subdomains'] += 1
                        if is_ent:
                            stats['ent_found'] += 1

                    # Increment hit counter for recursive domains
                    if not is_base_domain:
                        with domain_counts_lock:
                            domain_hit_counts[domain] = domain_hit_counts.get(domain, 0) + 1

                    # ------------------------------------------------------------------
                    # Recursion decision
                    # ------------------------------------------------------------------
                    found_via_rotating_wildcard = (
                        found_type is not None
                        and found_type in wildcard_exists
                        and found_type not in wildcard_sigs
                    )
                    allow_recurse = (not found_via_rotating_wildcard) or is_ent

                    # Block recursion if the parent domain has a rotating wildcard
                    if parent_has_rotating and not is_base_domain:
                        allow_recurse = False
                        if verbose:
                            print(Fore.CYAN + f"[DEBUG] Recursion blocked (parent rotating wildcard): {candidate}")

                    # Block recursion if the parent domain is already capped
                    with capped_lock:
                        parent_is_capped = domain in capped_set
                    if parent_is_capped:
                        allow_recurse = False
                        if verbose:
                            print(Fore.CYAN + f"[DEBUG] Recursion blocked (parent capped): {candidate}")

                    if current_depth < max_depth and allow_recurse:
                        with seen_lock:
                            if candidate not in seen_set:
                                seen_set.add(candidate)
                                work_queue.put((candidate, current_depth + 1))

            except Exception as e:
                with stats_lock:
                    stats['errors'] += 1
                if verbose:
                    print(Fore.RED + f"[!] Error checking {candidate}: {e}")

        work_queue.task_done()

# ----------------------------------------------------------------------
# Utility Functions
# ----------------------------------------------------------------------
def load_wordlist(path):
    words = []
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                words.append(line)
    return words

def print_banner():
    banner = r"""                                                          
███████╗██╗   ██╗██████╗ ██████╗ ███████╗ ██████╗██╗   ██╗██████╗ ███████╗███████╗
██╔════╝██║   ██║██╔══██╗██╔══██╗██╔════╝██╔════╝██║   ██║██╔══██╗██╔════╝██╔════╝
███████╗██║   ██║██████╔╝██████╔╝█████╗  ██║     ██║   ██║██████╔╝███████╗█████╗  
╚════██║██║   ██║██╔══██╗██╔══██╗██╔══╝  ██║     ██║   ██║██╔══██╗╚════██║██╔══╝  
███████║╚██████╔╝██████╔╝██║  ██║███████╗╚██████╗╚██████╔╝██║  ██║███████║███████╗
╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝
    """
    print(Fore.RED + banner + Style.RESET_ALL)
    print(Fore.YELLOW + "[+] Recursive Subdomain Enumeration | Wildcard & ENT detection | Multi-threaded")
    print(Fore.YELLOW + "[+] Version 1.0.0" + Style.RESET_ALL)
    print()

def signal_handler(sig, frame):
    print('\n[!] Interrupted by user. Exiting...')
    sys.exit(0)

# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------
def main():
    signal.signal(signal.SIGINT, signal_handler)

    parser = argparse.ArgumentParser(description='Subrecurse - Advanced recursive subdomain enumerator with HTTP verification.')
    parser.add_argument("-t", "--target", required=True, help="Target domain (e.g., example.com)")
    parser.add_argument("-w", "--wordlist", required=True, help="Path to wordlist file")
    parser.add_argument("-T", "--threads", type=int, default=20, help="Number of threads (default: 20, max 100)")
    parser.add_argument("-o", "--output", help="Output file (plain text)")
    parser.add_argument("--json", help="Output results in JSON format")
    parser.add_argument("--delay", type=float, default=0.0, help="Delay between DNS queries (seconds)")
    parser.add_argument("--depth", type=int, default=3, help="Max recursion depth (default: 3)")
    parser.add_argument("--exclude", nargs='+', help="Exclude subdomains containing these labels")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--version", action="version", version="Subrecurse 2.1.0")

    parser.add_argument(
        "--recursive-limit", type=int, default=10, metavar="N",
        help="Max results to collect per recursive domain (default: 10; 0 = unlimited)"
    )

    parser.add_argument("--http-verify", action="store_true", help="Enable HTTP verification to filter wildcard pages")
    parser.add_argument("--http-ports", type=int, nargs='+', default=[80, 443], help="Ports to check (default: 80 443)")
    parser.add_argument("--http-status", type=int, nargs='+', default=[200, 201, 204, 301, 302, 307, 308],
                        help="Acceptable HTTP status codes")
    parser.add_argument("--http-fingerprint", nargs='+', help="Strings that indicate a wildcard page")

    args = parser.parse_args()

    print_banner()

    target = args.target.rstrip('.')
    wordlist = load_wordlist(args.wordlist)
    total_words = len(wordlist)
    print(f"[*] Loaded {total_words} words.")
    print(f"[*] Target: {target} | Threads: {args.threads} | Depth: {args.depth} | Delay: {args.delay}s")
    if args.recursive_limit > 0:
        print(f"[*] Recursive result cap: {args.recursive_limit} results per recursive domain")
    else:
        print(f"[*] Recursive result cap: disabled (--recursive-limit 0)")
    if args.exclude:
        print(f"[*] Excluding labels: {', '.join(args.exclude)}")
    if args.http_verify:
        print(f"[*] HTTP verification enabled (ports: {args.http_ports}, status: {args.http_status})")
        if args.http_fingerprint:
            print(f"[*] HTTP fingerprints: {', '.join(args.http_fingerprint)}")

    progress = ProgressIndicator(total_words, target)
    progress.start()
    progress_lock = threading.Lock()

    work_queue = queue.Queue()
    work_queue.put((target, 1))

    seen_set = {target}
    seen_lock = threading.Lock()

    results_set = set()
    results_lock = threading.Lock()

    output_file = None
    output_lock = None
    if args.output:
        output_file = open(args.output, 'w', encoding='utf-8')
        output_lock = threading.Lock()

    num_workers = min(max(1, args.threads), 100)
    threads = []
    stop_sentinel = object()

    worker_args = (work_queue, wordlist, seen_lock, seen_set, results_lock, results_set,
                   stop_sentinel, output_file, output_lock, args.delay, args.depth,
                   args.exclude, args.verbose, progress, progress_lock, target,
                   args.http_verify, tuple(args.http_ports), tuple(args.http_status),
                   args.http_fingerprint, args.recursive_limit)

    for _ in range(num_workers):
        t = threading.Thread(target=worker, args=worker_args)
        t.daemon = True
        t.start()
        threads.append(t)

    work_queue.join()

    for _ in range(num_workers):
        work_queue.put(stop_sentinel)
    for t in threads:
        t.join(timeout=1)

    progress.stop()

    print("\n" + "="*50)
    print(Fore.CYAN + "[SUMMARY]")
    print(f"Base words processed: {stats['words_processed']}")
    print(f"Total DNS queries: {stats['total_queries']}")
    print(f"Subdomains found: {stats['found_subdomains']} (ENT: {stats['ent_found']})")
    print(f"Wildcard skips: {stats['wildcard_skipped']}")
    print(f"Recursive domains capped: {stats['recursive_capped']}")
    if args.http_verify:
        print(f"HTTP verified: {stats['http_verified']} | HTTP filtered: {stats['http_filtered']}")
    print(f"Timeouts: {stats['timeouts']} | SERVFAILs: {stats['servfails']} | Errors: {stats['errors']}")
    print("="*50)

    if results_set:
        print("\n=== Resolved subdomains ===")
        for sub in sorted(results_set):
            print(sub)
    else:
        print("\n[!] No subdomains found.")

    if args.json:
        json_data = {
            'target': target,
            'subdomains': sorted(list(results_set)),
            'stats': stats
        }
        with open(args.json, 'w', encoding='utf-8') as jf:
            json.dump(json_data, jf, indent=2)
        print(f"[+] JSON results saved to {args.json}")

    if output_file:
        output_file.close()
        print(f"[+] Plain text results saved to {args.output}")

if __name__ == "__main__":
    main()