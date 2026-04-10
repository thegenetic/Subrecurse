"""
Subrecurse - Recursive Subdomain Enumeration with Wildcard & ENT Detection
Author: Dipesh Paul
Version: 1.0.0
License: MIT
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
from colorama import Fore, Style, init
from functools import lru_cache
from threading import Event, Thread

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
    'wildcard_skipped': 0
}
stats_lock = threading.Lock()

# ----------------------------------------------------------------------
# Thread‑local Resolver
# ----------------------------------------------------------------------
thread_local = threading.local()

def get_thread_resolver():
    """Return a thread‑local DNS resolver with optimized settings."""
    if not hasattr(thread_local, 'resolver'):
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 2
        resolver.timeout = 2
        thread_local.resolver = resolver
    return thread_local.resolver

# ----------------------------------------------------------------------
# Wildcard Detection (Cached)
# ----------------------------------------------------------------------
@lru_cache(maxsize=1000)
def get_wildcard_signature(domain, record_type='A', num_probes=3):
    """
    Returns a frozenset of record values if consistent across multiple probes,
    else None (no wildcard or inconsistent responses).
    """
    signatures = []
    for _ in range(num_probes):
        random_label = uuid.uuid4().hex
        test_domain = f"{random_label}.{domain}"
        try:
            resolver = get_thread_resolver()
            answers = resolver.resolve(test_domain, record_type)
            signatures.append(frozenset(str(r) for r in answers))
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
            signatures.append(None)

    if signatures and all(s == signatures[0] for s in signatures) and signatures[0] is not None:
        return signatures[0]
    return None

# ----------------------------------------------------------------------
# ENT Detection
# ----------------------------------------------------------------------
def check_domain(domain, record_types=None, verbose=False):
    """
    Check if a domain exists and detect if it's an ENT.
    Returns: (exists: bool, is_ent: bool, found_record_type: str or None)
    """
    if record_types is None:
        record_types = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'PTR', 'SRV', 'CAA', 'DS', 'DNSKEY']

    resolver = get_thread_resolver()
    found_any = False
    found_type = None

    for rtype in record_types:
        try:
            answers = resolver.resolve(domain, rtype)
            if answers:
                found_any = True
                found_type = rtype
                if verbose:
                    print(Fore.CYAN + f"[DEBUG] {domain} has {rtype} records")
                return (True, False, found_type)
        except dns.resolver.NoAnswer:
            continue
        except dns.resolver.NXDOMAIN:
            if verbose:
                print(Fore.CYAN + f"[DEBUG] {domain} NXDOMAIN")
            return (False, False, None)
        except dns.resolver.Timeout:
            with stats_lock:
                stats['timeouts'] += 1
            if verbose:
                print(Fore.RED + f"[DEBUG] Timeout on {domain} ({rtype})")
            continue
        except dns.resolver.SERVFAIL:
            with stats_lock:
                stats['servfails'] += 1
            if verbose:
                print(Fore.RED + f"[DEBUG] SERVFAIL on {domain} ({rtype})")
            continue
        except Exception as e:
            if verbose:
                print(Fore.RED + f"[DEBUG] {domain} error: {e}")
            continue

    # No records found, no NXDOMAIN. Check NS as strong ENT hint.
    try:
        resolver.resolve(domain, 'NS')
        # Has NS records → exists but not ENT
        return (True, False, 'NS')
    except dns.resolver.NoAnswer:
        # True ENT
        return (True, True, None)
    except dns.resolver.NXDOMAIN:
        return (False, False, None)
    except Exception:
        return (False, False, None)

# ----------------------------------------------------------------------
# Progress Indicator
# ----------------------------------------------------------------------
class ProgressIndicator:
    def __init__(self, total_words, target, update_interval=1.0):
        self.total = total_words
        self.target = target
        self.processed = 0
        self.found = 0
        self.start_time = time.time()
        self.update_interval = update_interval
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
            time.sleep(self.update_interval)

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
           max_depth=3, current_depth=1, exclude_patterns=None, verbose=False,
           progress=None, progress_lock=None):
    """
    Worker thread function.
    """
    # High‑confidence record types are less likely to be wildcarded
    HIGH_CONFIDENCE_TYPES = ['CNAME', 'MX', 'NS', 'SOA']
    WILDCARD_CHECK_TYPES = ['A', 'AAAA', 'TXT']

    while True:
        try:
            domain = work_queue.get(timeout=1)
        except queue.Empty:
            continue

        if domain is stop_sentinel:
            work_queue.task_done()
            break

        if current_depth > max_depth:
            work_queue.task_done()
            continue

        # Detect wildcard signatures for this domain
        wildcard_sigs = {}
        for rec_type in WILDCARD_CHECK_TYPES:
            sig = get_wildcard_signature(domain, rec_type)
            if sig is not None:
                wildcard_sigs[rec_type] = sig

        for word in wordlist:
            candidate = f"{word}.{domain}"

            # Skip if matches exclude pattern
            if exclude_patterns and any(p in candidate for p in exclude_patterns):
                continue

            # Update progress (word processed count)
            with progress_lock:
                stats['words_processed'] += 1
                if progress:
                    progress.update(processed=stats['words_processed'],
                                    found=stats['found_subdomains'])

            # Refined wildcard filtering
            skip = True  # Assume skip until proven otherwise
            # First, check high‑confidence types that are NOT in wildcard_sigs
            for rtype in HIGH_CONFIDENCE_TYPES:
                if rtype in wildcard_sigs:
                    continue  # Skip if wildcard exists for this type
                try:
                    resolver = get_thread_resolver()
                    answers = resolver.resolve(candidate, rtype)
                    if answers:
                        # Legitimate record found → do not skip
                        skip = False
                        break
                except:
                    pass

            if skip and wildcard_sigs:
                # No high‑confidence record found; now check wildcard‑susceptible types
                for rtype, wild_sig in wildcard_sigs.items():
                    try:
                        resolver = get_thread_resolver()
                        answers = resolver.resolve(candidate, rtype)
                        cand_sig = frozenset(str(r) for r in answers)
                        if cand_sig != wild_sig:
                            # At least one type differs from wildcard → legitimate
                            skip = False
                            break
                    except:
                        # If query fails, we can't be sure, so conservatively don't skip
                        skip = False
                        break
            else:
                # If no wildcard signatures at all, never skip
                skip = False

            if skip:
                with stats_lock:
                    stats['wildcard_skipped'] += 1
                if verbose:
                    print(Fore.MAGENTA + f"[DEBUG] Wildcard skip: {candidate}")
                continue

            # Rate limiting
            if delay > 0:
                time.sleep(delay)

            # DNS query
            try:
                with stats_lock:
                    stats['total_queries'] += 1

                exists, is_ent, found_type = check_domain(candidate, verbose=verbose)
                if exists:
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

                    # Recursion if depth permits
                    if current_depth < max_depth:
                        with seen_lock:
                            if candidate not in seen_set:
                                seen_set.add(candidate)
                                work_queue.put(candidate)

            except Exception as e:
                with stats_lock:
                    stats['errors'] += 1
                if 'NXDOMAIN' not in str(e):
                    print(Fore.RED + f"[!] Error checking {candidate}: {e}")

        work_queue.task_done()

# ----------------------------------------------------------------------
# Utility Functions
# ----------------------------------------------------------------------
def load_wordlist(path):
    """Load wordlist, ignoring comments and empty lines."""
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
    print(Fore.YELLOW + "[+] Version 1.0.0 | https://github.com/yourname/subrecurse" + Style.RESET_ALL)
    print()

def signal_handler(sig, frame):
    print('\n[!] Interrupted by user. Exiting...')
    sys.exit(0)

# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------
def main():
    signal.signal(signal.SIGINT, signal_handler)

    parser = argparse.ArgumentParser(
        description='subrecurse - Recursive subdomain enumerator.',
        epilog='Example: %(prog)s -t example.com -w subdomains.txt -T 50 --delay 0.01 -o results.txt'
    )
    parser.add_argument("-t", "--target", required=True, help="Target domain (e.g., example.com)")
    parser.add_argument("-w", "--wordlist", required=True, help="Path to wordlist file")
    parser.add_argument("-T", "--threads", type=int, default=20, help="Number of threads (default: 20, max 100)")
    parser.add_argument("-o", "--output", help="Output file (plain text)")
    parser.add_argument("--json", help="Output results in JSON format to specified file")
    parser.add_argument("--delay", type=float, default=0.0, help="Delay in seconds between queries (default: 0)")
    parser.add_argument("--depth", type=int, default=3, help="Maximum recursion depth (default: 3)")
    parser.add_argument("--exclude", nargs='+', help="Exclude subdomains containing these patterns")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose/debug output")
    parser.add_argument("--version", action="version", version="subrecurse 1.0.0")
    args = parser.parse_args()

    print_banner()

    target = args.target.rstrip('.')
    wordlist = load_wordlist(args.wordlist)
    total_words = len(wordlist)
    print(f"[*] Loaded {total_words} words from wordlist.")
    print(f"[*] Target: {target} | Threads: {args.threads} | Depth: {args.depth} | Delay: {args.delay}s")
    if args.exclude:
        print(f"[*] Excluding patterns: {', '.join(args.exclude)}")

    # Progress indicator setup
    progress = ProgressIndicator(total_words, target)
    progress.start()
    progress_lock = threading.Lock()

    work_queue = queue.Queue()
    work_queue.put(target)

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
                   stop_sentinel, output_file, output_lock, args.delay, args.depth, 1,
                   args.exclude, args.verbose, progress, progress_lock)

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

    # Print summary
    print("\n" + "="*50)
    print(Fore.CYAN + "[SUMMARY]")
    print(f"Total words processed: {stats['words_processed']}")
    print(f"Total DNS queries: {stats['total_queries']}")
    print(f"Subdomains found: {stats['found_subdomains']} (ENT: {stats['ent_found']})")
    print(f"Wildcard skips: {stats['wildcard_skipped']}")
    print(f"Timeouts: {stats['timeouts']} | SERVFAILs: {stats['servfails']} | Errors: {stats['errors']}")
    print("="*50)

    # Print resolved subdomains
    if results_set:
        print("\n=== Resolved subdomains ===")
        for sub in sorted(results_set):
            print(sub)
    else:
        print("\n[!] No subdomains found.")

    # Write JSON output
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
