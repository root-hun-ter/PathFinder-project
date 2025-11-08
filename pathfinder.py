#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PathFinder v2.0 (CLI Edition)
By RootHunter / Mr M.Elha
GitHub: github.com/root-hun-ter | Facebook: fb.com/roothunter404 | Instagram: @_root_hunter_
"""

import aiohttp
import asyncio
import argparse
import json
import re
from pathlib import Path
from urllib.parse import urljoin, urlparse
from colorama import Fore, Style, init
from tqdm.asyncio import tqdm

init(autoreset=True)

BANNER = f"""{Fore.CYAN}
╔══════════════════════════════════════════════╗
║         {Fore.MAGENTA}PathFinder v2.0 by RootHunter{Fore.CYAN}         ║
║  {Fore.YELLOW}GitHub:{Fore.WHITE} github.com/root-hun-ter │ IG: @_root_hunter_  ║
║  {Fore.YELLOW}FB:{Fore.WHITE} fb.com/roothunter404
  BY MR ELHA                     ║
╚══════════════════════════════════════════════╝
{Style.RESET_ALL}"""

DEFAULT_WORDS = [
    "admin", "login", "dashboard", "backup", "test", "old", "config",
    "uploads", "server-status", ".git", ".env", "wp-admin", "wp-login.php"
]

async def fetch(session, url, sem, timeout):
    async with sem:
        try:
            async with session.get(url, timeout=timeout, allow_redirects=False, ssl=False) as resp:
                return resp.status, str(resp.url)
        except Exception:
            return None, url

async def scan_target(base, words, concurrency, timeout):
    sem = asyncio.Semaphore(concurrency)
    results = []
    connector = aiohttp.TCPConnector(limit_per_host=concurrency)
    timeout_obj = aiohttp.ClientTimeout(total=timeout)

    async with aiohttp.ClientSession(connector=connector, timeout=timeout_obj) as session:
        tasks = []
        for w in words:
            full = urljoin(base, "/" + w)
            tasks.append(fetch(session, full, sem, timeout_obj))
        for coro in tqdm(asyncio.as_completed(tasks), total=len(tasks), desc="Scanning"):
            status, url = await coro
            if status:
                results.append((status, url))
                if status < 300:
                    print(f"{Fore.GREEN}[{status}]{Style.RESET_ALL} {url}")
                elif status < 400:
                    print(f"{Fore.CYAN}[{status}]{Style.RESET_ALL} {url} (redirect)")
                elif status == 403:
                    print(f"{Fore.YELLOW}[403]{Style.RESET_ALL} {url} (forbidden)")
                elif status == 404:
                    print(f"{Fore.RED}[404]{Style.RESET_ALL} {url}")
                else:
                    print(f"{Fore.MAGENTA}[{status}]{Style.RESET_ALL} {url}")
    return results

def load_wordlist(path):
    if not path:
        return DEFAULT_WORDS
    p = Path(path)
    if not p.exists():
        print(Fore.RED + f"[!] Wordlist not found: {p}")
        return DEFAULT_WORDS
    with p.open("r", encoding="utf-8", errors="ignore") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]

async def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="PathFinder CLI Edition — Discover hidden paths ethically.")
    parser.add_argument("target", help="Target domain or full URL, e.g., example.com or https://example.com")
    parser.add_argument("-w", "--wordlist", help="Path to a custom wordlist file")
    parser.add_argument("-c", "--concurrency", type=int, default=10, help="Number of concurrent requests")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="Request timeout seconds")
    parser.add_argument("-o", "--outdir", default="out", help="Directory to save results")
    args = parser.parse_args()

    target = args.target
    if not target.startswith("http"):
        target = "https://" + target
    parsed = urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}"

    print(f"{Fore.WHITE}[*] Target: {Fore.CYAN}{base}")
    words = load_wordlist(args.wordlist)
    print(f"{Fore.WHITE}[*] Loaded {len(words)} paths from wordlist")

    results = await scan_target(base, words, args.concurrency, args.timeout)

    valid = [r for r in results if r[0] < 400]
    print(f"\n{Fore.GREEN}[+] Scan completed. {len(valid)} valid paths found.{Style.RESET_ALL}")

    Path(args.outdir).mkdir(parents=True, exist_ok=True)
    outfile = Path(args.outdir) / f"{parsed.netloc}_results.json"
    with open(outfile, "w", encoding="utf-8") as f:
        json.dump([{"status": s, "url": u} for s, u in results], f, indent=2)
    print(f"{Fore.CYAN}[*] Results saved to: {outfile}{Style.RESET_ALL}")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Aborted by user.")
