#!/usr/bin/env python3
import json
import ssl
import sys
import argparse
import codecs
import time
import os
import urllib.request
import urllib.error
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import base64

try:
    import mmh3
except ImportError:
    print("\033[91m[!] Error: 'mmh3' module is not installed.\033[0m")
    print("Please install it using: pip install mmh3")
    sys.exit(1)

class Colors:
    """Color constants for terminal output"""
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    CYAN = "\033[36m"
    MAGENTA = "\033[35m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

class FavHunt:
    def __init__(self, threads: int, output_dir: str, shodan: bool):
        self.threads = threads
        self.output_dir = output_dir
        self.shodan = shodan
        self.fingerprints = self._load_fingerprints()
        self.results = {}
        
        # We will need an unverified SSL context given security setups
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE

        # Modern User Agent to avoid basic WAF blocks
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36'
        }

    def _load_fingerprints(self) -> dict:
        """Loads known hashes from the JSON database"""
        fingerprints = {}
        if os.path.exists("fingerprints.json"):
            try:
                with open("fingerprints.json", "r", encoding="utf-8") as f:
                    raw_data = json.load(f)
                    for k, v in raw_data.items():
                        try:
                            fingerprints[int(k)] = v
                        except ValueError:
                            pass
            except Exception as e:
                print(f"{Colors.RED}[!] Error loading fingerprints.json: {e}{Colors.RESET}")
        else:
            print(f"{Colors.YELLOW}[!] fingerprints.json not found! Identification will be disabled.{Colors.RESET}")
        return fingerprints

    def format_url(self, url: str) -> str:
        """Format an input URL reliably so we target the standard favicon"""
        url = url.strip()
        if not url.startswith("http://") and not url.startswith("https://"):
            url = "http://" + url
            
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        return f"{base}/favicon.ico"

    def fetch_hash(self, base_url: str):
        """Fetch favicon for a single target and calculate its MurmurHash3"""
        target_url = self.format_url(base_url)
        try:
            req = urllib.request.Request(target_url, headers=self.headers)
            with urllib.request.urlopen(req, timeout=8, context=self.ssl_context) as response:
                content = response.read()
                # Encodes and creates mmh3 correctly for Shodan mappings using standard base64 library
                favicon_base64 = base64.encodebytes(content)
                icon_hash = mmh3.hash(favicon_base64)
                return base_url, icon_hash, None
        except Exception as e:
            return base_url, None, str(e)

    def scan(self, targets: list):
        """Multithreaded scanning of all provided targets"""
        print(f"\n{Colors.CYAN}[*] Starting scan on {len(targets)} targets with {self.threads} threads...{Colors.RESET}\n")
        
        start_time = time.time()
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_url = {executor.submit(self.fetch_hash, url): url for url in targets}
            
            for future in as_completed(future_to_url):
                url, icon_hash, error = future.result()
                
                if error is None:
                    # Successful fetch
                    print(f"{Colors.GREEN} [+] {Colors.RESET} {url} -> {Colors.BOLD}{icon_hash}{Colors.RESET}")
                    
                    if icon_hash not in self.results:
                        self.results[icon_hash] = []
                    self.results[icon_hash].append(url)
                else:
                    # Generic error silently skipped unless verbose, 
                    # but kept compact to avoid messy outputs.
                    print(f"{Colors.RED} [-] {Colors.RESET} {url} -> {Colors.YELLOW}{error}{Colors.RESET}")

        end_time = time.time()
        print(f"\n{Colors.CYAN}[*] Scan completed in {round(end_time - start_time, 2)} seconds.{Colors.RESET}")
        self.generate_report()

    def generate_report(self):
        """Displays mapping results, detects technologies, handles saving/Shodan generation"""
        if not self.results:
            print(f"{Colors.YELLOW}[!] No successful hashes retrieved.{Colors.RESET}")
            return
            
        print(f"\n{Colors.BOLD}=================[ FINGERPRINT INTELLIGENCE ]================={Colors.RESET}")
        
        total_clusters = len(self.results)
        identified = 0
        
        for icon_hash, urls in self.results.items():
            tech = self.fingerprints.get(icon_hash, "Unknown")
            count = len(urls)
            
            if tech != "Unknown":
                identified += 1
                header_color = Colors.MAGENTA
            else:
                header_color = Colors.BLUE
                
            print(f"\n{header_color}[Hash: {icon_hash}]{Colors.RESET} | {Colors.BOLD}Tech: {tech}{Colors.RESET} | Count: {count}")
            for u in urls:
                print(f"  {Colors.GREEN}➔{Colors.RESET} {u}")
                
        print(f"\n{Colors.BOLD}====================[ STATS & EXPORT ]========================{Colors.RESET}")
        print(f"Total Unique Assets Grouped: {total_clusters}")
        print(f"Technologies Positively Identified: {identified}")
        
        # Output shodan dorks
        if self.shodan:
            print(f"\n{Colors.YELLOW}[!] Generated Shodan Dorks:{Colors.RESET}")
            for icon_hash, urls in self.results.items():
                if icon_hash != 0:
                    domains = ", ".join(urls)
                    print(f"  {Colors.CYAN}http.favicon.hash:{icon_hash}{Colors.RESET}  ({domains})")
        
        # Export files natively
        if self.output_dir:
            if not os.path.exists(self.output_dir):
                os.makedirs(self.output_dir)
            
            for icon_hash, urls in self.results.items():
                file_path = os.path.join(self.output_dir, f"{icon_hash}.txt")
                with open(file_path, "w", encoding="utf-8") as f:
                    for u in urls:
                        f.write(f"{u}\n")
            
            print(f"\n{Colors.GREEN}[+] Successfully saved grouped domains to '{self.output_dir}' directory.{Colors.RESET}")

def display_banner():
    """Shows custom CLI ASCII Banner"""
    banner = rf"""{Colors.BOLD}{Colors.CYAN}
    ______              __  __             __ 
   / ____/___ __   __  / / / /__  ______  / /_
  / /_  / __ `/ | / / / /_/ / / / / __ \/ __/
 / __/ / /_/ /| |/ / / __  / /_/ / / / / /_  
/_/    \__,_/ |___/ /_/ /_/\__,_/_/ /_/\__/  
        
    v1.0 | Fast, Modern Asset Mapping via Favicon DNA
    Developed by {Colors.BOLD}m3hank{Colors.RESET}{Colors.CYAN}
    {Colors.RESET}
    """
    if sys.stdout.isatty():
        if os.name == 'nt':
            os.system('cls')
        else:
            os.system('clear')
    print(banner)

def main():
    display_banner()
    parser = argparse.ArgumentParser(description="FavHunt - Modern Favicon Asset Mapper")
    parser.add_argument('-l', '--list', type=str, help="File containing list of target URLs")
    parser.add_argument('-t', '--threads', type=int, default=20, help="Number of concurrent threads (default: 20)")
    parser.add_argument('-o', '--output', type=str, help="Directory name to export results")
    parser.add_argument('--shodan', action='store_true', help="Print generated Shodan dorks")
    
    args = parser.parse_args()

    targets = []
    if args.list:
        if not os.path.exists(args.list):
            print(f"{Colors.RED}[ERROR] File '{args.list}' not found.{Colors.RESET}")
            sys.exit(1)
        with open(args.list, "r", encoding="utf-8") as f:
            targets = [line.strip() for line in f if line.strip()]
    elif not sys.stdin.isatty():
        targets = [line.strip() for line in sys.stdin if line.strip()]
    else:
        print(f"{Colors.RED}[ERROR] No input provided. Example: python3 favhunt.py -l urls.txt OR cat urls.txt | python3 favhunt.py{Colors.RESET}")
        sys.exit(1)

    scanner = FavHunt(threads=args.threads, output_dir=args.output, shodan=args.shodan)
    scanner.scan(targets)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[!] Execution aborted by user.{Colors.RESET}")
        sys.exit(0)
