import asyncio
import aiohttp
import ipaddress
import random
import sqlite3
import time
import json
import os
import sys
from datetime import datetime
from typing import List, Tuple, Optional, Dict, Set

# ========== CONFIGURATION ==========
DEFAULT_PORTS = [80, 8080, 3128, 8000, 8888, 1080]
DEFAULT_TIMEOUT = 5
DEFAULT_THREADS = 200
TEST_URL = "http://www.google.com/generate_204"
MAX_RETRIES = 2
MAX_RANDOM_IPS = 5000
MIN_WORKING_RANGE_IPS = 10
DEBUG_LOG_FILE = "debug.log"

# ========== FILE PATHS ==========
IP_RANGES_FILE = "ipranges.txt"
OPEN_PROXIES_FILE = "open_proxies.txt"
WORKING_PROXIES_FILE = "working_proxies.txt"
WORKING_RANGES_FILE = "working_ranges.txt"
CONFIG_FILE = "proxy_scanner.cfg"
DATABASE_FILE = "proxies.db"
RESULTS_FILE = "results.txt"

# ========== COLORS ==========
class Colors:
    RESET = "\033[0m"
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"

# ========== STEALTH CONFIG ==========
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 13_2_3 like Mac OS X) AppleWebKit/605.1.15',
    'Mozilla/5.0 (Linux; Android 10; SM-A205U) AppleWebKit/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:80.0) Gecko/20100101 Firefox/80.0'
]

IRANIAN_TEST_SITES = [
    "http://www.aparat.com/video/video/embed/videohash/xyz",
    "http://www.snapp.ir/api/v1/ping",
    "http://www.digikala.com/static/js/main.js",
    "http://www.torob.com/api/v1/ping",
    "http://www.shahed.ir/",
    "http://www.yjc.ir/"
]

class ProxyScanner:
    def __init__(self):
        self.stop_event = asyncio.Event()
        self.total_tests = 0
        self.completed_tests = 0
        self.start_time = 0
        self.ports = DEFAULT_PORTS[:]
        self.timeout = DEFAULT_TIMEOUT
        self.concurrency_limit = DEFAULT_THREADS
        self.debug_mode = False
        self.debug_log = []
        self.scan_results = []
        self.load_config()
        self.setup_files()
        self.setup_database()
        self.session = None

    def log_debug(self, message: str) -> None:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        debug_msg = f"[DEBUG][{timestamp}] {message}"
        self.debug_log.append(debug_msg)
        if self.debug_mode:
            print(f"{Colors.MAGENTA}{debug_msg}{Colors.RESET}")

    def setup_files(self) -> None:
        try:
            for f in [IP_RANGES_FILE, OPEN_PROXIES_FILE, WORKING_PROXIES_FILE, 
                     WORKING_RANGES_FILE, DEBUG_LOG_FILE, RESULTS_FILE]:
                if not os.path.exists(f):
                    with open(f, 'w'):
                        pass
            self.log_debug("Initialized required files")
        except Exception as e:
            print(f"{Colors.RED}[!] File setup error: {e}{Colors.RESET}")
            sys.exit(1)

    def setup_database(self) -> None:
        try:
            self.conn = sqlite3.connect(DATABASE_FILE)
            self.cursor = self.conn.cursor()
            self.cursor.execute('PRAGMA journal_mode=WAL')
            
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS proxies (
                    ip TEXT,
                    port INTEGER,
                    country TEXT,
                    city TEXT,
                    speed INTEGER,
                    protocol TEXT,
                    anonymity TEXT,
                    isp TEXT,
                    last_checked TEXT,
                    is_active INTEGER DEFAULT 1,
                    PRIMARY KEY (ip, port)
                )''')
            
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS ip_ranges (
                    range TEXT PRIMARY KEY,
                    last_scan TEXT,
                    hit_rate REAL
                )''')
            
            self.cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_proxies_active 
                ON proxies(is_active)
            ''')
            
            self.conn.commit()
            self.log_debug("Database initialized successfully")
        except sqlite3.Error as e:
            print(f"{Colors.RED}[!] Database error: {e}{Colors.RESET}")
            sys.exit(1)

    async def async_init(self) -> None:
        self.session = aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(
                limit=self.concurrency_limit,
                force_close=True,
                enable_cleanup_closed=True
            ),
            headers=self.get_random_headers(),
            trust_env=True
        )
        self.log_debug("Async session initialized")

    async def close(self) -> None:
        try:
            if self.session and not self.session.closed:
                await self.session.close()
            if self.conn:
                self.conn.close()
            self.log_debug("Resources cleaned up")
        except Exception as e:
            print(f"{Colors.YELLOW}[!] Cleanup error: {e}{Colors.RESET}")

    def get_random_headers(self) -> Dict[str, str]:
        headers = {
            'User-Agent': random.choice(USER_AGENTS),
            'Accept': 'text/html,application/xhtml+xml',
            'Accept-Language': random.choice(['en-US,en;q=0.9', 'fa-IR,fa;q=0.8']),
            'Connection': random.choice(['keep-alive', 'close']),
            'X-Forwarded-For': f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
            'Accept-Encoding': 'gzip, deflate',
            'Cache-Control': random.choice(['no-cache', 'max-age=0'])
        }
        self.log_debug(f"Generated headers: {headers}")
        return headers

    def load_config(self) -> None:
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE) as f:
                    config = json.load(f)
                    
                    ports = config.get('ports', DEFAULT_PORTS)
                    if all(isinstance(p, int) and 1 <= p <= 65535 for p in ports):
                        self.ports = ports
                    
                    timeout = config.get('timeout', DEFAULT_TIMEOUT)
                    if isinstance(timeout, (int, float)) and 1 <= timeout <= 30:
                        self.timeout = timeout
                    
                    threads = config.get('threads', DEFAULT_THREADS)
                    if isinstance(threads, int) and 10 <= threads <= 500:
                        self.concurrency_limit = threads
                        
            self.log_debug("Configuration loaded")
        except json.JSONDecodeError:
            print(f"{Colors.YELLOW}[!] Config file corrupted, using defaults{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.YELLOW}[!] Config load error: {e}{Colors.RESET}")

    def save_config(self) -> None:
        try:
            with open(CONFIG_FILE, 'w') as f:
                json.dump({
                    'ports': self.ports,
                    'timeout': self.timeout,
                    'threads': self.concurrency_limit
                }, f, indent=2)
            self.log_debug("Configuration saved")
        except Exception as e:
            print(f"{Colors.RED}[!] Config save error: {e}{Colors.RESET}")

    def add_scan_result(self, result_type: str, details: str, status: str) -> None:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.scan_results.append({
            'timestamp': timestamp,
            'type': result_type,
            'details': details,
            'status': status
        })
        self.log_debug(f"Added scan result: {result_type} - {details} - {status}")

    async def check_single_ip(self) -> None:
        clear_screen()
        print(f"{Colors.CYAN}=== Check Single Proxy ==={Colors.RESET}")
        
        try:
            ip = input("Enter IP address: ").strip()
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                print(f"{Colors.RED}[!] Invalid IP address format{Colors.RESET}")
                return
            
            port_input = input(f"Enter port (default {self.ports[0]}): ").strip()
            port = int(port_input) if port_input.isdigit() else self.ports[0]
            port = max(1, min(port, 65535))
            
            print(f"\n{Colors.YELLOW}[*] Testing {ip}:{port}...{Colors.RESET}")
            
            start_time = time.time()
            success, _, _ = await self.check_proxy(ip, port)
            
            if success:
                print(f"\n{Colors.GREEN}[✓] Proxy {ip}:{port} is working!{Colors.RESET}")
                self.add_scan_result("Single Proxy Check", f"{ip}:{port}", "Working")
                
                proxy = f"{ip}:{port}"
                proxy_result, speed, anonymity = await self.test_proxy_connection(proxy)
                
                if speed is not None:
                    print(f"\n{Colors.CYAN}=== Detailed Results ==={Colors.RESET}")
                    print(f"Status: {Colors.GREEN}WORKING{Colors.RESET}")
                    print(f"Speed: {speed}ms")
                    print(f"Anonymity: {anonymity}")
                    
                    details = await self.get_proxy_details(ip)
                    print(f"Country: {details.get('country', 'Unknown')}")
                    print(f"ISP: {details.get('isp', 'Unknown')}")
                    
                    save = input("\nSave to database? (y/n): ").strip().lower()
                    if save == 'y':
                        self.save_to_database(proxy, speed, anonymity, details)
                        print(f"{Colors.GREEN}[✓] Saved to database{Colors.RESET}")
                else:
                    print(f"\n{Colors.YELLOW}[!] Proxy responded but failed full test{Colors.RESET}")
                    self.add_scan_result("Single Proxy Check", f"{ip}:{port}", "Partial Success")
            else:
                print(f"\n{Colors.RED}[✗] Proxy {ip}:{port} is not working{Colors.RESET}")
                self.add_scan_result("Single Proxy Check", f"{ip}:{port}", "Failed")
            
            elapsed = time.time() - start_time
            print(f"\nTest completed in {elapsed:.2f} seconds")
            
        except Exception as e:
            print(f"\n{Colors.RED}[!] Error testing proxy: {e}{Colors.RESET}")
            self.add_scan_result("Single Proxy Check", f"{ip}:{port}", f"Error: {str(e)}")
        
        input("\nPress Enter to continue...")

    def save_results_to_file(self) -> None:
        clear_screen()
        print(f"{Colors.CYAN}=== Saving Results ==={Colors.RESET}")
        
        try:
            with open(RESULTS_FILE, 'w') as f:
                f.write("=== Proxy Scanner Results ===\n")
                f.write(f"Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                if not self.scan_results:
                    f.write("No scan results available\n")
                    print(f"{Colors.YELLOW}No results to save{Colors.RESET}")
                    return
                
                f.write("=== Scan History ===\n")
                for result in self.scan_results:
                    f.write(f"[{result['timestamp']}] {result['type']}\n")
                    f.write(f"Details: {result['details']}\n")
                    f.write(f"Status: {result['status']}\n\n")
                
                f.write("\n=== Current Working Proxies ===\n")
                try:
                    self.cursor.execute('SELECT COUNT(*) FROM proxies WHERE is_active = 1')
                    count = self.cursor.fetchone()[0]
                    f.write(f"Total working proxies in database: {count}\n\n")
                    
                    self.cursor.execute('''
                        SELECT ip, port, speed, anonymity, country, isp 
                        FROM proxies 
                        WHERE is_active = 1 
                        ORDER BY speed ASC 
                        LIMIT 100
                    ''')
                    proxies = self.cursor.fetchall()
                    
                    if proxies:
                        f.write("Top 100 fastest proxies:\n")
                        f.write("IP:Port\t\tSpeed\tAnonymity\tCountry\tISP\n")
                        f.write("-"*80 + "\n")
                        for proxy in proxies:
                            f.write(f"{proxy[0]}:{proxy[1]}\t{proxy[2]}ms\t{proxy[3]}\t{proxy[4]}\t{proxy[5]}\n")
                    else:
                        f.write("No working proxies found in database\n")
                except sqlite3.Error as e:
                    f.write(f"\nError accessing database: {str(e)}\n")
            
            print(f"{Colors.GREEN}[✓] Results saved to {RESULTS_FILE}{Colors.RESET}")
            self.log_debug(f"Scan results saved to {RESULTS_FILE}")
        except IOError as e:
            print(f"{Colors.RED}[!] Error saving results: {e}{Colors.RESET}")

    def generate_targeted_ips(self, count: int) -> List[str]:
        targets = set()
        
        if os.path.exists(WORKING_RANGES_FILE):
            try:
                with open(WORKING_RANGES_FILE) as f:
                    working_ranges = [line.strip() for line in f if line.strip()]
                
                self.log_debug(f"Found {len(working_ranges)} working ranges")
                
                for r in working_ranges[:50]:
                    try:
                        net = ipaddress.IPv4Network(r)
                        targets.update(str(ip) for ip in net.hosts())
                        if len(targets) >= count * 2:
                            break
                    except ValueError:
                        continue
            except IOError as e:
                print(f"{Colors.YELLOW}[!] Error reading working ranges: {e}{Colors.RESET}")
        
        if os.path.exists(IP_RANGES_FILE):
            try:
                with open(IP_RANGES_FILE) as f:
                    iran_ranges = [line.strip() for line in f if line.strip()]
                    
                self.log_debug(f"Found {len(iran_ranges)} Iranian IP ranges")
                    
                for r in random.sample(iran_ranges, min(10, len(iran_ranges))):
                    try:
                        net = ipaddress.IPv4Network(r)
                        sample_size = min(50, len(list(net.hosts())))
                        targets.update(
                            str(ip) for ip in random.sample(list(net.hosts()), sample_size))
                    except ValueError:
                        continue
            except IOError as e:
                print(f"{Colors.YELLOW}[!] Error reading IP ranges: {e}{Colors.RESET}")
        
        while len(targets) < count:
            targets.add(f"{random.randint(1, 223)}.{random.randint(0, 255)}."
                      f"{random.randint(0, 255)}.{random.randint(1, 254)}")
        
        result = random.sample(list(targets), min(count, len(targets)))
        self.log_debug(f"Generated {len(result)} targeted IPs")
        return result

    async def stealth_check(self, ip: str, port: int) -> bool:
        try:
            delay = random.uniform(0.1, 1.5)
            self.log_debug(f"Testing {ip}:{port} with delay {delay:.2f}s")
            await asyncio.sleep(delay)
            
            test_url = random.choice(IRANIAN_TEST_SITES)
            proxy_url = f"http://{ip}:{port}"
            self.log_debug(f"Using test URL: {test_url}")
            
            try:
                async with self.session.get(
                    test_url,
                    proxy=proxy_url,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    headers=self.get_random_headers()
                ) as response:
                    status_ok = response.status in (200, 204, 404)
                    content_type = response.headers.get('content-type', '').lower()
                    server_header = response.headers.get('server', '').lower()
                    
                    self.log_debug(f"Response: status={response.status}, server={server_header}, content-type={content_type}")
                    
                    if any(x in server_header for x in ['apache', 'nginx', 'iis', 'litespeed']):
                        self.log_debug(f"Proxy {ip}:{port} passed server header check")
                        return True
                    
                    if 'digikala' in test_url:
                        result = status_ok and ('javascript' in content_type or 'text/html' in content_type)
                        self.log_debug(f"Digikala check result: {result}")
                        return result
                    elif 'aparat' in test_url:
                        result = response.status == 404
                        self.log_debug(f"Aparat check result: {result}")
                        return result
                    elif 'shahed' in test_url or 'yjc' in test_url:
                        lang = response.headers.get('content-language', '').lower()
                        result = 'fa-ir' in lang
                        self.log_debug(f"Language check result: {result} (language: {lang})")
                        return result
                    
                    self.log_debug(f"Default status check: {status_ok}")
                    return status_ok
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                self.log_debug(f"Proxy {ip}:{port} failed with error: {str(e)}")
                return False
        except Exception as e:
            self.log_debug(f"Unexpected error checking {ip}:{port}: {str(e)}")
            return False

    async def scan_for_open_proxies(self) -> None:
        clear_screen()
        print(f"{Colors.CYAN}=== Proxy Scanning Options ==={Colors.RESET}")
        print(f"{Colors.GREEN}[1]{Colors.RESET} Scan Iranian IP ranges")
        print(f"{Colors.GREEN}[2]{Colors.RESET} Scan targeted IPs (recommended)")
        print(f"{Colors.GREEN}[3]{Colors.RESET} Quick scan working ranges")
        
        choice = input("\nSelect scan type: ").strip()
        
        ip_list = []
        scan_type = ""
        if choice == "1":
            scan_type = "Iranian IP Ranges Scan"
            try:
                with open(IP_RANGES_FILE) as f:
                    all_ranges = [line.strip() for line in f if line.strip()]
                
                if not all_ranges:
                    print(f"{Colors.RED}[!] No IP ranges found in {IP_RANGES_FILE}{Colors.RESET}")
                    return
                    
                try:
                    max_ranges = len(all_ranges)
                    range_count = int(input(
                        f"How many IP ranges to scan (1-{max_ranges}, 0 for all)? "
                    ).strip())
                    
                    if range_count == 0:
                        range_count = max_ranges
                    else:
                        range_count = max(1, min(range_count, max_ranges))
                        
                    selected_ranges = random.sample(all_ranges, range_count)
                    self.log_debug(f"Selected {range_count} IP ranges to scan")
                    self.add_scan_result(scan_type, f"Scanning {range_count} IP ranges", "Started")
                    
                    print(f"{Colors.CYAN}[*] Scanning {range_count} IP ranges...{Colors.RESET}")
                    
                    for r in selected_ranges:
                        try:
                            net = ipaddress.IPv4Network(r)
                            ip_list.extend(str(ip) for ip in net.hosts())
                        except ValueError:
                            continue
                            
                except ValueError:
                    print(f"{Colors.RED}[!] Invalid input, using all ranges{Colors.RESET}")
                    range_count = max_ranges
                    selected_ranges = all_ranges
                    
            except Exception as e:
                print(f"{Colors.RED}[!] Error: {e}{Colors.RESET}")
                self.add_scan_result(scan_type, "Initialization", f"Error: {str(e)}")
                return
            
        elif choice == "2":
            scan_type = "Targeted IP Scan"
            try:
                count = int(input(f"IPs to scan (max {MAX_RANDOM_IPS}): "))
                count = max(10, min(count, MAX_RANDOM_IPS))
                ip_list = self.generate_targeted_ips(count)
                self.log_debug(f"Generated {count} targeted IPs")
                self.add_scan_result(scan_type, f"Scanning {count} targeted IPs", "Started")
            except ValueError:
                print(f"{Colors.RED}[!] Invalid input{Colors.RESET}")
                return
            
        elif choice == "3":
            scan_type = "Working Ranges Scan"
            if not os.path.exists(WORKING_RANGES_FILE):
                print(f"{Colors.RED}[!] No working ranges found{Colors.RESET}")
                return
            
            try:
                with open(WORKING_RANGES_FILE) as f:
                    ranges = [line.strip() for line in f if line.strip()]
                
                self.log_debug(f"Found {len(ranges)} working ranges")
                self.add_scan_result(scan_type, f"Scanning {len(ranges)} working ranges", "Started")
                
                for r in ranges[:20]:
                    try:
                        net = ipaddress.IPv4Network(r)
                        ip_list.extend(str(ip) for ip in net.hosts())
                    except ValueError:
                        continue
                        
                if not ip_list:
                    print(f"{Colors.RED}[!] No valid IPs in working ranges{Colors.RESET}")
                    self.add_scan_result(scan_type, "No valid IPs in working ranges", "Failed")
                    return
                    
            except Exception as e:
                print(f"{Colors.RED}[!] Error: {e}{Colors.RESET}")
                self.add_scan_result(scan_type, "Initialization", f"Error: {str(e)}")
                return
            
        else:
            print(f"{Colors.RED}[!] Invalid choice{Colors.RESET}")
            return

        self.total_tests = len(ip_list) * len(self.ports)
        self.completed_tests = 0
        self.start_time = time.time()
        self.log_debug(f"Starting scan of {len(ip_list)} IPs across {len(self.ports)} ports (total tests: {self.total_tests})")
        
        try:
            with open(OPEN_PROXIES_FILE, 'w'):
                pass
            self.log_debug("Cleared open proxies file")
        except IOError as e:
            print(f"{Colors.RED}[!] Error clearing output file: {e}{Colors.RESET}")
            self.add_scan_result(scan_type, "File operation", f"Error: {str(e)}")
            return

        tasks = [(ip, port) for ip in ip_list for port in self.ports]
        random.shuffle(tasks)
        self.log_debug("Created randomized task list")

        found_proxies = 0
        batch_size = self.concurrency_limit * 10
        
        for i in range(0, len(tasks), batch_size):
            if self.stop_event.is_set():
                self.log_debug("Scan stopped by user")
                self.add_scan_result(scan_type, "Scan progress", "Stopped by user")
                break
                
            batch = tasks[i:i+batch_size]
            self.log_debug(f"Processing batch {i//batch_size + 1} with {len(batch)} tasks")
            
            results = await asyncio.gather(*[self.check_proxy(ip, port) for ip, port in batch])
            
            for success, ip, port in results:
                if success:
                    found_proxies += 1
                    try:
                        with open(OPEN_PROXIES_FILE, 'a') as f:
                            f.write(f"{ip}:{port}\n")
                        self.log_debug(f"Found open proxy: {ip}:{port}")
                    except IOError as e:
                        print(f"{Colors.RED}[!] Error saving proxy: {e}{Colors.RESET}")
                        self.add_scan_result(scan_type, f"Saving proxy {ip}:{port}", f"Error: {str(e)}")
            
            self.completed_tests += len(batch)
            elapsed = time.time() - self.start_time
            print(f"{Colors.CYAN}\r[*] Progress: {self.completed_tests}/{self.total_tests} | "
                  f"Speed: {int(self.completed_tests/max(1, elapsed))}/s | "
                  f"Found: {found_proxies}{Colors.RESET}", end="")

        elapsed = time.time() - self.start_time
        self.log_debug(f"Scan completed. Found {found_proxies} proxies in {elapsed:.2f} seconds")
        self.add_scan_result(scan_type, "Scan completed", f"Found {found_proxies} proxies in {int(elapsed)}s")
        print(f"\n{Colors.GREEN}[✓] Found {found_proxies} proxies in {int(elapsed)}s "
              f"({int(found_proxies/max(1, elapsed))}/s){Colors.RESET}")

    async def check_proxy(self, ip: str, port: int) -> Tuple[bool, str, int]:
        for attempt in range(MAX_RETRIES + 1):
            try:
                self.log_debug(f"Attempt {attempt + 1} for {ip}:{port}")
                if await self.stealth_check(ip, port):
                    self.log_debug(f"Proxy {ip}:{port} verified")
                    return (True, ip, port)
            except Exception as e:
                self.log_debug(f"Error checking {ip}:{port}: {str(e)}")
                if attempt == MAX_RETRIES:
                    return (False, ip, port)
                await asyncio.sleep(random.uniform(0.5, 1.5))
        return (False, ip, port)

    async def test_working_proxies(self) -> None:
        if not os.path.exists(OPEN_PROXIES_FILE):
            print(f"{Colors.RED}[!] No proxies found to test{Colors.RESET}")
            self.add_scan_result("Proxy Testing", "Initialization", "No proxies to test")
            return

        try:
            with open(OPEN_PROXIES_FILE) as f:
                proxies = [line.strip() for line in f if line.strip()]
            self.log_debug(f"Loaded {len(proxies)} proxies for testing")
            self.add_scan_result("Proxy Testing", f"Loaded {len(proxies)} proxies", "Started")
        except IOError as e:
            print(f"{Colors.RED}[!] Error reading proxies: {e}{Colors.RESET}")
            self.add_scan_result("Proxy Testing", "File operation", f"Error: {str(e)}")
            return

        if not proxies:
            print(f"{Colors.RED}[!] No proxies to test{Colors.RESET}")
            self.add_scan_result("Proxy Testing", "No proxies loaded", "Failed")
            return

        self.total_tests = len(proxies)
        self.completed_tests = 0
        self.start_time = time.time()
        self.log_debug(f"Starting testing of {len(proxies)} proxies")
        
        try:
            with open(WORKING_PROXIES_FILE, 'w'), open(WORKING_RANGES_FILE, 'w'):
                pass
            self.log_debug("Cleared output files")
        except IOError as e:
            print(f"{Colors.RED}[!] Error clearing output files: {e}{Colors.RESET}")
            self.add_scan_result("Proxy Testing", "File operation", f"Error: {str(e)}")
            return

        working_proxies = 0
        batch_size = self.concurrency_limit * 5
        
        for i in range(0, len(proxies), batch_size):
            if self.stop_event.is_set():
                self.log_debug("Testing stopped by user")
                self.add_scan_result("Proxy Testing", "Testing progress", "Stopped by user")
                break
                
            batch = proxies[i:i+batch_size]
            self.log_debug(f"Testing batch {i//batch_size + 1} with {len(batch)} proxies")
            
            results = await asyncio.gather(*[self.test_proxy_connection(proxy) for proxy in batch])
            
            for proxy, speed, anonymity in results:
                if speed is not None:
                    working_proxies += 1
                    try:
                        details = await self.get_proxy_details(proxy.split(':')[0])
                        self.save_to_database(proxy, speed, anonymity, details)
                        self.save_working_range(proxy.split(':')[0])
                        
                        with open(WORKING_PROXIES_FILE, 'a') as f:
                            f.write(f"{proxy}\n")
                        self.log_debug(f"Working proxy: {proxy} (speed: {speed}ms, anonymity: {anonymity})")
                        self.add_scan_result("Proxy Testing", f"Working proxy: {proxy}", f"Speed: {speed}ms, Anonymity: {anonymity}")
                    except Exception as e:
                        print(f"{Colors.YELLOW}[!] Error processing proxy {proxy}: {e}{Colors.RESET}")
                        self.add_scan_result("Proxy Testing", f"Processing proxy {proxy}", f"Error: {str(e)}")
            
            self.completed_tests += len(batch)
            elapsed = time.time() - self.start_time
            print(f"{Colors.CYAN}\r[*] Progress: {self.completed_tests}/{self.total_tests} | "
                  f"Speed: {int(self.completed_tests/max(1, elapsed))}/s | "
                  f"Working: {working_proxies}{Colors.RESET}", end="")

        elapsed = time.time() - self.start_time
        self.log_debug(f"Testing completed. Found {working_proxies} working proxies in {elapsed:.2f} seconds")
        self.add_scan_result("Proxy Testing", "Testing completed", f"Found {working_proxies} working proxies in {int(elapsed)}s")
        print(f"\n{Colors.GREEN}[✓] Verified {working_proxies} working proxies in {int(elapsed)}s "
              f"({int(working_proxies/max(1, elapsed))}/s){Colors.RESET}")

    async def test_proxy_connection(self, proxy: str) -> Tuple[str, Optional[int], str]:
        ip, port = proxy.split(':')
        port = int(port)
        proxy_url = f"http://{ip}:{port}"
        
        for attempt in range(MAX_RETRIES + 1):
            try:
                self.log_debug(f"Testing proxy {proxy} (attempt {attempt + 1})")
                start_time = time.time()
                async with self.session.get(
                    TEST_URL,
                    proxy=proxy_url,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    headers=self.get_random_headers()
                ) as response:
                    if response.status == 204:
                        speed = int((time.time() - start_time) * 1000)
                        anonymity = await self.detect_anonymity(proxy_url)
                        self.log_debug(f"Proxy {proxy} working (speed: {speed}ms, anonymity: {anonymity})")
                        return (proxy, speed, anonymity)
                    elif attempt == MAX_RETRIES:
                        self.log_debug(f"Proxy {proxy} failed with status {response.status}")
                        return (proxy, None, "Unknown")
            except Exception as e:
                self.log_debug(f"Proxy {proxy} failed with error: {str(e)}")
                if attempt == MAX_RETRIES:
                    return (proxy, None, "Unknown")
                await asyncio.sleep(random.uniform(0.5, 2.0))
        
        return (proxy, None, "Unknown")

    async def detect_anonymity(self, proxy_url: str) -> str:
        try:
            test_urls = [
                "http://httpbin.org/headers",
                "http://httpbin.org/ip"
            ]
            
            for url in test_urls:
                try:
                    self.log_debug(f"Testing anonymity at {url}")
                    async with self.session.get(
                        url,
                        proxy=proxy_url,
                        timeout=aiohttp.ClientTimeout(total=self.timeout),
                        headers=self.get_random_headers()
                    ) as response:
                        data = await response.json()
                        headers = data.get("headers", {})
                        
                        if any(h in headers for h in ['Via', 'X-Forwarded-For', 'X-Proxy-ID']):
                            client_ip = proxy_url.split('@')[-1].split(':')[0]
                            if client_ip in headers.get("X-Forwarded-For", ""):
                                self.log_debug("Proxy is Anonymous")
                                return "Anonymous"
                            self.log_debug("Proxy is Transparent")
                            return "Transparent"
                except Exception as e:
                    self.log_debug(f"Anonymity test failed for {url}: {str(e)}")
                    continue
            
            self.log_debug("Proxy is Elite")
            return "Elite"
        except Exception as e:
            self.log_debug(f"Anonymity detection failed: {str(e)}")
            return "Unknown"

    def save_to_database(self, proxy: str, speed: int, anonymity: str, details: dict) -> None:
        ip, port = proxy.split(':')
        try:
            self.cursor.execute('''
                INSERT OR REPLACE INTO proxies 
                (ip, port, country, city, speed, protocol, anonymity, isp, last_checked, is_active)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
            ''', (
                ip,
                int(port),
                details.get("country", "Unknown"),
                details.get("city", "Unknown"),
                speed,
                "HTTP",
                anonymity,
                details.get("isp", "Unknown"),
                datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            ))
            self.conn.commit()
            self.log_debug(f"Saved proxy {proxy} to database")
        except sqlite3.Error as e:
            print(f"{Colors.YELLOW}[!] Database error saving proxy {proxy}: {e}{Colors.RESET}")

    def save_working_range(self, ip: str) -> None:
        try:
            network = ipaddress.IPv4Network(f"{ip}/24", strict=False)
            with open(WORKING_RANGES_FILE, 'a') as f:
                f.write(f"{network}\n")
            self.log_debug(f"Saved working range: {network}")
        except (ipaddress.AddressValueError, IOError) as e:
            print(f"{Colors.YELLOW}[!] Error saving working range for {ip}: {e}{Colors.RESET}")

    async def get_proxy_details(self, ip: str) -> dict:
        details = {
            "country": "IR",
            "city": "Unknown",
            "isp": "Unknown"
        }
        self.log_debug(f"Generated proxy details: {details}")
        return details

    def view_working_proxies(self) -> None:
        clear_screen()
        print(f"{Colors.CYAN}=== Working Proxies ==={Colors.RESET}")
        
        try:
            page_size = 20
            offset = 0
            
            while True:
                self.cursor.execute('''
                    SELECT ip, port, country, speed, anonymity, isp 
                    FROM proxies 
                    WHERE is_active = 1 
                    ORDER BY speed ASC
                    LIMIT ? OFFSET ?
                ''', (page_size, offset))
                proxies = self.cursor.fetchall()
                
                if not proxies and offset == 0:
                    print(f"{Colors.YELLOW}No working proxies found in database{Colors.RESET}")
                    break
                elif not proxies:
                    print(f"{Colors.YELLOW}\nNo more proxies to display{Colors.RESET}")
                    break
                
                print(f"\n{Colors.GREEN}{'IP:Port':<20} {'Country':<10} {'Speed':>7} {'Anonymity':<12} {'ISP'}{Colors.RESET}")
                for proxy in proxies:
                    ip, port, country, speed, anonymity, isp = proxy
                    print(f"{ip}:{port:<15} {country:<10} {speed:>7}ms {anonymity:<12} {isp}")
                
                print(f"\n{Colors.YELLOW}Page {offset//page_size + 1} | Total: {offset + len(proxies)} proxies{Colors.RESET}")
                
                choice = input("\n[N]ext page, [P]revious page, [Q]uit: ").strip().lower()
                if choice == 'n':
                    offset += page_size
                elif choice == 'p' and offset >= page_size:
                    offset -= page_size
                elif choice == 'q':
                    break
                clear_screen()
                print(f"{Colors.CYAN}=== Working Proxies ==={Colors.RESET}")
                
        except sqlite3.Error as e:
            print(f"{Colors.RED}Database error: {e}{Colors.RESET}")
        
        input("\nPress Enter to continue...")

    async def update_iran_ip_ranges(self) -> bool:
        clear_screen()
        print(f"{Colors.MAGENTA}[*] Updating Iranian IP ranges...{Colors.RESET}")
        
        sources = [
            "https://raw.githubusercontent.com/SecOps-Institute/Tor-IP-Addresses/master/iran-ip-ranges.txt",
            "https://raw.githubusercontent.com/ipverse/rir-ip/master/country/ir/ipv4-aggregated.txt",
            "https://raw.githubusercontent.com/herrbischoff/country-ip-blocks/master/ipv4/ir.cidr"
        ]
        
        collected_ranges = set()
        for url in sources:
            try:
                print(f"{Colors.CYAN}[*] Checking {url.split('/')[2]}...{Colors.RESET}")
                async with self.session.get(url, timeout=15) as response:
                    if response.status == 200:
                        text = await response.text()
                        new_ranges = 0
                        for line in text.splitlines():
                            line = line.strip()
                            if line and not line.startswith("#"):
                                try:
                                    ipaddress.IPv4Network(line)
                                    if line not in collected_ranges:
                                        collected_ranges.add(line)
                                        new_ranges += 1
                                except ValueError:
                                    continue
                        print(f"{Colors.GREEN}[+] Found {new_ranges} new ranges{Colors.RESET}")
                        self.log_debug(f"Found {new_ranges} new ranges from {url}")
            except Exception as e:
                print(f"{Colors.RED}[!] Error fetching {url}: {str(e)[:50]}...{Colors.RESET}")
                self.log_debug(f"Error fetching {url}: {str(e)}")
        
        if not collected_ranges:
            print(f"{Colors.RED}[!] Failed to fetch any IP ranges{Colors.RESET}")
            return False
        
        try:
            with open(IP_RANGES_FILE, 'w') as f:
                f.write("\n".join(sorted(collected_ranges)))
            print(f"{Colors.GREEN}[✓] Saved {len(collected_ranges)} total ranges{Colors.RESET}")
            self.log_debug(f"Saved {len(collected_ranges)} IP ranges to file")
            self.add_scan_result("IP Range Update", "Updated Iranian IP ranges", f"Added {len(collected_ranges)} ranges")
            return True
        except IOError as e:
            print(f"{Colors.RED}[!] Save error: {e}{Colors.RESET}")
            return False

    def show_settings(self) -> None:
        clear_screen()
        print(f"{Colors.YELLOW}=== Current Settings ==={Colors.RESET}")
        print(f"Ports: {', '.join(map(str, self.ports))}")
        print(f"Timeout: {self.timeout}s")
        print(f"Threads: {self.concurrency_limit}")
        
        print(f"\n{Colors.YELLOW}=== Update Settings ==={Colors.RESET}")
        try:
            ports_input = input("New ports (comma separated, empty to keep current): ").strip()
            if ports_input:
                new_ports = []
                for p in ports_input.split(","):
                    p = p.strip()
                    if p.isdigit() and 1 <= int(p) <= 65535:
                        new_ports.append(int(p))
                if new_ports:
                    self.ports = new_ports
                    self.log_debug(f"Updated ports to: {self.ports}")
            
            timeout_input = input(f"Timeout (current: {self.timeout}s): ").strip()
            if timeout_input and timeout_input.isdigit():
                self.timeout = max(1, min(int(timeout_input), 30))
                self.log_debug(f"Updated timeout to: {self.timeout}s")
            
            threads_input = input(f"Threads (current: {self.concurrency_limit}): ").strip()
            if threads_input and threads_input.isdigit():
                self.concurrency_limit = max(10, min(int(threads_input), 500))
                self.log_debug(f"Updated threads to: {self.concurrency_limit}")
            
            self.save_config()
            print(f"{Colors.GREEN}[✓] Settings updated{Colors.RESET}")
            self.add_scan_result("Settings Update", "Modified scanner settings", "Success")
        except ValueError:
            print(f"{Colors.RED}[!] Invalid input{Colors.RESET}")
        
        input("\nPress Enter to continue...")

    def show_debug_log(self) -> None:
        clear_screen()
        print(f"{Colors.CYAN}=== Debug Information ==={Colors.RESET}")
        
        if not self.debug_log:
            print(f"{Colors.YELLOW}No debug information available{Colors.RESET}")
        else:
            print(f"\nLast {min(20, len(self.debug_log))} debug messages:")
            for msg in self.debug_log[-20:]:
                print(f"{Colors.MAGENTA}{msg}{Colors.RESET}")
            
            try:
                with open(DEBUG_LOG_FILE, 'a') as f:
                    f.write("\n".join(self.debug_log) + "\n")
                print(f"\n{Colors.GREEN}[✓] Saved {len(self.debug_log)} debug messages to {DEBUG_LOG_FILE}{Colors.RESET}")
            except IOError as e:
                print(f"{Colors.RED}[!] Error saving debug log: {e}{Colors.RESET}")
        
        input("\nPress Enter to continue...")

    def toggle_debug_mode(self) -> None:
        self.debug_mode = not self.debug_mode
        status = "ON" if self.debug_mode else "OFF"
        color = Colors.GREEN if self.debug_mode else Colors.RED
        print(f"\n{color}Debug mode is now {status}{Colors.RESET}")
        self.log_debug(f"Debug mode toggled to {status}")
        input("\nPress Enter to continue...")

    async def main_menu(self) -> None:
        await self.async_init()
        
        while not self.stop_event.is_set():
            clear_screen()
            print(f"""
{Colors.CYAN}=== Http Proxy Scanner ==={Colors.RESET}
{Colors.GREEN}[1]{Colors.RESET} Scan for proxies
{Colors.GREEN}[2]{Colors.RESET} Test found proxies
{Colors.GREEN}[3]{Colors.RESET} View working proxies
{Colors.GREEN}[4]{Colors.RESET} Update IP ranges
{Colors.GREEN}[5]{Colors.RESET} Check single proxy
{Colors.GREEN}[6]{Colors.RESET} Settings
{Colors.GREEN}[7]{Colors.RESET} View debug log
{Colors.GREEN}[8]{Colors.RESET} Toggle debug mode ({'ON' if self.debug_mode else 'OFF'})
{Colors.GREEN}[9]{Colors.RESET} Save Progress to file
{Colors.GREEN}[0]{Colors.RESET} Exit
""")
            choice = input(f"{Colors.BLUE}Select option:{Colors.RESET} ").strip()
            
            if choice == "1":
                await self.scan_for_open_proxies()
                input("\nPress Enter to continue...")
            elif choice == "2":
                await self.test_working_proxies()
                input("\nPress Enter to continue...")
            elif choice == "3":
                self.view_working_proxies()
            elif choice == "4":
                await self.update_iran_ip_ranges()
                input("\nPress Enter to continue...")
            elif choice == "5":
                await self.check_single_ip()
            elif choice == "6":
                self.show_settings()
            elif choice == "7":
                self.show_debug_log()
            elif choice == "8":
                self.toggle_debug_mode()
            elif choice == "9":
                self.save_results_to_file()
                input("\nPress Enter to continue...")
            elif choice == "0":
                break
            else:
                print(f"{Colors.RED}[!] Invalid choice{Colors.RESET}")
                await asyncio.sleep(1)
        
        await self.close()

def clear_screen() -> None:
    os.system('cls' if os.name == 'nt' else 'clear')

async def main():
    scanner = ProxyScanner()
    try:
        await scanner.main_menu()
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[!] Interrupted by user{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.RED}[!] Fatal error: {e}{Colors.RESET}")
    finally:
        await scanner.close()

if __name__ == "__main__":
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[!] Program terminated{Colors.RESET}")
