"""
AQUA_SLOVIC - Interactive CLI Shell
Bettercap-style command interface for all modules.
"""

import os
import sys
import shlex

try:
    import readline
except ImportError:
    try:
        import pyreadline3 as readline  # Windows fallback
    except ImportError:
        pass  # No readline support - input() still works fine

from colorama import Fore, Style, init

init(autoreset=True)

from aquaslovic.core.utils import (
    print_info, print_success, print_error, print_warning,
    print_banner, print_table, get_local_ip, get_gateway_ip,
    get_subnet, get_default_interface, is_root,
)
from aquaslovic.core.scanner import NetworkScanner
from aquaslovic.core.sniffer import PacketSniffer
from aquaslovic.core.arpspoof import ARPSpoofer
from aquaslovic.core.dnsspoof import DNSSpoofer
from aquaslovic.core.httpproxy import HTTPProxy


class AquaSlovicCLI:
    """Interactive command-line interface for AQUA_SLOVIC."""

    def __init__(self):
        self.scanner = NetworkScanner()
        self.sniffer = PacketSniffer()
        self.arp_spoofer = ARPSpoofer()
        self.dns_spoofer = DNSSpoofer()
        self.http_proxy = HTTPProxy()

        # Session variables
        self.variables = {
            "net.interface": get_default_interface() or "auto",
            "net.subnet": get_subnet() or "auto",
            "arp.target": "",
            "arp.gateway": get_gateway_ip() or "",
            "dns.spoof.domains": "",
            "http.proxy.port": "8080",
        }

        # Command map
        self.commands = {
            "help": self._cmd_help,
            "?": self._cmd_help,
            "exit": self._cmd_exit,
            "quit": self._cmd_exit,
            "q": self._cmd_exit,
            "clear": self._cmd_clear,
            "set": self._cmd_set,
            "get": self._cmd_get,
            "env": self._cmd_env,
            "net.scan": self._cmd_net_scan,
            "net.sniff": self._cmd_net_sniff,
            "net.internet": self._cmd_net_internet,
            "arp.spoof": self._cmd_arp_spoof,
            "dns.spoof": self._cmd_dns_spoof,
            "http.proxy": self._cmd_http_proxy,
        }

    def run(self):
        """Start the interactive CLI."""
        print_banner()
        self._show_status()

        try:
            while True:
                try:
                    prompt = f"{Fore.CYAN}aqua_slovic{Style.RESET_ALL} > "
                    line = input(prompt).strip()

                    if not line:
                        continue

                    self._execute(line)

                except KeyboardInterrupt:
                    print()
                    print_info("Use 'exit' to quit.")
                except EOFError:
                    break

        except Exception as e:
            print_error(f"Fatal error: {e}")
        finally:
            self._cleanup()

    def _execute(self, line):
        """Parse and execute a command."""
        try:
            parts = shlex.split(line)
        except ValueError:
            parts = line.split()

        if not parts:
            return

        cmd = parts[0].lower()
        args = parts[1:]

        if cmd in self.commands:
            try:
                self.commands[cmd](args)
            except Exception as e:
                print_error(f"Command error: {e}")
        else:
            print_error(f"Unknown command: {cmd}")
            print_info("Type 'help' for a list of commands.")

    def _show_status(self):
        """Show current environment status."""
        local_ip = get_local_ip()
        gateway = get_gateway_ip() or "N/A"
        subnet = get_subnet() or "N/A"
        iface = get_default_interface() or "auto"
        is_admin = f"{Fore.GREEN}yes{Style.RESET_ALL}" if is_root() else f"{Fore.RED}no{Style.RESET_ALL}"

        print(f"\n  {Fore.WHITE}Local IP     :{Style.RESET_ALL} {local_ip}")
        print(f"  {Fore.WHITE}Gateway      :{Style.RESET_ALL} {gateway}")
        print(f"  {Fore.WHITE}Subnet       :{Style.RESET_ALL} {subnet}")
        print(f"  {Fore.WHITE}Interface    :{Style.RESET_ALL} {iface}")
        print(f"  {Fore.WHITE}Admin/Root   :{Style.RESET_ALL} {is_admin}")
        print()

    # -- Help ------------------------------------------------------------

    def _cmd_help(self, args):
        """Show help for all commands or a specific module."""
        if args:
            module = args[0].lower()
            self._module_help(module)
            return

        print(f"\n  {Fore.CYAN}--- AQUA_SLOVIC Commands ---{Style.RESET_ALL}\n")

        sections = [
            ("General", [
                ("help [module]", "Show this help or module-specific help"),
                ("set <var> <val>", "Set a session variable"),
                ("get <var>", "Get a session variable value"),
                ("env", "Show all session variables"),
                ("clear", "Clear the screen"),
                ("exit / quit", "Exit AQUA_SLOVIC"),
            ]),
            ("Network Discovery & Intel", [
                ("net.scan", "Scan the network for devices (ARP scan)"),
                ("net.scan ping", "Scan using ping sweep (no root needed)"),
                ("net.internet", "Show active internet status & local network client count"),
            ]),
            ("Packet Sniffing", [
                ("net.sniff on [filter]", "Start packet capture"),
                ("net.sniff off", "Stop packet capture"),
            ]),
            ("ARP Spoofing", [
                ("arp.spoof on <target>", "Start ARP spoofing a target"),
                ("arp.spoof off", "Stop ARP spoofing & restore tables"),
            ]),
            ("DNS Spoofing", [
                ("dns.spoof add <domain> <ip>", "Add a DNS spoofing rule"),
                ("dns.spoof remove <domain>", "Remove a DNS rule"),
                ("dns.spoof all <ip>", "Redirect ALL DNS queries to an IP"),
                ("dns.spoof list", "List current DNS rules"),
                ("dns.spoof on", "Start DNS spoofing"),
                ("dns.spoof off", "Stop DNS spoofing"),
            ]),
            ("HTTP Proxy", [
                ("http.proxy on [port]", "Start HTTP proxy (default: 8080)"),
                ("http.proxy off", "Stop HTTP proxy"),
                ("http.proxy inject <js>", "Inject JS into HTML responses"),
                ("http.proxy inject off", "Clear JS injection"),
            ]),
        ]

        for section_name, cmds in sections:
            print(f"  {Fore.YELLOW}{section_name}{Style.RESET_ALL}")
            for cmd, desc in cmds:
                print(f"    {Fore.WHITE}{cmd:<35}{Style.RESET_ALL} {desc}")
            print()

    def _module_help(self, module):
        """Show detailed help for a specific module."""
        helps = {
            "net.scan": """
  net.scan - Network Discovery Module

  Discovers all devices on your local network.
  Search can only happen on networks you are connected to.

  Commands:
    net.scan           ARP scan (fast, requires root/admin)
    net.scan ping      Ping sweep (slower, no root needed)
    net.scan <subnet>  Scan a specific subnet (e.g., 192.168.1.0/24)

  Variables:
    set net.subnet <CIDR>   Set the target subnet
    set net.interface <if>  Set the network interface
""",
            "net.internet": """
  net.internet - Active Internet & Client Detection Module

  Retrieves host internet status and analyzes local network device population.

  Commands:
    net.internet       Performs connectivity tests and counts local clients
""",
            "net.sniff": """
  net.sniff - Packet Sniffer Module

  Captures and analyzes network packets in real-time.
  Requires root/admin privileges.

  Commands:
    net.sniff on                    Start sniffing (all traffic)
    net.sniff on tcp port 80        Start with BPF filter
    net.sniff on "host 192.168.1.5" Filter by host
    net.sniff off                   Stop sniffing

  Common BPF Filters:
    tcp port 80        HTTP traffic
    tcp port 443       HTTPS traffic
    udp port 53        DNS traffic
    host 192.168.1.5   All traffic to/from a host
    tcp port 21        FTP traffic
""",
            "arp.spoof": """
  arp.spoof - ARP Spoofing Module

  Performs ARP cache poisoning for Man-in-the-Middle positioning.
  ! For authorized security testing only!
  Requires root/admin privileges.

  Commands:
    arp.spoof on <target_ip>    Start spoofing (gateway auto-detected)
    arp.spoof off               Stop & restore ARP tables

  Variables:
    set arp.gateway <ip>   Set gateway IP (auto-detected by default)
    set arp.target <ip>    Pre-set target IP
""",
            "dns.spoof": """
  dns.spoof - DNS Spoofing Module

  Intercepts DNS queries and sends forged responses.
  ! For authorized security testing only!
  Requires root/admin & typically used with ARP spoofing.

  Commands:
    dns.spoof add <domain> <ip>    Add a spoofing rule
    dns.spoof add *.example.com <ip>  Wildcard rule
    dns.spoof remove <domain>      Remove a rule
    dns.spoof all <ip>             Redirect ALL queries to an IP
    dns.spoof list                 Show current rules
    dns.spoof on                   Start DNS spoofing
    dns.spoof off                  Stop DNS spoofing
""",
            "http.proxy": """
  http.proxy - HTTP Proxy Module

  Transparent HTTP proxy for traffic inspection and injection.
  Configure the target's browser to use this as a proxy.

  Commands:
    http.proxy on [port]        Start proxy (default: 8080)
    http.proxy off              Stop proxy
    http.proxy inject <js_code> Inject JavaScript into HTML pages
    http.proxy inject off       Clear JS injection

  Variables:
    set http.proxy.port <port>  Set default proxy port
""",
        }

        if module in helps:
            print(helps[module])
        else:
            print_warning(f"No detailed help for '{module}'. Try: help")

    # -- Session Variables -----------------------------------------------

    def _cmd_set(self, args):
        """Set a session variable."""
        if len(args) < 2:
            print_error("Usage: set <variable> <value>")
            print_info("Use 'env' to see all variables.")
            return

        var = args[0].lower()
        val = " ".join(args[1:])

        if var == "net.subnet":
            from aquaslovic.core.utils import is_subnet_connected
            if not is_subnet_connected(val):
                print_error("Error: Search must only happen on a network you are connected to.")
                return

        if var not in self.variables:
            print_warning(f"Setting new session variable: {var}")

        self.variables[var] = val
        print_success(f"{var} -> {Fore.WHITE}{val}{Style.RESET_ALL}")

    def _cmd_get(self, args):
        """Get a session variable."""
        if not args:
            print_error("Usage: get <variable>")
            return

        var = args[0].lower()
        if var in self.variables:
            print_info(f"{var} = {Fore.WHITE}{self.variables[var]}{Style.RESET_ALL}")
        else:
            print_warning(f"Variable '{var}' not set.")

    def _cmd_env(self, args):
        """Show all session variables."""
        print_info("Session variables:")
        for var, val in sorted(self.variables.items()):
            print(f"  {Fore.WHITE}{var:<25}{Style.RESET_ALL} {val}")
        print()

    # -- Network Scanner -------------------------------------------------

    def _cmd_net_scan(self, args):
        """Execute a network scan."""
        if args and args[0].lower() == "ping":
            subnet = args[1] if len(args) > 1 else self.variables.get("net.subnet")
            if subnet == "auto":
                subnet = None
            self.scanner.ping_sweep(subnet)
        else:
            subnet = args[0] if args else self.variables.get("net.subnet")
            if subnet == "auto":
                subnet = None
            self.scanner.arp_scan(subnet)

    # -- Active Internet & Client Detection ------------------------------

    def _cmd_net_internet(self, args):
        """Execute active internet testing and client scanning."""
        from aquaslovic.core.utils import check_internet_connection, get_subnet
        
        print_info("Conducting internet connectivity tests...")
        online, rtt = check_internet_connection()
        if online:
            print_success(f"Internet Status  : {Fore.GREEN}ONLINE{Style.RESET_ALL} (Ping RTT: {rtt}ms)")
        else:
            print_warning(f"Internet Status  : {Fore.RED}OFFLINE{Style.RESET_ALL}")

        subnet = self.variables.get("net.subnet")
        if subnet == "auto":
            subnet = get_subnet()

        if not subnet:
            print_error("Could not obtain connected subnet CIDR to list local clients.")
            return

        print_info(f"Scanning {subnet} to count online network devices...")
        
        # Divert output of net.scan ping or scan results to avoid output pollution if we want a clean count
        # Or, we can simply execute ARP scan or ping sweep programmatically and print the result count.
        # Let's count hosts by executing Scanner results directly in-memory to get a precise read.
        try:
            # Re-read network scanner results
            prev_results = self.scanner.results
            
            # Run scan quietly or normally. Let's do a fast ARP scan or fall back to ping sweep.
            # To be friendly, let's use scanner's scanning methods but count them nicely.
            if is_root():
                # Temporarily redirect output or let it scan
                self.scanner.arp_scan(subnet)
            else:
                self.scanner.ping_sweep(subnet)
                
            active_count = len(self.scanner.results)
            print_success(f"Intranet Status  : {Fore.WHITE}{active_count} active device(s) found on {subnet}{Style.RESET_ALL}")
        except Exception as e:
            print_error(f"Failed to scan local network: {e}")

    # -- Packet Sniffer --------------------------------------------------

    def _cmd_net_sniff(self, args):
        """Start or stop packet sniffing."""
        if not args:
            print_error("Usage: net.sniff on [filter] | net.sniff off")
            return

        action = args[0].lower()

        if action == "on":
            bpf_filter = " ".join(args[1:]) if len(args) > 1 else ""
            iface = self.variables.get("net.interface")
            if iface == "auto":
                iface = None
            self.sniffer.start(iface=iface, bpf_filter=bpf_filter)

        elif action == "off":
            self.sniffer.stop()
        else:
            print_error("Usage: net.sniff on [filter] | net.sniff off")

    # -- ARP Spoofer -----------------------------------------------------

    def _cmd_arp_spoof(self, args):
        """Start or stop ARP spoofing."""
        if not args:
            print_error("Usage: arp.spoof on <target_ip> | arp.spoof off")
            return

        action = args[0].lower()

        if action == "on":
            target = args[1] if len(args) > 1 else self.variables.get("arp.target")
            if not target:
                print_error("Specify target: arp.spoof on <target_ip>")
                return
            gateway = self.variables.get("arp.gateway") or None
            iface = self.variables.get("net.interface")
            if iface == "auto":
                iface = None
            self.arp_spoofer.start(target, gateway, iface=iface)

        elif action == "off":
            self.arp_spoofer.stop()
        else:
            print_error("Usage: arp.spoof on <target_ip> | arp.spoof off")

    # -- DNS Spoofer -----------------------------------------------------

    def _cmd_dns_spoof(self, args):
        """DNS spoofing commands."""
        if not args:
            print_error("Usage: dns.spoof add|remove|all|list|on|off")
            return

        action = args[0].lower()

        if action == "add":
            if len(args) < 3:
                print_error("Usage: dns.spoof add <domain> <ip>")
                return
            self.dns_spoofer.add_record(args[1], args[2])

        elif action == "remove":
            if len(args) < 2:
                print_error("Usage: dns.spoof remove <domain>")
                return
            self.dns_spoofer.remove_record(args[1])

        elif action == "all":
            if len(args) < 2:
                print_error("Usage: dns.spoof all <ip>")
                return
            self.dns_spoofer.spoof_all = args[1]
            print_success(f"ALL DNS queries -> {Fore.RED}{args[1]}{Style.RESET_ALL}")

        elif action == "list":
            self.dns_spoofer.list_records()

        elif action == "on":
            iface = self.variables.get("net.interface")
            if iface == "auto":
                iface = None
            self.dns_spoofer.start(iface=iface)

        elif action == "off":
            self.dns_spoofer.stop()

        else:
            print_error("Usage: dns.spoof add|remove|all|list|on|off")

    # -- HTTP Proxy ------------------------------------------------------

    def _cmd_http_proxy(self, args):
        """HTTP proxy commands."""
        if not args:
            print_error("Usage: http.proxy on [port] | off | inject <js>")
            return

        action = args[0].lower()

        if action == "on":
            port = int(args[1]) if len(args) > 1 else int(self.variables.get("http.proxy.port", 8080))
            self.http_proxy.start(port)

        elif action == "off":
            self.http_proxy.stop()

        elif action == "inject":
            if len(args) < 2:
                print_error("Usage: http.proxy inject <js_code> | http.proxy inject off")
                return
            if args[1].lower() == "off":
                self.http_proxy.clear_js_inject()
            else:
                js = " ".join(args[1:])
                self.http_proxy.set_js_inject(js)

        else:
            print_error("Usage: http.proxy on [port] | off | inject <js>")

    # -- General ---------------------------------------------------------

    def _cmd_clear(self, args):
        """Clear the screen."""
        os.system("cls" if os.name == "nt" else "clear")
        print_banner()

    def _cmd_exit(self, args):
        """Exit AQUA_SLOVIC."""
        self._cleanup()
        print_info("Goodbye!")
        sys.exit(0)

    def _cleanup(self):
        """Clean up all running modules before exit."""
        if self.sniffer.running:
            self.sniffer.stop()
        if self.arp_spoofer.running:
            self.arp_spoofer.stop()
        if self.dns_spoofer.running:
            self.dns_spoofer.stop()
        if self.http_proxy.running:
            self.http_proxy.stop()
