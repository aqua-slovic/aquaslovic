"""
AQUA_SLOVIC - Network Scanner Module
Discover all devices on the local network using ARP scan or ping sweep.
"""

import socket
import subprocess
import threading
import time
import platform
import re

from colorama import Fore, Style

from aquaslovic.core.utils import (
    print_info, print_success, print_error, print_warning,
    print_table, get_local_ip, get_gateway_ip, get_subnet,
    get_default_interface, is_root, require_root,
    resolve_hostname, get_mac, lookup_vendor, is_windows,
    is_subnet_connected,
)


class NetworkScanner:
    """
    Network device discovery using ARP scan and ping sweep.

    - ARP scan: Fast and accurate, requires root/admin
    - Ping sweep: Slower fallback, no root needed
    """

    def __init__(self):
        self.results = []

    def arp_scan(self, subnet=None):
        """
        Perform an ARP scan on the local network.
        Requires root/admin privileges.

        Args:
            subnet: Target subnet in CIDR format (e.g., '192.168.1.0/24').
                    Auto-detected if not specified.
        """
        if not require_root():
            print_info("Falling back to ping sweep (no root privileges).")
            self.ping_sweep(subnet)
            return

        subnet = subnet or get_subnet()
        if not subnet:
            print_error("Could not detect subnet. Specify one: net.scan 192.168.1.0/24")
            return

        if not is_subnet_connected(subnet):
            print_error("Error: Search must only happen on a network you are connected to.")
            return

        print_info(f"ARP scanning {Fore.WHITE}{subnet}{Style.RESET_ALL} ...")

        try:
            from scapy.all import ARP, Ether, srp, conf

            # Set interface if available
            iface = get_default_interface()
            if iface:
                conf.iface = iface

            ans, _ = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet),
                timeout=3, verbose=False,
            )

            self.results = []
            local_ip = get_local_ip()
            gateway_ip = get_gateway_ip()

            for _, rcv in ans:
                ip = rcv.psrc
                mac = rcv.hwsrc
                hostname = resolve_hostname(ip)
                vendor = lookup_vendor(mac)

                # Tag special devices
                tag = ""
                if ip == gateway_ip:
                    tag = f"  {Fore.YELLOW}(gateway){Style.RESET_ALL}"
                elif ip == local_ip:
                    tag = f"  {Fore.GREEN}(you){Style.RESET_ALL}"

                self.results.append({
                    "ip": ip,
                    "mac": mac,
                    "hostname": hostname,
                    "vendor": vendor,
                    "tag": tag,
                })

            self._display_results()

        except ImportError:
            print_error("Scapy is required for ARP scan. Install: pip install scapy")
            print_info("Falling back to ping sweep...")
            self.ping_sweep(subnet)
        except Exception as e:
            print_error(f"ARP scan failed: {e}")

    def ping_sweep(self, subnet=None):
        """
        Perform a ping sweep on the local network.
        Does not require root/admin privileges.

        Args:
            subnet: Target subnet in CIDR format. Auto-detected if not specified.
        """
        subnet = subnet or get_subnet()
        if not subnet:
            print_error("Could not detect subnet. Specify one: net.scan ping 192.168.1.0/24")
            return

        if not is_subnet_connected(subnet):
            print_error("Error: Search must only happen on a network you are connected to.")
            return

        print_info(f"Ping sweeping {Fore.WHITE}{subnet}{Style.RESET_ALL} (this may take a while)...")

        # Parse subnet
        try:
            base_ip, cidr = subnet.split("/")
            cidr = int(cidr)
        except ValueError:
            print_error(f"Invalid subnet format: {subnet}")
            return

        if cidr != 24:
            print_warning("Ping sweep works best with /24 subnets.")

        # Generate IP range for /24
        parts = base_ip.split(".")
        base = ".".join(parts[:3])

        self.results = []
        local_ip = get_local_ip()
        gateway_ip = get_gateway_ip()
        threads = []
        lock = threading.Lock()

        def ping_host(ip):
            """Ping a single host."""
            try:
                if is_windows():
                    cmd = ["ping", "-n", "1", "-w", "1000", ip]
                else:
                    cmd = ["ping", "-c", "1", "-W", "1", ip]

                result = subprocess.run(
                    cmd, capture_output=True, timeout=3
                )

                if result.returncode == 0:
                    hostname = resolve_hostname(ip)
                    mac = get_mac(ip) if is_root() else "N/A"
                    vendor = lookup_vendor(mac) if mac != "N/A" else "N/A"

                    tag = ""
                    if ip == gateway_ip:
                        tag = f"  {Fore.YELLOW}(gateway){Style.RESET_ALL}"
                    elif ip == local_ip:
                        tag = f"  {Fore.GREEN}(you){Style.RESET_ALL}"

                    with lock:
                        self.results.append({
                            "ip": ip,
                            "mac": mac,
                            "hostname": hostname,
                            "vendor": vendor,
                            "tag": tag,
                        })
            except (subprocess.TimeoutExpired, Exception):
                pass

        # Ping all hosts in the subnet
        for i in range(1, 255):
            ip = f"{base}.{i}"
            t = threading.Thread(target=ping_host, args=(ip,))
            threads.append(t)
            t.start()

            # Limit concurrent threads
            if len(threads) >= 50:
                for t in threads:
                    t.join(timeout=5)
                threads = []

        # Wait for remaining threads
        for t in threads:
            t.join(timeout=5)

        # Sort by IP
        self.results.sort(key=lambda x: [int(p) for p in x["ip"].split(".")])
        self._display_results()

    def _display_results(self):
        """Display scan results in a table."""
        if not self.results:
            print_warning("No devices found.")
            return

        print_success(f"Found {Fore.WHITE}{len(self.results)}{Style.RESET_ALL} device(s):")

        headers = ["IP Address", "MAC Address", "Hostname", "Vendor"]
        rows = []
        for r in self.results:
            rows.append([
                f"{r['ip']}{r['tag']}",
                r["mac"],
                r["hostname"],
                r["vendor"],
            ])

        print_table(headers, rows)
