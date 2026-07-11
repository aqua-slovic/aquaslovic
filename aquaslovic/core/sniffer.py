"""
AQUA_SLOVIC - Packet Sniffer Module
Capture and analyze network packets in real-time with protocol analysis
and credential detection.
"""

import threading
import time

from colorama import Fore, Style

from aquaslovic.core.utils import (
    print_info, print_success, print_error, print_warning,
    is_root, require_root, get_default_interface,
)


class PacketSniffer:
    """
    Real-time packet capture and analysis.

    Features:
        - Protocol analysis (HTTP, DNS, FTP, etc.)
        - Credential detection in cleartext protocols
        - BPF filter support
        - Requires root/admin privileges
    """

    def __init__(self):
        self.running = False
        self.sniff_thread = None
        self.packet_count = 0

    def start(self, iface=None, bpf_filter=""):
        """
        Start packet capture.

        Args:
            iface: Network interface to sniff on (auto-detected if None)
            bpf_filter: BPF filter string (e.g., 'tcp port 80')
        """
        if not require_root():
            return

        if self.running:
            print_warning("Sniffer is already running. Stop it first: net.sniff off")
            return

        try:
            from scapy.all import conf
        except ImportError:
            print_error("Scapy is required for packet sniffing. Install: pip install scapy")
            return

        self.running = True
        self.packet_count = 0

        filter_msg = f" with filter: {Fore.WHITE}{bpf_filter}{Style.RESET_ALL}" if bpf_filter else ""
        print_success(f"Packet sniffer started{filter_msg}")
        print_info("Press Ctrl+C or type 'net.sniff off' to stop.")

        self.sniff_thread = threading.Thread(
            target=self._sniff_loop,
            args=(iface, bpf_filter),
            daemon=True,
        )
        self.sniff_thread.start()

    def stop(self):
        """Stop packet capture."""
        if not self.running:
            print_warning("Sniffer is not running.")
            return

        self.running = False
        print_info(f"Sniffer stopped. Captured {Fore.WHITE}{self.packet_count}{Style.RESET_ALL} packet(s).")

    def _sniff_loop(self, iface, bpf_filter):
        """Main sniffing loop using scapy."""
        try:
            from scapy.all import sniff as scapy_sniff, conf

            if iface:
                conf.iface = iface

            # Use a loop with short timeouts instead of one blocking call.
            # This ensures we check self.running every ~1 second, so
            # start/stop is responsive even when there's low traffic.
            while self.running:
                scapy_sniff(
                    prn=self._process_packet,
                    filter=bpf_filter if bpf_filter else None,
                    store=False,
                    stop_filter=lambda p: not self.running,
                    timeout=1,
                    iface=iface,
                )
        except Exception as e:
            if self.running:
                print_error(f"Sniffer error: {e}")
                self.running = False

    def _process_packet(self, packet):
        """Process and display a captured packet."""
        if not self.running:
            return

        self.packet_count += 1

        try:
            from scapy.all import IP, TCP, UDP, DNS, DNSQR, Raw

            if not packet.haslayer(IP):
                return

            ip_layer = packet[IP]
            src = ip_layer.src
            dst = ip_layer.dst
            proto = ip_layer.proto

            # Determine protocol
            if packet.haslayer(TCP):
                tcp = packet[TCP]
                sport = tcp.sport
                dport = tcp.dport

                # HTTP detection
                if dport == 80 or sport == 80:
                    self._print_packet("HTTP", src, dst, sport, dport, Fore.GREEN)
                    if packet.haslayer(Raw):
                        self._analyze_http(packet[Raw].load, src, dst)

                # HTTPS detection
                elif dport == 443 or sport == 443:
                    self._print_packet("HTTPS", src, dst, sport, dport, Fore.CYAN)

                # FTP detection
                elif dport == 21 or sport == 21:
                    self._print_packet("FTP", src, dst, sport, dport, Fore.YELLOW)
                    if packet.haslayer(Raw):
                        self._analyze_ftp(packet[Raw].load, src, dst)

                # SSH detection
                elif dport == 22 or sport == 22:
                    self._print_packet("SSH", src, dst, sport, dport, Fore.MAGENTA)

                # Telnet detection
                elif dport == 23 or sport == 23:
                    self._print_packet("TELNET", src, dst, sport, dport, Fore.RED)
                    if packet.haslayer(Raw):
                        self._analyze_telnet(packet[Raw].load, src, dst)

                # SMTP detection
                elif dport == 25 or sport == 25 or dport == 587 or sport == 587:
                    self._print_packet("SMTP", src, dst, sport, dport, Fore.YELLOW)

                # Other TCP
                else:
                    self._print_packet("TCP", src, dst, sport, dport, Fore.WHITE)

            elif packet.haslayer(UDP):
                udp = packet[UDP]
                sport = udp.sport
                dport = udp.dport

                # DNS detection
                if packet.haslayer(DNS) and packet.haslayer(DNSQR):
                    qname = packet[DNSQR].qname.decode(errors="ignore").rstrip(".")
                    print(
                        f"  {Fore.BLUE}[DNS]{Style.RESET_ALL} "
                        f"{src} -> {dst}  Query: {Fore.WHITE}{qname}{Style.RESET_ALL}"
                    )
                elif dport == 53 or sport == 53:
                    self._print_packet("DNS", src, dst, sport, dport, Fore.BLUE)
                else:
                    self._print_packet("UDP", src, dst, sport, dport, Fore.WHITE)

        except Exception:
            pass  # Silently skip malformed packets

    def _print_packet(self, proto, src, dst, sport, dport, color):
        """Print a formatted packet line."""
        print(
            f"  {color}[{proto}]{Style.RESET_ALL} "
            f"{src}:{sport} -> {dst}:{dport}"
        )

    def _analyze_http(self, payload, src, dst):
        """Analyze HTTP payload for credentials and interesting data."""
        try:
            data = payload.decode(errors="ignore")

            # Check for HTTP methods
            if data.startswith(("GET ", "POST ", "PUT ", "DELETE ")):
                first_line = data.split("\r\n")[0]
                print(
                    f"    {Fore.GREEN}>> {first_line}{Style.RESET_ALL}"
                )

            # Check for Host header
            for line in data.split("\r\n"):
                if line.lower().startswith("host:"):
                    host = line.split(":", 1)[1].strip()
                    print(f"    Host: {Fore.WHITE}{host}{Style.RESET_ALL}")
                    break

            # Check for credentials in POST data
            lower = data.lower()
            cred_keywords = ["password", "passwd", "pass", "pwd", "user", "username",
                             "login", "email", "token", "auth", "session"]
            for keyword in cred_keywords:
                if keyword in lower:
                    print(
                        f"    {Fore.RED}[CREDENTIAL]{Style.RESET_ALL} "
                        f"Possible credential in {src}->{dst}: "
                        f"{Fore.YELLOW}{data[:200]}{Style.RESET_ALL}"
                    )
                    break
        except Exception:
            pass

    def _analyze_ftp(self, payload, src, dst):
        """Analyze FTP payload for credentials."""
        try:
            data = payload.decode(errors="ignore").strip()
            if data.upper().startswith("USER ") or data.upper().startswith("PASS "):
                print(
                    f"    {Fore.RED}[CREDENTIAL]{Style.RESET_ALL} "
                    f"FTP {src}->{dst}: {Fore.YELLOW}{data}{Style.RESET_ALL}"
                )
        except Exception:
            pass

    def _analyze_telnet(self, payload, src, dst):
        """Analyze Telnet payload for credentials."""
        try:
            data = payload.decode(errors="ignore").strip()
            if data and len(data) > 1:
                print(
                    f"    {Fore.RED}[TELNET DATA]{Style.RESET_ALL} "
                    f"{src}->{dst}: {Fore.YELLOW}{data[:100]}{Style.RESET_ALL}"
                )
        except Exception:
            pass
