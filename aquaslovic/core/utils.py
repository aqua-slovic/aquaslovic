"""
AquaSlovic Utility Functions
Cross-platform helpers for network operations.
"""

import os
import sys
import platform
import socket
import struct
import subprocess
from colorama import Fore, Style, init

init(autoreset=True)

BANNER = rf"""
{Fore.CYAN}
    /   |   ____    __  __     /   |            _____    __       ____   _    __     ____    ______
   / /| |  / __ \  / / / /    / /| |           / ___/   / /      / __ \ | |  / /    /  _/   / ____/
  / ___ | / /_/ / / /_/ /    / ___ |           \__ \   / /      / /_/ / | | / /     / /    / /     
 /_/  |_| \___\_\ \____/    /_/  |_|  ______  ___/ /  / /___    \____/  | |/ /    _/ /    / /___   
                                     /_____/ /____/   /____/            |___/    /___/    \____/   
{Style.RESET_ALL}
{Fore.WHITE}  AquaSlovic v1.0.0 - Network Security Toolkit{Style.RESET_ALL}
{Fore.YELLOW}  For authorized security testing{Style.RESET_ALL}
{Fore.CYAN}  for more visit github = https://github.com/aqua-slovic{Style.RESET_ALL}
{Fore.CYAN}  telegram = https://t.me/aqua_slovic{Style.RESET_ALL}
{Fore.CYAN}  portfolio = https://wisdom-malata.vercel.app{Style.RESET_ALL}
"""


def print_banner():
    """Print the AquaSlovic banner."""
    print(BANNER)


def print_info(msg):
    print(f"{Fore.CYAN}[*]{Style.RESET_ALL} {msg}")


def print_success(msg):
    print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {msg}")


def print_error(msg):
    print(f"{Fore.RED}[-]{Style.RESET_ALL} {msg}")


def print_warning(msg):
    print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")


def print_table(headers, rows):
    """Print a formatted table."""
    if not rows:
        print_warning("No results to display.")
        return

    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            col_widths[i] = max(col_widths[i], len(str(cell)))

    header_line = "  ".join(
        f"{Fore.CYAN}{h:<{col_widths[i]}}{Style.RESET_ALL}"
        for i, h in enumerate(headers)
    )
    separator = "  ".join("-" * w for w in col_widths)

    print(f"\n  {header_line}")
    print(f"  {separator}")
    for row in rows:
        line = "  ".join(f"{str(c):<{col_widths[i]}}" for i, c in enumerate(row))
        print(f"  {line}")
    print()


# -- Platform Detection ------------------------------------------------------

def is_windows():
    return platform.system().lower() == "windows"


def is_linux():
    return platform.system().lower() == "linux"


def is_root():
    """Check if running with admin/root privileges."""
    if is_windows():
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    else:
        return os.geteuid() == 0


def require_root():
    """Exit if not running as root/admin."""
    if not is_root():
        print_error("This module requires root/administrator privileges.")
        if is_windows():
            print_info("Right-click Command Prompt -> 'Run as administrator'")
        else:
            print_info("Run with: sudo python slovic.py")
        return False
    return True


# -- Network Utilities -------------------------------------------------------

def get_default_interface():
    """Get the default network interface name."""
    if is_windows():
        return None  # Windows uses scapy's conf.iface

    try:
        import netifaces
        gateways = netifaces.gateways()
        default = gateways.get("default", {})
        if netifaces.AF_INET in default:
            return default[netifaces.AF_INET][1]
    except Exception:
        pass

    return "eth0"


def get_local_ip():
    """Get the local IP address of this machine."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def get_gateway_ip():
    """Get the default gateway IP."""
    try:
        import netifaces
        gateways = netifaces.gateways()
        default = gateways.get("default", {})
        if netifaces.AF_INET in default:
            return default[netifaces.AF_INET][0]
    except Exception:
        pass

    # Fallback: parse route table
    try:
        if is_windows():
            output = subprocess.check_output("ipconfig", shell=True).decode(errors="ignore")
            for line in output.splitlines():
                if "Default Gateway" in line:
                    parts = line.split(":")
                    if len(parts) > 1:
                        gw = parts[1].strip()
                        if gw:
                            return gw
        else:
            output = subprocess.check_output("ip route show default", shell=True).decode(errors="ignore")
            parts = output.split()
            if "via" in parts:
                return parts[parts.index("via") + 1]
    except Exception:
        pass

    return None


def get_connected_subnets():
    """Get the subnets of all active/connected local interfaces (excluding loopback)."""
    import ipaddress
    subnets = []
    
    # 1. Get subnet via get_subnet() (our detected default default interface subnet)
    default_sub = get_subnet()
    if default_sub:
        try:
            subnets.append(ipaddress.IPv4Network(default_sub, strict=False))
        except ValueError:
            pass

    # 2. Query all netifaces to find all IPs and netmasks
    try:
        import netifaces
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs:
                for addr_info in addrs[netifaces.AF_INET]:
                    ip = addr_info.get("addr")
                    netmask = addr_info.get("netmask")
                    if ip and netmask and ip != "127.0.0.1":
                        try:
                            # Convert netmask representation to CIDR prefix length
                            prefix = sum(bin(int(x)).count("1") for x in netmask.split("."))
                            subnets.append(ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False))
                        except ValueError:
                            pass
    except Exception:
        pass

    # Unique subnets
    unique_networks = []
    for sub in subnets:
        if sub not in unique_networks:
            unique_networks.append(sub)
    return unique_networks


def is_subnet_connected(subnet_str):
    """Check if the given subnet target is connected to the host."""
    import ipaddress
    if not subnet_str or subnet_str.lower() == "auto":
        return True  # 'auto' resolves to local subnet, which is connected
        
    try:
        # Standardize subnet string
        if "/" not in subnet_str:
            # Single host IP targeted, check if it fits in any connected subnets or matches host
            target_ip = ipaddress.IPv4Address(subnet_str)
            for net in get_connected_subnets():
                if target_ip in net:
                    return True
            return False
            
        target_net = ipaddress.IPv4Network(subnet_str, strict=False)
        for net in get_connected_subnets():
            # Check overlap or containment
            if target_net.overlaps(net) or target_net == net:
                return True
    except ValueError:
        return False
    return False


def check_internet_connection():
    """Check internet connectivity by attempting to connect or ping a reliable IP address."""
    import time
    try:
        start_time = time.time()
        # Connect to a public DNS server
        socket.setdefaulttimeout(2.0)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("8.8.8.8", 53))
        s.close()
        rtt = int((time.time() - start_time) * 1000)
        return True, rtt
    except Exception:
        return False, None


def get_subnet():
    """Get the local subnet in CIDR notation (e.g., 192.168.1.0/24)."""
    ip = get_local_ip()
    if ip == "127.0.0.1":
        return None

    try:
        import netifaces
        iface = get_default_interface()
        if iface:
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs:
                info = addrs[netifaces.AF_INET][0]
                netmask = info.get("netmask", "255.255.255.0")
                # Convert to CIDR
                cidr = sum(bin(int(x)).count("1") for x in netmask.split("."))
                net_parts = ip.split(".")
                net_parts[3] = "0"
                return f"{'.'.join(net_parts)}/{cidr}"
    except Exception:
        pass

    # Fallback: assume /24
    parts = ip.split(".")
    parts[3] = "0"
    return f"{'.'.join(parts)}/24"


def get_mac(ip_addr, iface=None):
    """Get MAC address for a given IP using ARP."""
    try:
        from scapy.all import ARP, Ether, srp, conf
        send_iface = iface or conf.iface
        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_addr),
            timeout=3, verbose=False, iface=send_iface
        )
        if ans:
            return ans[0][1].hwsrc
    except Exception:
        pass
    return None


def get_own_mac(iface=None):
    """Get this machine's MAC address."""
    try:
        from scapy.all import get_if_hwaddr, conf
        return get_if_hwaddr(iface or conf.iface)
    except Exception:
        pass

    try:
        import netifaces
        iface = iface or get_default_interface()
        if iface:
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_LINK in addrs:
                return addrs[netifaces.AF_LINK][0].get("addr", "??:??:??:??:??:??")
    except Exception:
        pass
    return "??:??:??:??:??:??"


def _resolve_dns(ip_addr):
    """Try standard DNS reverse lookup."""
    try:
        hostname = socket.gethostbyaddr(ip_addr)[0]
        if hostname and hostname != ip_addr:
            return hostname
    except (socket.herror, socket.gaierror, OSError):
        pass
    return None


def _resolve_netbios(ip_addr):
    """Try NetBIOS name resolution (gets Windows PC names, some phones)."""
    try:
        if is_windows():
            output = subprocess.check_output(
                ["nbtstat", "-A", ip_addr],
                timeout=4, stderr=subprocess.DEVNULL
            ).decode(errors="ignore")
            for line in output.splitlines():
                line = line.strip()
                if "<00>" in line and "UNIQUE" in line.upper():
                    name = line.split("<00>")[0].strip()
                    if name and not name.startswith("__"):
                        return name
        else:
            output = subprocess.check_output(
                ["nmblookup", "-A", ip_addr],
                timeout=4, stderr=subprocess.DEVNULL
            ).decode(errors="ignore")
            for line in output.splitlines():
                line = line.strip()
                if "<00>" in line and "UNIQUE" in line.upper():
                    name = line.split("<00>")[0].strip()
                    if name and not name.startswith("__"):
                        return name
    except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.CalledProcessError, Exception):
        pass
    return None


def _resolve_mdns(ip_addr):
    """Try mDNS / DNS-SD for Apple and Android devices."""
    try:
        if is_windows():
            output = subprocess.check_output(
                ["ping", "-a", "-n", "1", "-w", "1000", ip_addr],
                timeout=4, stderr=subprocess.DEVNULL
            ).decode(errors="ignore")
            # Search for a line containing the IP in brackets, e.g. "[192.168.1.5]"
            # This makes the hostname extraction independent of Windows system language.
            for line in output.splitlines():
                if f"[{ip_addr}]" in line:
                    before_bracket = line.split(f"[{ip_addr}]")[0].strip()
                    # Grab the last token on the left side of the bracket
                    parts = before_bracket.split()
                    if parts:
                        name = parts[-1]
                        # Discard generic localizable verbs/prepositions (e.g. "Pinging", "haciendo")
                        if name.lower() not in ["pinging", "ping", "a", "für", "pour", "haciendo", "envoi", "requête", "sur"]:
                            return name
        else:
            output = subprocess.check_output(
                ["avahi-resolve", "-a", ip_addr],
                timeout=4, stderr=subprocess.DEVNULL
            ).decode(errors="ignore").strip()
            if output:
                parts = output.split()
                if len(parts) >= 2:
                    name = parts[-1].rstrip(".")
                    if name and name != ip_addr:
                        return name
    except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.CalledProcessError, Exception):
        pass
    return None


def resolve_hostname(ip_addr):
    """
    Resolve IP to device name using multiple methods:
    1. DNS reverse lookup
    2. NetBIOS name (nbtstat / nmblookup)
    3. mDNS / ping -a fallback
    Returns the device name (e.g. phone name, PC name) or 'Unknown'.
    """
    # Method 1: DNS reverse lookup
    name = _resolve_dns(ip_addr)
    if name:
        return name

    # Method 2: NetBIOS
    name = _resolve_netbios(ip_addr)
    if name:
        return name

    # Method 3: mDNS / ping -a
    name = _resolve_mdns(ip_addr)
    if name:
        return name

    return "Unknown"


def enable_ip_forwarding():
    """Enable IP forwarding on the system."""
    try:
        if is_linux():
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("1")
            print_success("IP forwarding enabled (Linux)")
        elif is_windows():
            # Use netsh for immediate effect (no reboot needed)
            result = subprocess.run(
                ["netsh", "interface", "ipv4", "set", "global", "forwarding=enabled"],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                print_success("IP forwarding enabled (Windows)")
            else:
                # Fallback to registry method
                subprocess.run(
                    ["reg", "add",
                     r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
                     "/v", "IPEnableRouter", "/t", "REG_DWORD", "/d", "1", "/f"],
                    capture_output=True
                )
                print_success("IP forwarding enabled via registry (Windows -- may need restart)")
    except Exception as e:
        print_error(f"Failed to enable IP forwarding: {e}")


def disable_ip_forwarding():
    """Disable IP forwarding on the system."""
    try:
        if is_linux():
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("0")
            print_info("IP forwarding disabled (Linux)")
        elif is_windows():
            result = subprocess.run(
                ["netsh", "interface", "ipv4", "set", "global", "forwarding=disabled"],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                print_info("IP forwarding disabled (Windows)")
            else:
                subprocess.run(
                    ["reg", "add",
                     r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
                     "/v", "IPEnableRouter", "/t", "REG_DWORD", "/d", "0", "/f"],
                    capture_output=True
                )
                print_info("IP forwarding disabled via registry (Windows)")
    except Exception as e:
        print_error(f"Failed to disable IP forwarding: {e}")


# -- OUI Vendor Lookup -------------------------------------------------------

# Small built-in OUI table for common vendors
OUI_TABLE = {
    "00:50:56": "VMware",
    "00:0c:29": "VMware",
    "08:00:27": "VirtualBox",
    "52:54:00": "QEMU/KVM",
    "b8:27:eb": "Raspberry Pi",
    "dc:a6:32": "Raspberry Pi",
    "e4:5f:01": "Raspberry Pi",
    "00:1a:2b": "Cisco",
    "00:1b:44": "Cisco",
    "00:25:9c": "Cisco",
    "ac:de:48": "Apple",
    "3c:22:fb": "Apple",
    "a4:83:e7": "Apple",
    "f0:18:98": "Apple",
    "38:f9:d3": "Apple",
    "00:23:12": "Apple",
    "60:fb:42": "Apple",
    "48:d7:05": "Apple",
    "14:7d:da": "Apple",
    "b0:be:76": "Samsung",
    "a8:9f:ba": "Samsung",
    "c0:ee:fb": "Samsung",
    "fc:a1:3e": "Samsung",
    "a0:99:9b": "D-Link",
    "90:94:e4": "D-Link",
    "1c:7e:e5": "D-Link",
    "e8:48:b8": "TP-Link",
    "50:c7:bf": "TP-Link",
    "c0:25:e9": "TP-Link",
    "30:b5:c2": "TP-Link",
    "c4:e9:84": "TP-Link",
    "b4:75:0e": "Belkin",
    "ec:1a:59": "Belkin",
    "e0:63:da": "Huawei",
    "70:8b:cd": "Huawei",
    "48:46:fb": "Huawei",
    "34:97:f6": "ASUSTek",
    "00:1e:8c": "ASUSTek",
    "74:d0:2b": "ASUSTek",
    "00:14:bf": "Linksys",
    "c0:56:27": "Belkin/Linksys",
    "a4:f1:e8": "Motorola",
    "28:6a:ba": "Intel",
    "3c:97:0e": "Intel",
    "f8:63:3f": "Intel",
    "8c:16:45": "Intel",
    "a4:c3:f0": "Intel",
    "f4:8c:50": "Intel",
    "7c:67:a2": "Intel",
    "60:67:20": "Intel",
    "18:56:80": "Intel",
    "80:86:f2": "Intel",
    "9c:b6:d0": "Realtek",
    "00:e0:4c": "Realtek",
    "50:3e:aa": "Microsoft",
    "00:26:b9": "Dell",
    "f8:db:88": "Dell",
    "b0:83:fe": "Dell",
    "28:d2:44": "Lenovo",
    "98:fa:9b": "Lenovo",
    "50:7b:9d": "Lenovo",
    "e8:6a:64": "Lenovo",
    "c8:d9:d2": "HP",
    "d4:c9:ef": "HP",
    "00:21:5a": "HP",
}


def lookup_vendor_api(mac):
    """Lookup vendor from MAC address using the macvendors.com API.

    Free tier allows ~1 request/second. Results are cached in-memory.
    Returns vendor name string or None if lookup fails.
    """
    if not mac or mac in ("??:??:??:??:??:??", "N/A"):
        return None

    # Normalize MAC format (API accepts colon, dash, or dot separated)
    normalized = mac.strip().upper()

    # Check in-memory cache first
    if normalized in _vendor_cache:
        return _vendor_cache[normalized]

    # Also cache by OUI prefix (first 3 octets)
    prefix = normalized[:8]
    if prefix in _vendor_cache:
        return _vendor_cache[prefix]

    try:
        import urllib.request
        import urllib.error
        import time

        # Rate limiting: wait if needed (1 req/sec for free tier)
        now = time.time()
        elapsed = now - _vendor_api_state.get("last_request", 0)
        if elapsed < 1.0:
            time.sleep(1.0 - elapsed)

        url = f"https://api.macvendors.com/{normalized}"
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "AquaSlovic/1.0")

        with urllib.request.urlopen(req, timeout=3) as response:
            vendor = response.read().decode("utf-8").strip()
            _vendor_api_state["last_request"] = time.time()

            if vendor and "errors" not in vendor.lower():
                # Cache by full MAC and by OUI prefix
                _vendor_cache[normalized] = vendor
                _vendor_cache[prefix] = vendor
                return vendor

    except (urllib.error.HTTPError, urllib.error.URLError):
        pass
    except Exception:
        pass

    _vendor_api_state["last_request"] = time.time()
    return None


# In-memory cache for vendor lookups (prefix -> vendor name)
_vendor_cache = {}
# Rate limiting state
_vendor_api_state = {"last_request": 0}


def lookup_vendor(mac):
    """Lookup vendor from MAC address.

    Strategy:
      1. Try the macvendors.com API (most accurate, 250k+ vendors)
      2. Fall back to the built-in OUI table
    """
    if not mac or mac in ("??:??:??:??:??:??", "N/A"):
        return "Unknown"

    # Try API first
    api_result = lookup_vendor_api(mac)
    if api_result:
        return api_result

    # Fallback to local OUI table
    prefix = mac[:8].lower()
    return OUI_TABLE.get(prefix, "Unknown")

