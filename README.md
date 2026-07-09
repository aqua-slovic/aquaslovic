# AQUA_SLOVIC — Cross-Platform Network Security Toolkit

> A powerful network security toolkit inspired by bettercap, focusing on auditing and device discovery. Works on both **Linux** and **Windows**.

**DISCLAIMER**: This tool is for **authorized security testing and network administration only**. Unauthorized use against networks you do not own or have permission to test is **illegal**. You are responsible for your own actions.

---

##  Table of Contents

- [Features](#-features)
- [Installation](#-installation)
  - [Linux](#linux)
  - [Windows](#windows)
- [Quick Start](#-quick-start)
- [Commands Reference](#-commands-reference)
  - [General Commands](#general-commands)
  - [Network Scanner](#-network-scanner-netscan)
  - [Active Internet Detection](#-active-internet-detection-netinternet)
  - [Packet Sniffer](#-packet-sniffer-netsniff)
  - [ARP Spoofer](#-arp-spoofer-arpspoof)
  - [DNS Spoofer](#-dns-spoofer-dnsspoof)
  - [HTTP Proxy](#-http-proxy-httpproxy)
- [Session Variables](#-session-variables)
- [Examples](#-full-examples)
- [Troubleshooting](#-troubleshooting)
- [Project Structure](#-project-structure)

---

## ✨ Features

| Feature | Description | Root/Admin? |
|---|---|---|
| **Network Scanner** | Discover all devices on your network (IP, MAC, hostname, vendor) | ARP scan: Yes · Ping sweep: No |
| **Active Internet Detection** | Show internet availability, latency, and connected host counts | No |
| **Packet Sniffer** | Capture & analyze packets, detect credentials in cleartext protocols | Yes |
| **ARP Spoofer** | Man-in-the-Middle via ARP cache poisoning (bidirectional) | Yes |
| **DNS Spoofer** | Intercept DNS queries and inject forged responses | Yes |
| **HTTP Proxy** | Inspect HTTP traffic, inject JavaScript into pages | No |

---

##  Installation

### Linux

```bash
# 1. Install Python 3 and pip (if not already installed)
sudo apt update
sudo apt install python3 python3-pip -y

# 2. Clone or navigate to the AQUA_SLOVIC directory
cd /path/to/slovic

# 3. Install dependencies
pip3 install -r requirements.txt

# 4. (Optional) Install as a package
pip3 install -e .

# 5. Launch AQUA_SLOVIC (use sudo for full features)
sudo python3 main.py
```

### Windows

```powershell
# 1. Make sure Python 3 is installed (https://python.org)
#    Check with:
#    python --version

# 2. Install Npcap (REQUIRED for packet capture)
#    Download from: https://npcap.com/#download
#    During install, check "Install in WinPcap API-compatible mode"

# 3. Navigate to the AQUA_SLOVIC directory
cd C:\path\to\slovic

# 4. Install dependencies
pip install -r requirements.txt

# 5. Launch AQUA_SLOVIC (run CMD/PowerShell as Administrator for full features)
python main.py
```

> **Windows Users**: Right-click Command Prompt or PowerShell → **"Run as administrator"** to enable all features.

---

## 🚀 Quick Start

```
# Launch the tool
Linux:   sudo python3 main.py
Windows: python main.py        (as Administrator)

# Inside the AQUA_SLOVIC shell:
aqua_slovic » net.internet                          # Get internet connectivity & local client stats
aqua_slovic » net.scan                              # Discover all devices on the network you are connected to
aqua_slovic » help                                  # See all commands
aqua_slovic » exit                                  # Quit
```

---

##  Commands Reference

### General Commands

| Command | Description |
|---|---|
| `help` | Show all available commands |
| `help <module>` | Show detailed help for a module (e.g., `help net.scan`) |
| `set <var> <value>` | Set a session variable |
| `get <var>` | Get a session variable's value |
| `env` | Show all session variables |
| `clear` | Clear the screen |
| `exit` / `quit` / `q` | Exit AQUA_SLOVIC (cleans up all running modules) |

---

### Network Scanner (`net.scan`)

Discover all devices connected to your local network.

#### Network Scanner Commands

| Command | Description |
|---|---|
| `net.scan` | ARP scan (fast & accurate, requires root/admin) |
| `net.scan ping` | Ping sweep (no root needed, but slower) |
| `net.scan 192.168.1.0/24` | Scan a specific subnet |

#### Linux Examples

```bash
# Full ARP scan (requires sudo)
sudo python3 main.py
aqua_slovic » net.scan

# Ping sweep (no sudo needed)
python3 main.py
aqua_slovic » net.scan ping

# Scan specific subnet
aqua_slovic » net.scan 10.0.0.0/24
```

#### Windows Examples

```powershell
# Run CMD as Administrator, then:
python main.py
aqua_slovic » net.scan

# Without admin (ping sweep only)
python main.py
aqua_slovic » net.scan ping
```

#### Output Example

```text
[+] Found 5 device(s):

  IP Address       MAC Address         Hostname           Vendor
  ───────────────  ──────────────────  ─────────────────  ────────
  192.168.1.1      aa:bb:cc:dd:ee:ff   router.local       TP-Link    (gateway)
  192.168.1.10     11:22:33:44:55:66   johns-laptop       Intel      (you)
  192.168.1.15     de:ad:be:ef:00:01   marys-phone        Samsung
  192.168.1.20     ab:cd:ef:12:34:56   living-room-tv     Apple
  192.168.1.25     fe:dc:ba:98:76:54   office-printer     HP
```

---

### Active Internet Detection (`net.internet`)

Test active internet availability and gauge the client density on your local intranet.

Search can only happen on networks you are currently connected to.

#### Active Internet Detection Commands

| Command        | Description                                                            |
|----------------|------------------------------------------------------------------------|
| `net.internet` | Verify internet reachability and count active local network clients. |

#### Usage Examples

```bash
# Execute active internet checklist & intranet counting
aqua_slovic » net.internet
```

#### Network Status Output Example

```text
[*] Conducting internet connectivity tests...
[+] Internet Status  : ONLINE (Ping RTT: 28ms)
[*] Scanning 192.168.1.0/24 to count online network devices...
[+] Found 4 device(s):

  IP Address       MAC Address         Hostname           Vendor
  ───────────────  ──────────────────  ─────────────────  ────────
  192.168.1.1      aa:bb:cc:dd:ee:ff   router.local       TP-Link    (gateway)
  192.168.1.10     11:22:33:44:55:66   johns-laptop       Intel      (you)
  192.168.1.15     de:ad:be:ef:00:01   marys-phone        Samsung
  192.168.1.20     ab:cd:ef:12:34:56   living-room-tv     Apple

[+] Intranet Status  : 4 active device(s) found on 192.168.1.0/24
```

---

### Packet Sniffer (`net.sniff`)

Capture network packets in real-time with protocol analysis and credential detection.

> **Requires**: root (Linux) or Administrator (Windows)

#### Packet Sniffer Commands

| Command | Description |
|---|---|
| `net.sniff on` | Start capturing all traffic |
| `net.sniff on <bpf_filter>` | Start with a BPF filter |
| `net.sniff off` | Stop capturing |

#### Common BPF Filters

| Filter | What it captures |
|---|---|
| `tcp port 80` | HTTP traffic |
| `tcp port 443` | HTTPS traffic |
| `udp port 53` | DNS queries/responses |
| `tcp port 21` | FTP traffic |
| `host 192.168.1.50` | All traffic to/from a specific host |
| `tcp port 80 or tcp port 443` | All web traffic |
| `not port 22` | Everything except SSH |

#### Linux Examples

```bash
sudo python3 main.py

# Capture all traffic
aqua_slovic » net.sniff on

# Capture only HTTP
aqua_slovic » net.sniff on tcp port 80

# Capture DNS queries
aqua_slovic » net.sniff on udp port 53

# Monitor a specific host
aqua_slovic » net.sniff on host 192.168.1.50

# Stop
aqua_slovic » net.sniff off
```

#### Windows Examples

```powershell
# Run as Administrator
python main.py

aqua_slovic » net.sniff on
aqua_slovic » net.sniff on tcp port 80
aqua_slovic » net.sniff off
```

---

### ☠️ ARP Spoofer (`arp.spoof`)

Perform ARP cache poisoning to position yourself as a Man-in-the-Middle between a target and the gateway.

> **Requires**: root (Linux) or Administrator (Windows)
>  **Only use on networks you own or have explicit permission to test!**

#### ARP Spoofer Commands

| Command | Description |
|---|---|
| `arp.spoof on <target_ip>` | Start spoofing (gateway auto-detected) |
| `arp.spoof off` | Stop spoofing and restore ARP tables |

#### What it does

1. Tells the **target**: "I am the gateway" (sends forged ARP replies)
2. Tells the **gateway**: "I am the target" (full-duplex / bidirectional)
3. Enables **IP forwarding** so traffic flows through your machine
4. On stop: **restores** the original ARP tables

#### Linux Examples

```bash
sudo python3 main.py

# Spoof a target (gateway auto-detected)
aqua_slovic » arp.spoof on 192.168.1.50

# Specify a custom gateway
aqua_slovic » set arp.gateway 192.168.1.254
aqua_slovic » arp.spoof on 192.168.1.50

# Stop and restore
aqua_slovic » arp.spoof off
```

#### Windows Examples

```powershell
# Run as Administrator
python main.py

aqua_slovic » arp.spoof on 192.168.1.50
aqua_slovic » arp.spoof off
```

---

###  DNS Spoofer (`dns.spoof`)

Intercept DNS queries and redirect domains to your chosen IP addresses.

> **Requires**: root (Linux) or Administrator (Windows)
> **Best used with**: ARP spoofing active to intercept the target's DNS traffic

#### DNS Spoofer Commands

| Command | Description |
|---|---|
| `dns.spoof add <domain> <ip>` | Add a spoofing rule |
| `dns.spoof add *.example.com <ip>` | Add a wildcard rule |
| `dns.spoof remove <domain>` | Remove a rule |
| `dns.spoof all <ip>` | Redirect ALL DNS queries to one IP |
| `dns.spoof list` | Show current rules |
| `dns.spoof on` | Start the DNS spoofer |
| `dns.spoof off` | Stop the DNS spoofer |

#### Linux Examples

```bash
sudo python3 main.py

# Redirect a specific domain
aqua_slovic » dns.spoof add example.com 192.168.1.10
aqua_slovic » dns.spoof on

# Redirect all subdomains of a domain
aqua_slovic » dns.spoof add *.google.com 192.168.1.10
aqua_slovic » dns.spoof on

# Redirect ALL DNS queries (captive portal style)
aqua_slovic » dns.spoof all 192.168.1.10
aqua_slovic » dns.spoof on

# Check rules and stop
aqua_slovic » dns.spoof list
aqua_slovic » dns.spoof off
```

#### Windows Examples

```powershell
# Run as Administrator
python main.py

aqua_slovic » dns.spoof add example.com 10.0.0.5
aqua_slovic » dns.spoof on
aqua_slovic » dns.spoof off
```

#### Typical MITM Workflow (DNS + ARP)

```
aqua_slovic » arp.spoof on 192.168.1.50              # MITM the target
aqua_slovic » dns.spoof add login.example.com 192.168.1.10  # Redirect their login
aqua_slovic » dns.spoof on
# ... wait for target to visit login.example.com ...
aqua_slovic » dns.spoof off
aqua_slovic » arp.spoof off
```

---

###  HTTP Proxy (`http.proxy`)

A transparent HTTP proxy for inspecting and modifying web traffic.

#### HTTP Proxy Commands

| Command | Description |
|---|---|
| `http.proxy on [port]` | Start proxy (default port: 8080) |
| `http.proxy off` | Stop proxy |
| `http.proxy inject <javascript>` | Inject JS into every HTML page |
| `http.proxy inject off` | Remove JS injection |

#### Linux Examples

```bash
python3 main.py

# Start on default port
aqua_slovic » http.proxy on

# Start on custom port
aqua_slovic » http.proxy on 9090

# Inject an alert into every page
aqua_slovic » http.proxy inject alert('Injected by AQUA_SLOVIC')

# Stop
aqua_slovic » http.proxy off
```

#### Windows Examples

```powershell
python main.py

aqua_slovic » http.proxy on 8080
aqua_slovic » http.proxy inject alert('Hello from AQUA_SLOVIC')
aqua_slovic » http.proxy inject off
aqua_slovic » http.proxy off
```

> **Usage**: Configure the target browser's proxy settings to `http://<your-ip>:8080` to route traffic through AQUA_SLOVIC.

---

##  Session Variables

Use `set` and `get` to configure behavior. Use `env` to see all variables.

| Variable | Default | Description |
|---|---|---|
| `net.interface` | auto-detected | Network interface to use |
| `net.subnet` | auto-detected | Subnet to scan (CIDR format) |
| `arp.target` | *(empty)* | Pre-set ARP spoof target IP |
| `arp.gateway` | auto-detected | Gateway IP for ARP spoofing |
| `http.proxy.port` | `8080` | HTTP proxy port |

```
aqua_slovic » set net.subnet 192.168.1.0/24
aqua_slovic » get net.interface
aqua_slovic » env
```

---

##  Full Examples

### Example 1: View Active Internet and Scan Connected Network

```bash
# Linux
sudo python3 main.py

aqua_slovic » net.internet                             # Check active connection and device count
aqua_slovic » net.scan                                 # Scan the connected subnet
```

### Example 2: Full MITM Attack (Authorized Testing)

```bash
# Linux (requires sudo)
sudo python3 main.py

aqua_slovic » net.scan                                # Step 1: Find devices
aqua_slovic » arp.spoof on 192.168.1.50               # Step 2: MITM target
aqua_slovic » net.sniff on tcp port 80                 # Step 3: Sniff HTTP
# ... observe traffic ...
aqua_slovic » net.sniff off                            # Step 4: Stop sniffing
aqua_slovic » arp.spoof off                            # Step 5: Restore ARP
```

### Example 3: DNS Redirection (Authorized Testing)

```bash
# Linux (requires sudo)
sudo python3 main.py

aqua_slovic » arp.spoof on 192.168.1.50               # MITM the target
aqua_slovic » dns.spoof add evil-site.com 192.168.1.10 # Redirect domain
aqua_slovic » dns.spoof on                             # Start DNS spoofing
# ... target visits evil-site.com and goes to 192.168.1.10 ...
aqua_slovic » dns.spoof off
aqua_slovic » arp.spoof off
```

### Example 4: HTTP Proxy with JS Injection

```bash
python3 main.py

aqua_slovic » http.proxy on 8080
aqua_slovic » http.proxy inject document.title='Hacked by AQUA_SLOVIC'
# Configure target browser proxy → your-ip:8080
# Every page they visit will have modified title
aqua_slovic » http.proxy inject off
aqua_slovic » http.proxy off
```

---

## 🔧 Troubleshooting

### "Permission denied" / "Requires root"

| OS | Solution |
|---|---|
| Linux | Run with `sudo`: `sudo python3 main.py` |
| Windows | Right-click CMD/PowerShell → **"Run as administrator"** |

### "Scapy not available" / Import errors

```bash
# Linux
pip3 install scapy colorama netifaces tqdm

# Windows
pip install scapy colorama netifaces tqdm
```

### Windows: "No module named 'scapy'" or packet capture fails

1. Install **Npcap**: https://npcap.com/#download
2. During install, check **"Install Npcap in WinPcap API-compatible Mode"**
3. Restart your terminal

### "Address already in use" (port conflict)

```
aqua_slovic » http.proxy on 9090         # Use a different port
```

### ARP scan returns no results

- Make sure you're on the same network/subnet as the target devices (Scans are restricted to connected networks)
- Try `net.scan ping` as a fallback (no root needed)
- Check your firewall isn't blocking ARP

---

##  Project Structure

```
slovic/
├── main.py                        # Entry point
├── setup.py                       # Package installer
├── requirements.txt               # Python dependencies
├── README.md                      # This file
└── aquaslovic/
    ├── __init__.py
    ├── cli.py                     # Interactive shell
    └── core/
        ├── __init__.py
        ├── utils.py               # Cross-platform utilities
        ├── scanner.py             # Network device discovery
        ├── sniffer.py             # Packet capture & analysis
        ├── arpspoof.py            # ARP cache poisoning
        ├── dnsspoof.py            # DNS query spoofing
        └── httpproxy.py           # HTTP proxy & injection
```

---

## License

This project is provided as-is for educational and authorized security testing purposes.

**Use responsibly. You are solely responsible for your actions.**

---

*program was built by AQUA_SLOVIC*
