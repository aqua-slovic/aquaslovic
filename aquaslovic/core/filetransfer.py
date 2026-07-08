"""
AQUA_SLOVIC — File Transfer Module
Send and receive any file to/from devices on the same network.
Uses TCP sockets with UDP broadcast for peer discovery.
"""

import os
import sys
import json
import socket
import struct
import hashlib
import threading
import time

from colorama import Fore, Style

from aquaslovic.core.utils import (
    print_info, print_success, print_error, print_warning,
    print_table, get_local_ip, get_subnet,
)

# Constants
TRANSFER_PORT = 9876        # Default TCP port for file transfer
DISCOVERY_PORT = 9877       # UDP broadcast port for peer discovery
CHUNK_SIZE = 65536          # 64 KB chunks
MAGIC_HEADER = b"AQUASLOVIC"
DISCOVERY_MSG = b"AQUASLOVIC_DISCOVER"
DISCOVERY_RESP = b"AQUASLOVIC_HERE"


class FileTransfer:
    """
    Peer-to-peer file transfer over the local network.

    Features:
        - Send any file to any IP on the same network
        - Auto-discover peers running AQUA_SLOVIC
        - Progress display with transfer speed
        - SHA-256 checksum verification
        - Works on both Linux and Windows
    """

    def __init__(self):
        self.receive_running = False
        self.receive_thread = None
        self.discovery_thread = None
        self.server_socket = None
        self.port = TRANSFER_PORT
        self.save_dir = os.path.expanduser("~/AQUA_SLOVIC_Received")
        self.peers = {}  # ip → hostname

    # ── Receiver ────────────────────────────────────────────────────────

    def start_receiver(self, port=None, save_dir=None):
        """Start the file receive server."""
        if self.receive_running:
            print_warning("File receiver is already running.")
            return

        self.port = port or TRANSFER_PORT
        self.save_dir = save_dir or self.save_dir

        # Create save directory
        os.makedirs(self.save_dir, exist_ok=True)

        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(("0.0.0.0", self.port))
            self.server_socket.listen(5)
            self.server_socket.settimeout(1.0)

            self.receive_running = True

            # Start receiver thread
            self.receive_thread = threading.Thread(
                target=self._receive_loop, daemon=True
            )
            self.receive_thread.start()

            # Start discovery responder
            self.discovery_thread = threading.Thread(
                target=self._discovery_responder, daemon=True
            )
            self.discovery_thread.start()

            local_ip = get_local_ip()
            print_success(f"File receiver started on {Fore.WHITE}{local_ip}:{self.port}{Style.RESET_ALL}")
            print_info(f"Files will be saved to: {Fore.WHITE}{self.save_dir}{Style.RESET_ALL}")
            print_info("Other AQUA_SLOVIC users can now send files to you.")
            print_info("Use 'file.receive off' to stop.")

        except OSError as e:
            print_error(f"Failed to start receiver: {e}")
            if "Address already in use" in str(e) or "10048" in str(e):
                print_info(f"Port {self.port} is in use. Try: file.receive on <port>")

    def stop_receiver(self):
        """Stop the file receive server."""
        if not self.receive_running:
            print_warning("File receiver is not running.")
            return

        self.receive_running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass
        print_info("File receiver stopped.")

    def _receive_loop(self):
        """Accept incoming file transfers."""
        while self.receive_running:
            try:
                conn, addr = self.server_socket.accept()
                # Handle each transfer in a separate thread
                handler = threading.Thread(
                    target=self._handle_incoming, args=(conn, addr), daemon=True
                )
                handler.start()
            except socket.timeout:
                continue
            except OSError:
                break
            except Exception as e:
                if self.receive_running:
                    print_error(f"Receiver error: {e}")

    def _handle_incoming(self, conn, addr):
        """Handle an incoming file transfer."""
        try:
            # Read magic header
            magic = conn.recv(len(MAGIC_HEADER))
            if magic != MAGIC_HEADER:
                conn.close()
                return

            # Read metadata length (4 bytes)
            meta_len_data = conn.recv(4)
            if len(meta_len_data) < 4:
                conn.close()
                return
            meta_len = struct.unpack("!I", meta_len_data)[0]

            # Read metadata JSON
            meta_data = b""
            while len(meta_data) < meta_len:
                chunk = conn.recv(min(CHUNK_SIZE, meta_len - len(meta_data)))
                if not chunk:
                    break
                meta_data += chunk

            metadata = json.loads(meta_data.decode("utf-8"))
            filename = os.path.basename(metadata["filename"])  # Security: basename only
            filesize = metadata["filesize"]
            checksum = metadata["checksum"]
            sender = metadata.get("sender", addr[0])

            print(f"\n  {Fore.CYAN}INCOMING FILE:{Style.RESET_ALL}")
            print(f"  From     : {Fore.WHITE}{sender} ({addr[0]}){Style.RESET_ALL}")
            print(f"  Filename : {Fore.WHITE}{filename}{Style.RESET_ALL}")
            print(f"  Size     : {Fore.WHITE}{self._format_size(filesize)}{Style.RESET_ALL}")

            # Send acceptance
            conn.send(b"ACCEPT")

            # Receive file data
            save_path = os.path.join(self.save_dir, filename)

            # Handle name collisions
            if os.path.exists(save_path):
                base, ext = os.path.splitext(filename)
                counter = 1
                while os.path.exists(save_path):
                    save_path = os.path.join(self.save_dir, f"{base}_{counter}{ext}")
                    counter += 1

            received = 0
            sha256 = hashlib.sha256()
            start_time = time.time()

            with open(save_path, "wb") as f:
                while received < filesize:
                    remaining = filesize - received
                    chunk = conn.recv(min(CHUNK_SIZE, remaining))
                    if not chunk:
                        break
                    f.write(chunk)
                    sha256.update(chunk)
                    received += len(chunk)

                    # Progress
                    pct = (received / filesize) * 100
                    speed = received / max(time.time() - start_time, 0.001)
                    bar = self._progress_bar(pct)
                    sys.stdout.write(
                        f"\r  {bar} {pct:.1f}%  "
                        f"{self._format_size(received)}/{self._format_size(filesize)}  "
                        f"({self._format_size(speed)}/s)  "
                    )
                    sys.stdout.flush()

            print()  # Newline after progress bar

            # Verify checksum
            if sha256.hexdigest() == checksum:
                conn.send(b"OK")
                elapsed = time.time() - start_time
                print_success(
                    f"File saved: {Fore.WHITE}{save_path}{Style.RESET_ALL} "
                    f"({self._format_size(filesize)} in {elapsed:.1f}s) checksum verified"
                )
            else:
                conn.send(b"CHECKSUM_FAIL")
                print_error(f"Checksum mismatch! File may be corrupted: {save_path}")

        except Exception as e:
            print_error(f"Error receiving file from {addr[0]}: {e}")
        finally:
            conn.close()

    def _discovery_responder(self):
        """Respond to UDP discovery broadcasts."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("0.0.0.0", DISCOVERY_PORT))
            sock.settimeout(1.0)

            hostname = socket.gethostname()

            while self.receive_running:
                try:
                    data, addr = sock.recvfrom(1024)
                    if data == DISCOVERY_MSG:
                        response = json.dumps({
                            "hostname": hostname,
                            "port": self.port,
                        }).encode()
                        sock.sendto(DISCOVERY_RESP + b"|" + response, addr)
                except socket.timeout:
                    continue
                except Exception:
                    continue
        except Exception:
            pass
        finally:
            try:
                sock.close()
            except Exception:
                pass

    # ── Sender ──────────────────────────────────────────────────────────

    def send_file(self, target_ip, filepath, port=None):
        """
        Send a file to a target IP.

        Args:
            target_ip: IP address of the receiver
            filepath: Path to the file to send
            port: Port to connect to (default: TRANSFER_PORT)
        """
        port = port or TRANSFER_PORT

        if not os.path.isfile(filepath):
            print_error(f"File not found: {filepath}")
            return False

        filename = os.path.basename(filepath)
        filesize = os.path.getsize(filepath)

        # Calculate checksum
        print_info(f"Calculating checksum for {Fore.WHITE}{filename}{Style.RESET_ALL}...")
        sha256 = hashlib.sha256()
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                sha256.update(chunk)
        checksum = sha256.hexdigest()

        print_info(f"Connecting to {Fore.WHITE}{target_ip}:{port}{Style.RESET_ALL}...")

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((target_ip, port))

            # Send magic header
            sock.send(MAGIC_HEADER)

            # Send metadata
            metadata = json.dumps({
                "filename": filename,
                "filesize": filesize,
                "checksum": checksum,
                "sender": socket.gethostname(),
            }).encode("utf-8")

            sock.send(struct.pack("!I", len(metadata)))
            sock.send(metadata)

            # Wait for acceptance
            response = sock.recv(10)
            if response != b"ACCEPT":
                print_error("Receiver rejected the transfer.")
                sock.close()
                return False

            print_info(
                f"Sending {Fore.WHITE}{filename}{Style.RESET_ALL} "
                f"({self._format_size(filesize)}) to {target_ip}..."
            )

            # Send file data
            sent = 0
            start_time = time.time()

            with open(filepath, "rb") as f:
                while True:
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    sock.sendall(chunk)
                    sent += len(chunk)

                    # Progress
                    pct = (sent / filesize) * 100
                    speed = sent / max(time.time() - start_time, 0.001)
                    bar = self._progress_bar(pct)
                    sys.stdout.write(
                        f"\r  {bar} {pct:.1f}%  "
                        f"{self._format_size(sent)}/{self._format_size(filesize)}  "
                        f"({self._format_size(speed)}/s)  "
                    )
                    sys.stdout.flush()

            print()

            # Wait for verification
            sock.settimeout(30)
            verify = sock.recv(20)
            elapsed = time.time() - start_time

            if verify == b"OK":
                print_success(
                    f"File sent successfully! "
                    f"({self._format_size(filesize)} in {elapsed:.1f}s) verified"
                )
                return True
            else:
                print_error("Checksum verification failed on receiver side!")
                return False

        except ConnectionRefusedError:
            print_error(
                f"Connection refused by {target_ip}:{port}. "
                f"Make sure the receiver is running (file.receive on)."
            )
            return False
        except socket.timeout:
            print_error(f"Connection to {target_ip}:{port} timed out.")
            return False
        except Exception as e:
            print_error(f"File transfer failed: {e}")
            return False
        finally:
            try:
                sock.close()
            except Exception:
                pass

    # ── Peer Discovery ──────────────────────────────────────────────────

    def discover_peers(self, timeout=3):
        """
        Discover other AQUA_SLOVIC instances on the network via UDP broadcast.
        """
        print_info("Discovering AQUA_SLOVIC peers on the network...")

        self.peers = {}
        local_ip = get_local_ip()

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.settimeout(timeout)

            # Force routing through active interface on Windows/Linux by binding client socket to local IP
            try:
                sock.bind((local_ip, 0))
            except Exception:
                pass

            # Broadcast discovery messages to general broadcast and subnet-specific broadcast to ensure reception
            broadcast_ips = ["<broadcast>", "255.255.255.255"]
            subnet = get_subnet()
            if subnet and "/" in subnet:
                try:
                    ip_part, cidr_part = subnet.split("/")
                    cidr = int(cidr_part)
                    ip_octets = [int(x) for x in ip_part.split(".")]
                    if cidr == 24 and len(ip_octets) == 4:
                        broadcast_ips.append(f"{ip_octets[0]}.{ip_octets[1]}.{ip_octets[2]}.255")
                except Exception:
                    pass

            for bip in broadcast_ips:
                try:
                    sock.sendto(DISCOVERY_MSG, (bip, DISCOVERY_PORT))
                except Exception:
                    pass

            start = time.time()
            while time.time() - start < timeout:
                try:
                    data, addr = sock.recvfrom(1024)
                    if data.startswith(DISCOVERY_RESP):
                        parts = data.split(b"|", 1)
                        if len(parts) > 1:
                            info = json.loads(parts[1].decode())
                            peer_ip = addr[0]
                            self.peers[peer_ip] = info.get("hostname", "Unknown")
                except socket.timeout:
                    break
                except Exception:
                    continue

            sock.close()

        except Exception as e:
            print_error(f"Discovery failed: {e}")

        if self.peers:
            print_success(f"Found {len(self.peers)} AQUA_SLOVIC peer(s):")
            headers = ["IP Address", "Hostname"]
            rows = []
            for ip, hostname in self.peers.items():
                if ip == local_ip:
                    rows.append([ip, f"{hostname} {Fore.GREEN}(you){Style.RESET_ALL}"])
                else:
                    rows.append([ip, hostname])
            print_table(headers, rows)
        else:
            print_warning("No AQUA_SLOVIC peers found on the network.")
            print_info("Make sure the receiver has started: file.receive on")

        return self.peers

    # ── Helpers ─────────────────────────────────────────────────────────

    @staticmethod
    def _format_size(size):
        """Format bytes to human-readable size."""
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} PB"

    @staticmethod
    def _progress_bar(pct, width=30):
        """Generate a progress bar string."""
        filled = int(width * pct / 100)
        bar = f"{Fore.GREEN}{'#' * filled}{Style.RESET_ALL}{'-' * (width - filled)}"
        return f"[{bar}]"
