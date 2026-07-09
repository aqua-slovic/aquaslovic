"""
AQUA_SLOVIC — HTTP Proxy Module
Transparent HTTP proxy for inspecting and modifying web traffic.
"""

import threading
import socket
import select
import re

from colorama import Fore, Style

from aquaslovic.core.utils import (
    print_info, print_success, print_error, print_warning,
    get_local_ip,
)


class HTTPProxy:
    """
    Transparent HTTP proxy for traffic inspection and JavaScript injection.

    Features:
        - Inspect HTTP requests and responses
        - Inject JavaScript into HTML pages
        - Configurable port
        - Works on both Linux and Windows
    """

    def __init__(self):
        self.running = False
        self.proxy_thread = None
        self.server_socket = None
        self.port = 8080
        self.js_inject = ""  # JavaScript to inject into HTML pages

    def start(self, port=8080):
        """
        Start the HTTP proxy.

        Args:
            port: Port to listen on (default: 8080)
        """
        if self.running:
            print_warning("HTTP proxy is already running.")
            return

        self.port = port

        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(("0.0.0.0", self.port))
            self.server_socket.listen(50)
            self.server_socket.settimeout(1.0)

            self.running = True

            self.proxy_thread = threading.Thread(
                target=self._proxy_loop, daemon=True
            )
            self.proxy_thread.start()

            local_ip = get_local_ip()
            print_success(
                f"HTTP proxy started on {Fore.WHITE}{local_ip}:{self.port}{Style.RESET_ALL}"
            )
            print_info(
                f"Configure target browser proxy to: "
                f"{Fore.WHITE}http://{local_ip}:{self.port}{Style.RESET_ALL}"
            )
            if self.js_inject:
                print_info(f"JS injection active: {Fore.YELLOW}{self.js_inject[:50]}...{Style.RESET_ALL}")
            print_info("Use 'http.proxy off' to stop.")

        except OSError as e:
            print_error(f"Failed to start proxy: {e}")
            if "Address already in use" in str(e) or "10048" in str(e):
                print_info(f"Port {self.port} is in use. Try: http.proxy on <port>")

    def stop(self):
        """Stop the HTTP proxy."""
        if not self.running:
            print_warning("HTTP proxy is not running.")
            return

        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass
        print_info("HTTP proxy stopped.")

    def set_js_inject(self, js_code):
        """
        Set JavaScript code to inject into HTML responses.

        Args:
            js_code: JavaScript code to inject
        """
        self.js_inject = js_code
        print_success(
            f"JS injection set: {Fore.YELLOW}{js_code[:80]}{Style.RESET_ALL}"
        )

    def clear_js_inject(self):
        """Clear JavaScript injection."""
        self.js_inject = ""
        print_info("JS injection cleared.")

    def _proxy_loop(self):
        """Accept incoming proxy connections."""
        while self.running:
            try:
                client_sock, addr = self.server_socket.accept()
                handler = threading.Thread(
                    target=self._handle_client,
                    args=(client_sock, addr),
                    daemon=True,
                )
                handler.start()
            except socket.timeout:
                continue
            except OSError:
                break
            except Exception as e:
                if self.running:
                    print_error(f"Proxy error: {e}")

    def _handle_client(self, client_sock, addr):
        """Handle an incoming proxy connection."""
        try:
            client_sock.settimeout(10)
            request = client_sock.recv(8192)

            if not request:
                client_sock.close()
                return

            # Parse the HTTP request
            try:
                request_line = request.split(b"\r\n")[0].decode(errors="ignore")
            except Exception:
                client_sock.close()
                return

            parts = request_line.split()
            if len(parts) < 3:
                client_sock.close()
                return

            method = parts[0]
            url = parts[1]

            # Handle CONNECT method (HTTPS tunneling)
            if method == "CONNECT":
                self._handle_connect(client_sock, url, request)
                return

            # Parse host from URL or Host header
            host, port, path = self._parse_url(url, request)
            if not host:
                client_sock.close()
                return

            # Log the request
            print(
                f"  {Fore.GREEN}[HTTP]{Style.RESET_ALL} "
                f"{method} {Fore.WHITE}{host}{path}{Style.RESET_ALL} "
                f"(from {addr[0]})"
            )

            # Forward request to the target server
            try:
                remote_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote_sock.settimeout(10)
                remote_sock.connect((host, port))

                # Fix the request line to use path only (not full URL)
                modified_request = request.replace(
                    url.encode() if isinstance(url, str) else url,
                    path.encode() if isinstance(path, str) else path,
                    1,
                )
                remote_sock.sendall(modified_request)

                # Receive response
                response = b""
                while True:
                    try:
                        chunk = remote_sock.recv(8192)
                        if not chunk:
                            break
                        response += chunk
                    except socket.timeout:
                        break

                remote_sock.close()

                # Inject JavaScript if configured
                if self.js_inject and b"text/html" in response:
                    response = self._inject_js(response)

                # Send response back to client
                client_sock.sendall(response)

            except Exception as e:
                # Send 502 Bad Gateway
                error_resp = (
                    b"HTTP/1.1 502 Bad Gateway\r\n"
                    b"Content-Type: text/plain\r\n"
                    b"Connection: close\r\n\r\n"
                    b"502 Bad Gateway - AQUA_SLOVIC Proxy"
                )
                client_sock.sendall(error_resp)

        except Exception:
            pass
        finally:
            try:
                client_sock.close()
            except Exception:
                pass

    def _handle_connect(self, client_sock, url, request):
        """Handle HTTPS CONNECT tunneling."""
        try:
            # Parse host:port from CONNECT target
            if ":" in url:
                host, port = url.split(":", 1)
                port = int(port)
            else:
                host = url
                port = 443

            print(
                f"  {Fore.CYAN}[HTTPS]{Style.RESET_ALL} "
                f"CONNECT {Fore.WHITE}{host}:{port}{Style.RESET_ALL}"
            )

            # Connect to remote
            remote_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote_sock.settimeout(10)
            remote_sock.connect((host, port))

            # Send 200 Connection Established
            client_sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

            # Tunnel bidirectionally
            self._tunnel(client_sock, remote_sock)

        except Exception:
            try:
                client_sock.sendall(
                    b"HTTP/1.1 502 Bad Gateway\r\n\r\n"
                )
            except Exception:
                pass
        finally:
            try:
                client_sock.close()
            except Exception:
                pass

    def _tunnel(self, client_sock, remote_sock, timeout=30):
        """Bidirectional TCP tunnel for HTTPS."""
        sockets = [client_sock, remote_sock]
        try:
            start_time = __import__("time").time()
            while self.running and (__import__("time").time() - start_time < timeout):
                readable, _, errored = select.select(sockets, [], sockets, 1.0)

                if errored:
                    break

                for sock in readable:
                    try:
                        data = sock.recv(8192)
                        if not data:
                            return
                        if sock is client_sock:
                            remote_sock.sendall(data)
                        else:
                            client_sock.sendall(data)
                    except Exception:
                        return
        finally:
            try:
                remote_sock.close()
            except Exception:
                pass

    def _parse_url(self, url, request):
        """
        Parse host, port, and path from a proxy request URL.
        Returns (host, port, path) tuple.
        """
        try:
            if url.startswith("http://"):
                url_stripped = url[7:]  # Remove http://
                if "/" in url_stripped:
                    host_port = url_stripped.split("/", 1)[0]
                    path = "/" + url_stripped.split("/", 1)[1]
                else:
                    host_port = url_stripped
                    path = "/"

                if ":" in host_port:
                    host, port = host_port.split(":", 1)
                    port = int(port)
                else:
                    host = host_port
                    port = 80

                return host, port, path
            else:
                # Relative URL — get host from Host header
                host = None
                for line in request.split(b"\r\n"):
                    if line.lower().startswith(b"host:"):
                        host = line.split(b":", 1)[1].strip().decode(errors="ignore")
                        break

                if not host:
                    return None, None, None

                port = 80
                if ":" in host:
                    host, port = host.split(":", 1)
                    port = int(port)

                return host, port, url

        except Exception:
            return None, None, None

    def _inject_js(self, response):
        """Inject JavaScript into an HTML response."""
        try:
            js_tag = f"<script>{self.js_inject}</script>".encode()

            # Inject before </body> or </html>
            if b"</body>" in response:
                response = response.replace(b"</body>", js_tag + b"</body>", 1)
            elif b"</html>" in response:
                response = response.replace(b"</html>", js_tag + b"</html>", 1)
            else:
                response += js_tag

            # Update Content-Length if present
            if b"Content-Length:" in response:
                header_end = response.find(b"\r\n\r\n")
                if header_end != -1:
                    headers = response[:header_end]
                    body = response[header_end + 4:]
                    new_len = len(body)
                    headers = re.sub(
                        b"Content-Length:\\s*\\d+",
                        f"Content-Length: {new_len}".encode(),
                        headers,
                    )
                    response = headers + b"\r\n\r\n" + body

        except Exception:
            pass

        return response
