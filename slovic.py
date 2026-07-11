#!/usr/bin/env python3
"""
AQUA_SLOVIC - Cross-Platform Network Security Toolkit
Encrypted bootstrap loader.

Usage:
    python slovic.py              Launch interactive shell
    python slovic.py --help       Show help
    python slovic.py --version    Show version

WARNING - DISCLAIMER: This tool is intended for authorized security testing
  and network administration ONLY. Unauthorized use against networks
  you do not own or have permission to test is illegal.
"""

import os
import sys
import json
import types
import base64
import hashlib
import argparse
import importlib

__version__ = "1.0.0"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ENCRYPTED_FILE = os.path.join(BASE_DIR, "encrypted", "source.dat")
FIXED_LICENSE_KEY = "MkhdjMJDHJJSHDUJue792736==_"
FIXED_MASTER_KEY = "aqua==_"
FIXED_MASTER_KEY_HASH = hashlib.sha256(FIXED_MASTER_KEY.encode("utf-8")).hexdigest()
FIXED_LICENSE_KEY_HASH = hashlib.sha256(FIXED_LICENSE_KEY.encode("utf-8")).hexdigest()


def hash_secret(value):
    """Return a one-way hash of a secret value for display and verification."""
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()


def resolve_master_key(secret):
    """Resolve the real master key from the user input or a hash of it."""
    provided = (secret or "").strip()
    if not provided:
        raise ValueError("empty master key")

    if provided in {FIXED_MASTER_KEY, FIXED_LICENSE_KEY}:
        return FIXED_MASTER_KEY.encode("utf-8")

    if provided in {FIXED_MASTER_KEY_HASH, FIXED_LICENSE_KEY_HASH}:
        return FIXED_MASTER_KEY.encode("utf-8")

    raise ValueError("invalid master key")


def extract_master_key(license_key):
    """Extract the master decryption key from the supplied secret."""
    return resolve_master_key(license_key)


def derive_fernet_key(master_key):
    """Derive a Fernet-compatible key from the master key."""
    if isinstance(master_key, bytes):
        normalized = master_key
    else:
        normalized = str(master_key).encode("utf-8")

    derived = hashlib.sha256(normalized).digest()
    return base64.urlsafe_b64encode(derived)


def decrypt_and_load(license_key):
    """Decrypt the source files and load them as modules."""
    try:
        from cryptography.fernet import Fernet
    except ImportError:
        print("[-] Missing dependency: cryptography")
        print("    Install with: pip install cryptography")
        sys.exit(1)

    if not os.path.exists(ENCRYPTED_FILE):
        print("[-] Encrypted source not found: encrypted/source.dat")
        print("    This file should come with the repository.")
        sys.exit(1)

    # Extract and derive the key
    try:
        master_key = extract_master_key(license_key)
        fernet_key = derive_fernet_key(master_key)
        fernet = Fernet(fernet_key)
    except Exception as e:
        print(f"[-] Invalid key format. Error: {e}")
        return False

    # Load the encrypted manifest
    with open(ENCRYPTED_FILE, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    # Decrypt all modules into memory
    decrypted_modules = {}
    try:
        for rel_path, encoded_data in manifest.items():
            encrypted_data = base64.b64decode(encoded_data)
            decrypted_bytes = fernet.decrypt(encrypted_data)
            decrypted_modules[rel_path] = decrypted_bytes.decode("utf-8")
    except Exception as e:
        print(f"[-] Decryption failed. Invalid or expired key. Error: {e}")
        return False

    # Create package structure in memory and register modules
    _load_modules_from_memory(decrypted_modules)
    return True


def _load_modules_from_memory(decrypted_modules):
    """Load decrypted source code as Python modules."""
    def module_priority(path):
        normalized = path.replace("\\", "/")
        if normalized.endswith("/__init__.py"):
            return (0, normalized)
        if normalized.endswith("/core/utils.py"):
            return (1, normalized)
        if "/core/" in normalized and normalized.endswith(".py"):
            return (2, normalized)
        if normalized.endswith("/cli.py"):
            return (3, normalized)
        if normalized.endswith(".py"):
            return (4, normalized)
        return (5, normalized)

    sorted_paths = sorted(decrypted_modules.keys(), key=module_priority)

    for rel_path in sorted_paths:
        source_code = decrypted_modules[rel_path]
        if not rel_path.endswith(".py"):
            continue

        # Convert file path to module name
        module_path = rel_path.replace("/", ".").replace("\\", ".")
        if module_path.endswith(".__init__.py"):
            module_name = module_path[:-12]
            is_package = True
        elif module_path.endswith(".py"):
            module_name = module_path[:-3]
            is_package = False
        else:
            continue

        # Skip non-aquaslovic modules (like setup.py, requirements.txt)
        if not module_name.startswith("aquaslovic"):
            continue

        # Create the module
        module = types.ModuleType(module_name)
        module.__file__ = os.path.join(BASE_DIR, rel_path)
        module.__loader__ = None

        if is_package:
            module.__path__ = [os.path.join(BASE_DIR, os.path.dirname(rel_path))]
            module.__package__ = module_name
        else:
            module.__package__ = module_name.rsplit(".", 1)[0] if "." in module_name else ""

        # Register the module in sys.modules
        sys.modules[module_name] = module

    # Now execute the source code in each module
    for rel_path in sorted_paths:
        source_code = decrypted_modules[rel_path]
        if not rel_path.endswith(".py"):
            continue

        module_path = rel_path.replace("/", ".").replace("\\", ".")
        if module_path.endswith(".__init__.py"):
            module_name = module_path[:-12]
        elif module_path.endswith(".py"):
            module_name = module_path[:-3]
        else:
            continue

        if not module_name.startswith("aquaslovic"):
            continue

        module = sys.modules[module_name]
        try:
            code = compile(source_code, module.__file__, "exec")
            exec(code, module.__dict__)
        except Exception as e:
            print(f"[-] Error loading module {module_name}: {e}")
            return


def print_key_prompt():
    """Display the key entry prompt."""
    try:
        from colorama import Fore, Style, init
        init(autoreset=True)
        print(f"""
{Fore.CYAN}
    /   |   ____    __  __     /   |            _____    __       ____   _    __     ____    ______
   / /| |  / __ \\  / / / /    / /| |           / ___/   / /      / __ \\ | |  / /    /  _/   / ____/
  / ___ | / /_/ / / /_/ /    / ___ |           \\__ \\   / /      / /_/ / | | / /     / /    / /     
 /_/  |_| \\___\\_\\ \\____/    /_/  |_|  ______  ___/ /  / /___    \\____/  | |/ /    _/ /    / /___   
                                     /_____/ /____/   /____/            |___/    /___/    \\____/   
{Style.RESET_ALL}
{Fore.WHITE}  AquaSlovic v{__version__} - Network Security Toolkit{Style.RESET_ALL}
{Fore.YELLOW}  Protected by license key encryption{Style.RESET_ALL}
{Fore.CYAN}  for more visit github account = https://github.com/aqua-slovic, telegram = https://t.me/aqua_slovic, website = https://wisdom-malata.vercel.app{Style.RESET_ALL}
""")
    except ImportError:
        print(f"""
    AQUA_SLOVIC v{__version__} - Network Security Toolkit
    Protected by license key encryption
    for more visit github account = https://github.com/aqua-slovic, telegram = https://t.me/aqua_slovic, website = https://wisdom-malata.vercel.app
""")


def main():
    parser = argparse.ArgumentParser(
        description="AQUA_SLOVIC - Cross-Platform Network Security Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python slovic.py                  # Launch interactive shell
  python slovic.py --version        # Show version
  python slovic.py --dev            # Load local source code for development

WARNING: For authorized security testing only.
        """,
    )

    parser.add_argument(
        "--version", "-v",
        action="version",
        version=f"AQUA_SLOVIC v{__version__}",
    )
    parser.add_argument(
        "--dev",
        action="store_true",
        help="Load the local source tree directly (developer mode).",
    )

    args = parser.parse_args()

    # Show banner and prompt for key
    print_key_prompt()

    source_dir = os.path.join(BASE_DIR, "aquaslovic")
    if args.dev and os.path.isdir(source_dir) and os.path.exists(os.path.join(source_dir, "__init__.py")):
        print("  [*] Development mode detected - loading from source\n")

        from aquaslovic.core.utils import print_warning
        print_warning("=" * 60)
        print_warning("  AQUA_SLOVIC - LEGAL DISCLAIMER")
        print_warning("  This tool is for AUTHORIZED security testing only.")
        print_warning("  Unauthorized access to computer networks is illegal.")
        print_warning("  You are responsible for your own actions.")
        print_warning("=" * 60)
        print()

        from aquaslovic.cli import AquaSlovicCLI
        cli = AquaSlovicCLI()
        cli.run()
        return

    try:
        license_key = input("  Enter master key: ").strip()
    except (KeyboardInterrupt, EOFError):
        print("\n  Cancelled.")
        sys.exit(0)

    if not license_key:
        print("  [-] No key provided. Exiting.")
        sys.exit(1)

    print("  [*] Validating key and decrypting modules...\n")

    if not decrypt_and_load(license_key):
        print("  [-] Access denied. Invalid license key.")
        sys.exit(1)

    print("  [+] Key accepted. Loading toolkit...\n")

    try:
        from aquaslovic.core.utils import print_warning
        print_warning("=" * 60)
        print_warning("  AQUA_SLOVIC - LEGAL DISCLAIMER")
        print_warning("  This tool is for AUTHORIZED security testing only.")
        print_warning("  Unauthorized access to computer networks is illegal.")
        print_warning("  You are responsible for your own actions.")
        print_warning("=" * 60)
        print()

        from aquaslovic.cli import AquaSlovicCLI
        cli = AquaSlovicCLI()
        cli.run()
    except Exception as e:
        print(f"  [-] Failed to start toolkit: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
