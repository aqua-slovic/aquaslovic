#!/usr/bin/env python3
"""
AQUA_SLOVIC - Cross-Platform Network Security Toolkit
Main entry point.

Usage:
    python main.py              Launch interactive shell
    python main.py --help       Show help
    python main.py --version    Show version

WARNING - DISCLAIMER: This tool is intended for authorized security testing
  and network administration ONLY. Unauthorized use against networks
  you do not own or have permission to test is illegal.
"""

import sys
import argparse

from aquaslovic import __version__
from aquaslovic.cli import AquaSlovicCLI
from aquaslovic.core.utils import print_banner, print_warning


def main():
    parser = argparse.ArgumentParser(
        description="AQUA_SLOVIC - Cross-Platform Network Security Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                  # Launch interactive shell
  python main.py --version        # Show version

WARNING: For authorized security testing only.
        """,
    )

    parser.add_argument(
        "--version", "-v",
        action="version",
        version=f"AQUA_SLOVIC v{__version__}",
    )

    parser.parse_args()

    # Legal disclaimer
    print_warning("=" * 60)
    print_warning("  AQUA_SLOVIC - LEGAL DISCLAIMER")
    print_warning("  This tool is for AUTHORIZED security testing.")
    print_warning("  You are responsible for your own actions.")
    print_warning("  Test on your own network and devices.")
    print_warning("=" * 60)
    print()

    # Launch interactive shell
    cli = AquaSlovicCLI()
    cli.run()


if __name__ == "__main__":
    main()
