#!/usr/bin/env python3
# redtool.py — Entry point for the RedTool framework

import sys
import argparse
from pathlib import Path

# Make sure core/ is importable regardless of cwd
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

from core.output import banner, info, error, warning
from core.console import Console


def parse_args():
    parser = argparse.ArgumentParser(
        description="RedTool — Red Team Framework (Lab Edition)",
        add_help=True,
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Skip the ASCII banner on startup",
    )
    parser.add_argument(
        "--module", "-m",
        metavar="MODULE",
        help="Load a module directly on startup (e.g. recon/portscan)",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    if not args.no_banner:
        banner()

    modules_dir = BASE_DIR / "modules"
    console = Console(modules_dir)

    if args.module:
        info(f"Auto-loading module: {args.module}")
        console._cmd_use([args.module])

    console.run()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        warning("Interrupted. Exiting cleanly.")
        sys.exit(0)
