#!/usr/bin/env python3
"""RecSpoof â€” hide application windows from screen capture (OBS, Discord).

Apply SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE) so that
protected windows stay visible on screen but appear black or empty in
capture tools. The recspoof/ package must sit next to this launcher.

Examples:
    python recspoof.py                       interactive selection, then protect
    python recspoof.py -l                    list windows and their state
    python recspoof.py -s -t Discord         show state without modifying
    python recspoof.py -n notepad            protect by process name
    python recspoof.py -t Discord -c         remove protection
    python recspoof.py -n brave -a           protect all matching windows
    python recspoof.py -p 1234 -x            force in-process injection
    python recspoof.py --config protect.txt  batch-protect from a file
    python recspoof.py --check               check config targets, inject the rest
"""

import argparse
import sys

from lib.config import Config
from lib.core import WDA_EXCLUDEFROMCAPTURE, Window, log
from lib.protector import Protector
from lib.system import System
from lib.ui import Menu, print_windows, show_status
from lib.windows import WindowQuery

__version__ = "1.1.0"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="recspoof",
        description="Hide windows from screen capture via SetWindowDisplayAffinity.",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    target = parser.add_argument_group("target")
    target.add_argument("-p", "--pid", type=int, help="target a window by PID (exact)")
    target.add_argument("-n", "--name", help="target by process name (exact)")
    target.add_argument("-t", "--title", help="target by window title (substring)")
    target.add_argument("-a", "--all", action="store_true", help="all matching windows")
    action = parser.add_argument_group("action")
    action.add_argument("-l", "--list", action="store_true", help="list windows")
    action.add_argument("-s", "--status", action="store_true", help="show state only")
    action.add_argument("-c", "--clear", action="store_true", help="remove protection")
    action.add_argument(
        "--config",
        metavar="FILE",
        help="batch-protect from a file (one target per line, # comments)",
    )
    action.add_argument(
        "--check",
        action="store_true",
        help="check config targets and propose to inject the unprotected ones",
    )
    opt = parser.add_argument_group("options")
    opt.add_argument(
        "-x", "--inject", action="store_true", help="force in-process injection"
    )
    return parser.parse_args()


def find_targets(
    windows: list[Window], args: argparse.Namespace
) -> list[Window] | None:
    """Return matching windows for CLI criteria, or None for interactive mode."""
    if not (args.pid or args.name or args.title):
        return None
    selected: list[Window] = []
    for window in windows:
        match = True
        if args.pid is not None:
            match = match and window.pid == args.pid
        if args.name is not None:
            match = (
                match
                and WindowQuery.get_process_name(window.pid).lower()
                == args.name.lower()
            )
        if args.title is not None:
            match = match and args.title.lower() in window.title.lower()
        if match:
            selected.append(window)
    if not args.all:
        selected = selected[:1]
    return selected


def main() -> int:
    args = parse_args()
    System.ensure_admin()
    System.setup_console_logging()
    log.debug("Arguments: %s", vars(args))

    windows = WindowQuery.list_windows()
    log.debug("%d visible window(s)", len(windows))

    if args.list:
        print_windows(windows)
        return 0

    if args.config:
        targets = Config.load_config_targets(windows, args.config)
        if not targets:
            print("No windows matched the config file.")
            System.wait_key()
            return 1
        ok = Protector.protect(targets, clear=args.clear, force_inject=args.inject)
        if ok:
            verb = "removed" if args.clear else "applied"
            print(
                f"[VERIFIED] Protection {verb} and verified for {len(targets)} window(s)."
            )
        System.wait_key()
        return 0 if ok else 1

    if args.check:
        path = args.config or "protect.txt"
        targets = Config.load_config_targets(windows, path)
        if targets is None:
            return 1
        lines = Config.load_config(path)
        for line in lines:
            needle = line.lower()
            if not any(
                needle in WindowQuery.get_process_name(w.pid).lower()
                or needle in w.title.lower()
                for w in targets
            ):
                print(f"[--] no window for: {line}")
        unprotected = [
            w
            for w in targets
            if WindowQuery.window_affinity(w.hwnd) != WDA_EXCLUDEFROMCAPTURE
        ]
        for w in targets:
            state = WindowQuery.window_affinity(w.hwnd)
            if state == WDA_EXCLUDEFROMCAPTURE:
                print(f"[OK] '{w.title}' (pid {w.pid}) injected")
            else:
                print(f"[--] '{w.title}' (pid {w.pid}) not injected")
        if unprotected and System.ask_yes_no(
            f"Inject the {len(unprotected)} unprotected window(s)? (y/N)"
        ):
            ok = Protector.protect(unprotected, force_inject=args.inject)
            if ok:
                print(
                    f"[VERIFIED] Protection applied and verified for {len(unprotected)} window(s)."
                )
        System.wait_key()
        return 0

    targets = find_targets(windows, args)
    if targets is None:
        if not windows:
            print("No visible windows found.")
            return 1
        Menu(windows, args.config).run()
        return 0

    if not targets:
        print("No windows found.")
        return 1

    if args.status:
        show_status(targets)
        return 0

    log.debug("Selected target(s): %s", targets)
    ok = Protector.protect(targets, clear=args.clear, force_inject=args.inject)
    if ok:
        verb = "removed" if args.clear else "applied"
        print(
            f"[VERIFIED] Protection {verb} and verified for {len(targets)} window(s)."
        )
    System.wait_key()
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
