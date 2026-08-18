"""Config file support: load targets, match windows, propose creation."""

import sys

from lib.core import Window, log
from lib.system import System
from lib.windows import WindowQuery


class Config:
    """Read and match the protect config file (one target per line)."""

    @staticmethod
    def load_config(path: str) -> list[str]:
        """Return non-empty, non-comment lines from the config file."""
        with open(path, encoding="utf-8") as fh:
            return [
                line.strip()
                for line in fh
                if line.strip() and not line.lstrip().startswith("#")
            ]

    @staticmethod
    def config_matches(windows: list[Window], path: str) -> list[Window]:
        """Return windows matching any config line (process name or title)."""
        targets: list[Window] = []
        seen: set[int] = set()
        for line in Config.load_config(path):
            needle = line.lower()
            for window in windows:
                if window.hwnd in seen:
                    continue
                name = WindowQuery.get_process_name(window.pid).lower()
                title = window.title.lower()
                if needle in name or needle in title:
                    seen.add(window.hwnd)
                    targets.append(window)
        return targets

    @staticmethod
    def load_config_targets(windows: list[Window], path: str) -> list[Window] | None:
        """Match config targets; offer to create the file if missing."""
        try:
            return Config.config_matches(windows, path)
        except OSError:
            log.error("Config file not found: %s", path)
            print(f"Config file not found: {path}")
            if System.ask_yes_no("Create it now? (y/N)"):
                try:
                    with open(path, "w", encoding="utf-8") as fh:
                        fh.write(
                            "# one target per line (process name or window title)\n"
                        )
                    print(f"Created {path} - add one target per line, then run again.")
                    created = True
                except OSError as exc:
                    log.error("Unable to create config file: %s", exc)
                    created = False
            else:
                created = False
            System.wait_key()
            sys.exit(0 if created else 1)
