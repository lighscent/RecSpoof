"""Terminal output and the interactive arrow-key menu."""

import logging
import msvcrt
import os
import shutil
import sys

from lib.core import (
    CHROMIUM_UNSUPPORTED,
    WDA_EXCLUDEFROMCAPTURE,
    Window,
    log,
)
from lib.protector import Protector
from lib.system import System
from lib.windows import WindowQuery


def render_windows(windows: list[Window]) -> list[str]:
    """Build the window list lines (header, separator, rows)."""
    proc_w = min(max(len(WindowQuery.get_process_name(w.pid)) for w in windows), 40)
    header = (
        f"{'#':>4}  {'PID':>6}    {'PROC':<{proc_w}} {'STATE':<15} {'INJ':<11} TITLE"
    )
    rows = [header, "-" * len(header)]
    for i, window in enumerate(windows, 1):
        state = WindowQuery.window_affinity(window.hwnd)
        inj = ""
        if WindowQuery.is_chromium(window.pid) and state != WDA_EXCLUDEFROMCAPTURE:
            inj = "unsupported"
        rows.append(
            f"{i:>4}  {window.pid:>6}  "
            f"{WindowQuery.get_process_name(window.pid):<{proc_w}} "
            f"{WindowQuery.affinity_label(window.hwnd, state):<15} {inj:<11} "
            f"{window.title}"
        )
    return rows


def print_windows(windows: list[Window]) -> None:
    """Print the window list to the console."""
    print("\n".join(render_windows(windows)))


def show_status(windows: list[Window]) -> None:
    """Print one status line per window."""
    for window in windows:
        print(
            f"[{WindowQuery.affinity_label(window.hwnd)}] "
            f"{WindowQuery.get_process_name(window.pid)} (pid {window.pid}) "
            f"{window.title}"
        )


class Menu:
    """Arrow-key menu over the visible windows."""

    GREEN = "\x1b[32m"
    CYAN = "\x1b[36m"
    RESET = "\x1b[0m"
    HINT = (
        "Up/Down: navigate | Enter: protect | a: all | "
        "s: save to config | r: refresh | q: quit"
    )

    def __init__(self, windows: list[Window], config_path: str | None = None) -> None:
        self.windows = list(windows)
        self.config_path = config_path
        self.states: dict[int, int | None] = {}
        self.idx = 0
        self.offset = 0
        self.status = ""
        self.term = shutil.get_terminal_size((80, 25))
        self.page_h = max(self.term.lines - 5, 3)
        self.width = self.term.columns
        self.proc_w = min(
            max(len(WindowQuery.get_process_name(w.pid)) for w in self.windows), 40
        )
        header, self.sep = render_windows(self.windows)[:2]
        self.header = header
        System.enable_ansi()

    def get_state(self, hwnd: int) -> int | None:
        """Cached window affinity state."""
        if hwnd not in self.states:
            self.states[hwnd] = WindowQuery.window_affinity(hwnd)
        return self.states[hwnd]

    def row_text(self, i: int) -> str:
        """Live row text for window i (state and INJ always current)."""
        window = self.windows[i]
        state = self.get_state(window.hwnd)
        inj = ""
        if WindowQuery.is_chromium(window.pid) and state != WDA_EXCLUDEFROMCAPTURE:
            inj = "unsupported"
        return (
            f"{i + 1:>4}  {window.pid:>6}  "
            f"{WindowQuery.get_process_name(window.pid):<{self.proc_w}} "
            f"{WindowQuery.affinity_label(window.hwnd, state):<15} {inj:<11} "
            f"{window.title}"
        )

    def paint(self, i: int, selected: bool) -> str:
        """Colorize row i (green selection, cyan already injected)."""
        text = self.row_text(i)[: self.width - 3]
        if selected:
            return f"{self.GREEN}> {text}{self.RESET}"
        if self.get_state(self.windows[i].hwnd) == WDA_EXCLUDEFROMCAPTURE:
            return f"{self.CYAN}  {text}{self.RESET}"
        return f"  {text}"

    def draw_status(self) -> None:
        """Redraw the status line at the bottom of the viewport."""
        sys.stdout.write(f"\x1b[{self.page_h + 4}H\x1b[K{self.status}")
        sys.stdout.flush()

    def save_to_config(self, i: int) -> None:
        """Append the selected window's process name to the config file."""
        window = self.windows[i]
        name = os.path.splitext(WindowQuery.get_process_name(window.pid))[0].lower()
        path = os.path.abspath(self.config_path or "protect.txt")
        try:
            existing: list[str] = []
            try:
                with open(path, encoding="utf-8") as fh:
                    existing = [ln.strip().lower() for ln in fh if ln.strip()]
            except OSError:
                pass
            if name in existing:
                self.status = f"'{name}' is already in {os.path.basename(path)}"
            else:
                with open(path, "a", encoding="utf-8") as fh:
                    fh.write(name + "\n")
                self.status = f"Added '{name}' to {os.path.basename(path)}"
        except OSError:
            self.status = f"Unable to write {os.path.basename(path)}"
        self.status = self.status[: self.width - 1]
        self.draw_status()

    def draw_all(self) -> None:
        """Full redraw of the viewport."""
        out = ["\x1b[H\x1b[J", self.header, self.sep]
        for i in range(self.offset, min(self.offset + self.page_h, len(self.windows))):
            out.append(self.paint(i, i == self.idx))
        sys.stdout.write("\n".join(out) + "\n" + self.HINT + "\n")
        self.draw_status()

    def draw_line(self, i: int, selected: bool) -> None:
        """Redraw a single row (skip if outside the visible page)."""
        if self.offset <= i < self.offset + self.page_h:
            sys.stdout.write(
                f"\x1b[{3 + i - self.offset}H\x1b[K{self.paint(i, selected)}"
            )
            sys.stdout.flush()

    def protect_one(self, i: int) -> bool:
        """Protect window i, refresh its state and the status line."""
        window = self.windows[i]
        hwnd = window.hwnd
        pid = window.pid
        title = window.title
        if (
            WindowQuery.is_chromium(pid)
            and self.get_state(hwnd) != WDA_EXCLUDEFROMCAPTURE
        ):
            self.status = f"[SKIP] '{title}' (pid {pid}) {CHROMIUM_UNSUPPORTED}"
            self.status = self.status[: self.width - 1]
            log.warning("SKIP: '%s' (pid %s) %s", title, pid, CHROMIUM_UNSUPPORTED)
            self.draw_line(i, i == self.idx)
            self.draw_status()
            return False
        ok, method = Protector.apply_affinity(hwnd, WDA_EXCLUDEFROMCAPTURE, False)
        self.states[hwnd] = WindowQuery.window_affinity(hwnd)
        ok = ok and self.states[hwnd] == WDA_EXCLUDEFROMCAPTURE
        if ok:
            self.status = f"[OK] ({method}) '{title}' (pid {pid}) injected"
        else:
            self.status = f"[FAILED] '{title}' (pid {pid})"
        self.status = self.status[: self.width - 1]
        self.draw_line(i, i == self.idx)
        self.draw_status()
        return ok

    def run(self) -> None:
        """Event loop: arrows navigate, Enter protects, q quits."""
        System.set_console_logging(logging.CRITICAL)
        try:
            self.draw_all()
            while True:
                key = msvcrt.getwch()
                if key in ("\xe0", "\x00"):  # arrow prefix
                    key = msvcrt.getwch()
                    if key == "H":  # up
                        new = (self.idx - 1) % len(self.windows)
                        if new < self.offset:
                            self.offset = new
                            self.draw_all()
                        elif new >= self.offset + self.page_h:
                            self.offset = new - self.page_h + 1
                            self.draw_all()
                        else:
                            self.draw_line(self.idx, False)
                            self.draw_line(new, True)
                        self.idx = new
                    elif key == "P":  # down
                        new = (self.idx + 1) % len(self.windows)
                        if new >= self.offset + self.page_h:
                            self.offset = new - self.page_h + 1
                            self.draw_all()
                        elif new < self.offset:
                            self.offset = new
                            self.draw_all()
                        else:
                            self.draw_line(self.idx, False)
                            self.draw_line(new, True)
                        self.idx = new
                elif key == "\r":
                    self.protect_one(self.idx)
                elif key in ("\x03", "q"):  # Ctrl+C / q
                    return
                elif key == "a":
                    ok_n = sum(
                        1 for i in range(len(self.windows)) if self.protect_one(i)
                    )
                    self.status = (
                        f"[OK] {ok_n} window(s) injected"
                        if ok_n == len(self.windows)
                        else f"[FAILED] {len(self.windows) - ok_n}/{len(self.windows)} window(s)"
                    )
                    self.status = self.status[: self.width - 1]
                    self.draw_all()
                elif key == "s":
                    self.save_to_config(self.idx)
                elif key in ("r", "R"):
                    refreshed = WindowQuery.list_windows()
                    if not refreshed:
                        return
                    self.windows = refreshed
                    self.states.clear()
                    self.proc_w = min(
                        max(
                            len(WindowQuery.get_process_name(w.pid))
                            for w in self.windows
                        ),
                        40,
                    )
                    self.header, self.sep = render_windows(self.windows)[:2]
                    self.idx = min(self.idx, len(self.windows) - 1)
                    self.offset = min(
                        self.offset, max(0, len(self.windows) - self.page_h)
                    )
                    self.draw_all()
        finally:
            System.set_console_logging(logging.WARNING)
