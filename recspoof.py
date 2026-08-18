#!/usr/bin/env python3
"""RecSpoof - protects a window against screen capture (OBS, sharing, Discord...)

Usage:
  python recspoof.py                       # interactive selection, then protect
  python recspoof.py -l                    # list windows and their state
  python recspoof.py -s -t Discord         # show state without modifying
  python recspoof.py -n notepad            # protect by process name
  python recspoof.py -t Discord -c         # remove protection
  python recspoof.py -n brave -a           # protect all matching windows
  python recspoof.py -p 1234 -x            # force in-process injection
  python recspoof.py --config protect.txt  # batch-protect from a config file
  python recspoof.py --check               # check config targets, inject the rest
"""

from __future__ import annotations

import argparse
import ctypes
import functools
import logging
import msvcrt
import os
import shutil
import struct
import subprocess
import sys
from collections.abc import Callable
from contextlib import contextmanager
from ctypes import wintypes
from dataclasses import dataclass
from typing import Any

log = logging.getLogger("recspoof")

__version__ = "1.0.0"


@dataclass
class Window:
    """A visible window (hwnd, pid, title)."""

    hwnd: int
    pid: int
    title: str

    def __iter__(self):
        """Backward compatible with the old tuple unpacking."""
        return iter((self.hwnd, self.pid, self.title))


# ------------------------------------------------------------- constants

WDA_NONE = 0x00000000
WDA_EXCLUDEFROMCAPTURE = 0x00000011
AFFINITY_NAMES = {WDA_NONE: "not injected", WDA_EXCLUDEFROMCAPTURE: "injected"}
CHROMIUM = frozenset({"chrome", "brave", "msedge", "opera", "vivaldi", "chromium"})
CHROMIUM_UNSUPPORTED = (
    "cannot be protected: the direct call is denied (error 5) and "
    "thread injection crashes the browser"
)

PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_CREATE_THREAD = 0x0002
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_RELEASE = 0x8000
PAGE_EXECUTE_READWRITE = 0x40
TH32CS_SNAPTHREAD = 0x00000004
LIST_MODULES_32BIT = 0x00000001
THREAD_SUSPENDED = 0x00000004
STILL_ACTIVE = 259
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

# ------------------------------------------------------- Win32 bindings


def api(dll: ctypes.WinDLL, name: str, restype: Any, *argtypes: Any) -> Any:
    fn = getattr(dll, name)
    fn.argtypes = list(argtypes)
    fn.restype = restype
    return fn


user32 = ctypes.WinDLL("user32", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
shell32 = ctypes.WinDLL("shell32", use_last_error=True)
psapi = ctypes.WinDLL("psapi", use_last_error=True)

EnumWindowsProc = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

EnumWindows = api(
    user32, "EnumWindows", wintypes.BOOL, EnumWindowsProc, wintypes.LPARAM
)
IsWindowVisible = api(user32, "IsWindowVisible", wintypes.BOOL, wintypes.HWND)
GetWindowTextLengthW = api(user32, "GetWindowTextLengthW", ctypes.c_int, wintypes.HWND)
GetWindowTextW = api(
    user32, "GetWindowTextW", ctypes.c_int, wintypes.HWND, wintypes.LPWSTR, ctypes.c_int
)
GetWindowThreadProcessId = api(
    user32,
    "GetWindowThreadProcessId",
    wintypes.DWORD,
    wintypes.HWND,
    ctypes.POINTER(wintypes.DWORD),
)
SetWindowDisplayAffinity = api(
    user32, "SetWindowDisplayAffinity", wintypes.BOOL, wintypes.HWND, wintypes.UINT
)
GetWindowDisplayAffinity = api(
    user32,
    "GetWindowDisplayAffinity",
    wintypes.BOOL,
    wintypes.HWND,
    ctypes.POINTER(wintypes.UINT),
)

OpenProcess = api(
    kernel32,
    "OpenProcess",
    wintypes.HANDLE,
    wintypes.DWORD,
    wintypes.BOOL,
    wintypes.DWORD,
)
CloseHandle = api(kernel32, "CloseHandle", wintypes.BOOL, wintypes.HANDLE)
VirtualAllocEx = api(
    kernel32,
    "VirtualAllocEx",
    wintypes.LPVOID,
    wintypes.HANDLE,
    wintypes.LPVOID,
    ctypes.c_size_t,
    wintypes.DWORD,
    wintypes.DWORD,
)
VirtualFreeEx = api(
    kernel32,
    "VirtualFreeEx",
    wintypes.BOOL,
    wintypes.HANDLE,
    wintypes.LPVOID,
    ctypes.c_size_t,
    wintypes.DWORD,
)
WriteProcessMemory = api(
    kernel32,
    "WriteProcessMemory",
    wintypes.BOOL,
    wintypes.HANDLE,
    wintypes.LPVOID,
    wintypes.LPVOID,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
)
CreateRemoteThread = api(
    kernel32,
    "CreateRemoteThread",
    wintypes.HANDLE,
    wintypes.HANDLE,
    wintypes.LPVOID,
    ctypes.c_size_t,
    wintypes.LPVOID,
    wintypes.LPVOID,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
)
WaitForSingleObject = api(
    kernel32, "WaitForSingleObject", wintypes.DWORD, wintypes.HANDLE, wintypes.DWORD
)
GetExitCodeThread = api(
    kernel32,
    "GetExitCodeThread",
    wintypes.BOOL,
    wintypes.HANDLE,
    ctypes.POINTER(wintypes.DWORD),
)
IsWow64Process = api(
    kernel32,
    "IsWow64Process",
    wintypes.BOOL,
    wintypes.HANDLE,
    ctypes.POINTER(wintypes.BOOL),
)
QueryFullProcessImageNameW = api(
    kernel32,
    "QueryFullProcessImageNameW",
    wintypes.BOOL,
    wintypes.HANDLE,
    wintypes.DWORD,
    wintypes.LPWSTR,
    ctypes.POINTER(wintypes.DWORD),
)
IsUserAnAdmin = api(shell32, "IsUserAnAdmin", wintypes.BOOL)


class SHELLEXECUTEINFOW(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("fMask", wintypes.ULONG),
        ("hwnd", wintypes.HWND),
        ("lpVerb", wintypes.LPCWSTR),
        ("lpFile", wintypes.LPCWSTR),
        ("lpParameters", wintypes.LPCWSTR),
        ("lpDirectory", wintypes.LPCWSTR),
        ("nShow", ctypes.c_int),
        ("hInstApp", wintypes.HINSTANCE),
        ("lpIDList", wintypes.LPVOID),
        ("lpClass", wintypes.LPCWSTR),
        ("hkeyClass", wintypes.HKEY),
        ("dwHotKey", wintypes.DWORD),
        ("hIcon", wintypes.HANDLE),
        ("hProcess", wintypes.HANDLE),
    ]


class THREADENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ThreadID", wintypes.DWORD),
        ("th32OwnerProcessID", wintypes.DWORD),
        ("tpBasePri", wintypes.LONG),
        ("tpDeltaPri", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
    ]


ShellExecuteExW = api(
    shell32, "ShellExecuteExW", wintypes.BOOL, ctypes.POINTER(SHELLEXECUTEINFOW)
)

STD_INPUT_HANDLE = -10
STD_OUTPUT_HANDLE = -11
STD_ERROR_HANDLE = -12
ATTACH_PARENT_PROCESS = 0xFFFFFFFF
SEE_MASK_NOCLOSEPROCESS = 0x00000040
SEE_MASK_NO_CONSOLE = 0x00008000
ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004

GetStdHandle = api(kernel32, "GetStdHandle", wintypes.HANDLE, wintypes.DWORD)
SetStdHandle = api(
    kernel32, "SetStdHandle", wintypes.BOOL, wintypes.DWORD, wintypes.HANDLE
)
AttachConsole = api(kernel32, "AttachConsole", wintypes.BOOL, wintypes.DWORD)
AllocConsole = api(kernel32, "AllocConsole", wintypes.BOOL)
GetExitCodeProcess = api(
    kernel32,
    "GetExitCodeProcess",
    wintypes.BOOL,
    wintypes.HANDLE,
    ctypes.POINTER(wintypes.DWORD),
)
GetConsoleMode = api(
    kernel32,
    "GetConsoleMode",
    wintypes.BOOL,
    wintypes.HANDLE,
    ctypes.POINTER(wintypes.DWORD),
)
SetConsoleMode = api(
    kernel32, "SetConsoleMode", wintypes.BOOL, wintypes.HANDLE, wintypes.DWORD
)
CreateToolhelp32Snapshot = api(
    kernel32,
    "CreateToolhelp32Snapshot",
    wintypes.HANDLE,
    wintypes.DWORD,
    wintypes.DWORD,
)
Thread32First = api(
    kernel32,
    "Thread32First",
    wintypes.BOOL,
    wintypes.HANDLE,
    ctypes.POINTER(THREADENTRY32),
)
Thread32Next = api(
    kernel32,
    "Thread32Next",
    wintypes.BOOL,
    wintypes.HANDLE,
    ctypes.POINTER(THREADENTRY32),
)
EnumProcessModulesEx = api(
    psapi,
    "EnumProcessModulesEx",
    wintypes.BOOL,
    wintypes.HANDLE,
    wintypes.LPVOID,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
    wintypes.DWORD,
)
GetModuleBaseNameW = api(
    psapi,
    "GetModuleBaseNameW",
    wintypes.DWORD,
    wintypes.HANDLE,
    wintypes.HMODULE,
    wintypes.LPWSTR,
    wintypes.DWORD,
)

# ---------------------------------------------------------------- helpers


def enable_ansi() -> None:
    """Enable ANSI color sequences on the Windows console."""
    h = GetStdHandle(STD_OUTPUT_HANDLE)
    mode = wintypes.DWORD()
    if GetConsoleMode(h, ctypes.byref(mode)):
        SetConsoleMode(h, mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING)


@contextmanager
def safe_handle(handle: wintypes.HANDLE) -> Any:
    """Close a Win32 handle on exit, even on exception."""
    try:
        yield handle
    finally:
        if handle and handle != INVALID_HANDLE_VALUE:
            CloseHandle(handle)


def setup_console_logging() -> None:
    """Configure console-only logging (WARNING and above)."""
    stream = logging.StreamHandler()
    stream.setLevel(logging.WARNING)
    logging.basicConfig(
        level=logging.WARNING,
        format="%(levelname)s: %(message)s",
        handlers=[stream],
    )


def set_console_logging(level: int) -> None:
    """Set the console log level (WARNING and above only)."""
    for logger in (logging.getLogger(), log):
        for handler in logger.handlers:
            if type(handler) is logging.StreamHandler:
                handler.setLevel(level)


def rebind_console_stdio() -> None:
    """Reopen stdio on the current console (CONIN$/CONOUT$)."""
    sys.stdin = None
    sys.stdout = None
    sys.stderr = None
    for name, fd, std_handle in (
        ("CONOUT$", 1, STD_OUTPUT_HANDLE),
        ("CONOUT$", 2, STD_ERROR_HANDLE),
        ("CONIN$", 0, STD_INPUT_HANDLE),
    ):
        flags = os.O_RDONLY if name == "CONIN$" else os.O_WRONLY
        new_fd = os.open(name, flags)
        os.dup2(new_fd, fd)
        os.close(new_fd)
        SetStdHandle(std_handle, msvcrt.get_osfhandle(fd))
    sys.stdin = os.fdopen(0, "r")
    sys.stdout = os.fdopen(1, "w")
    sys.stderr = os.fdopen(2, "w")


def attach_parent_console() -> None:
    """Attach to the console of the launching process (UAC relaunch)."""
    attached = bool(AttachConsole(ATTACH_PARENT_PROCESS))
    if not attached:
        attached = bool(AllocConsole())
    if attached:
        rebind_console_stdio()


def relaunch_elevated() -> int:
    """Relaunch elevated via UAC, then wait for it in the same console."""
    script = os.path.abspath(__file__)
    params = f'"{script}" {subprocess.list2cmdline(sys.argv[1:])}'
    sei = SHELLEXECUTEINFOW()
    sei.cbSize = ctypes.sizeof(SHELLEXECUTEINFOW)
    sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NO_CONSOLE
    sei.hwnd = None
    sei.lpVerb = "runas"
    sei.lpFile = sys.executable
    sei.lpParameters = params
    sei.lpDirectory = os.path.dirname(script)
    sei.nShow = 1
    if not ShellExecuteExW(ctypes.byref(sei)):
        err = ctypes.get_last_error()
        if err == 1223:  # ERROR_CANCELLED
            log.error("Elevation cancelled.")
        else:
            log.error("Elevation failed (error %s).", err)
        return 0
    with safe_handle(sei.hProcess):
        WaitForSingleObject(sei.hProcess, 0xFFFFFFFF)  # keep the console alive
        code = wintypes.DWORD()
        GetExitCodeProcess(sei.hProcess, ctypes.byref(code))
        return code.value


def ensure_admin() -> None:
    """Request UAC elevation at launch, keeping the same console window."""
    if IsUserAnAdmin():
        attach_parent_console()
        return
    sys.exit(relaunch_elevated())


def get_window_title(hwnd: int) -> str:
    length = GetWindowTextLengthW(hwnd)
    if length == 0:
        return ""
    buf = ctypes.create_unicode_buffer(length + 1)
    GetWindowTextW(hwnd, buf, length + 1)
    return buf.value


@functools.lru_cache(maxsize=256)
def get_process_name(pid: int) -> str:
    with safe_handle(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)) as h:
        if not h:
            return f"pid {pid}"
        size = wintypes.DWORD(260)
        buf = ctypes.create_unicode_buffer(260)
        if QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
            return os.path.basename(buf.value)
        return f"pid {pid}"


def list_windows() -> list[Window]:
    windows: list[Window] = []

    @EnumWindowsProc
    def callback(hwnd, lparam) -> bool:
        if IsWindowVisible(hwnd):
            title = get_window_title(hwnd)
            if title:
                pid = wintypes.DWORD()
                GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
                windows.append(Window(hwnd, pid.value, title))
        return True

    EnumWindows(callback, 0)
    return windows


def window_affinity(hwnd: int) -> int | None:
    state = wintypes.UINT()
    if GetWindowDisplayAffinity(hwnd, ctypes.byref(state)):
        return state.value
    return None


def affinity_label(hwnd: int, state: int | None = None) -> str:
    if state is None:
        state = window_affinity(hwnd)
    if state is None:
        return "?"
    return AFFINITY_NAMES.get(state, f"unknown ({state})")


def is_chromium(pid: int) -> bool:
    name = os.path.splitext(get_process_name(pid))[0].lower()
    return name in CHROMIUM


def process_suspended(pid: int) -> bool:
    with safe_handle(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, pid)) as snap:
        if snap == INVALID_HANDLE_VALUE:
            return False
        entry = THREADENTRY32()
        entry.dwSize = ctypes.sizeof(THREADENTRY32)
        if not Thread32First(snap, ctypes.byref(entry)):
            return False
        while True:
            if entry.th32OwnerProcessID == pid and entry.dwFlags & THREAD_SUSPENDED:
                return True
            if not Thread32Next(snap, ctypes.byref(entry)):
                return False


# ---------------------------------------------------------------- actions


def render_windows(windows: list[Window]) -> list[str]:
    proc_w = min(max(len(get_process_name(pid)) for _, pid, _ in windows), 40)
    header = (
        f"{'#':>4}  {'PID':>6}    {'PROC':<{proc_w}} {'STATE':<15} {'INJ':<11} TITLE"
    )
    rows = [header, "-" * len(header)]
    for i, (hwnd, pid, title) in enumerate(windows, 1):
        state = window_affinity(hwnd)
        inj = ""
        if is_chromium(pid) and state != WDA_EXCLUDEFROMCAPTURE:
            inj = "unsupported"
        rows.append(
            f"{i:>4}  {pid:>6}  {get_process_name(pid):<{proc_w}} "
            f"{affinity_label(hwnd, state):<15} {inj:<11} {title}"
        )
    return rows


def print_windows(windows: list[Window]) -> None:
    print("\n".join(render_windows(windows)))


def select_interactive(windows: list[Window], config_path: str | None = None) -> None:
    """Arrow-key navigation; Enter protects inline, status shown at the bottom."""
    enable_ansi()
    GREEN = "\x1b[32m"
    CYAN = "\x1b[36m"
    RESET = "\x1b[0m"
    hint = (
        "Up/Down: navigate | Enter: protect | a: all | s: save to config "
        "| r: refresh | q: quit"
    )

    header, sep, *_ = render_windows(windows)
    body = list(windows)
    proc_w = min(max(len(get_process_name(pid)) for _, pid, _ in windows), 40)
    term = shutil.get_terminal_size((80, 25))
    page_h = max(term.lines - 5, 3)
    width = term.columns
    idx, offset = [0], 0
    status = [""]
    states = {}

    def get_state(hwnd: int) -> int | None:
        if hwnd not in states:
            states[hwnd] = window_affinity(hwnd)
        return states[hwnd]

    def row_text(i: int) -> str:
        """Live row text: state and INJ marker always up to date."""
        hwnd, pid, title = windows[i]
        state = get_state(hwnd)
        inj = ""
        if is_chromium(pid) and state != WDA_EXCLUDEFROMCAPTURE:
            inj = "unsupported"
        return (
            f"{i + 1:>4}  {pid:>6}  {get_process_name(pid):<{proc_w}} "
            f"{affinity_label(hwnd, state):<15} {inj:<11} {title}"
        )

    def paint(i: int, selected: bool) -> str:
        """Colored line: green = selection, cyan = already protected."""
        line = row_text(i)[: width - 3]  # truncate so no wrap (keeps rows aligned)
        if selected:
            return f"{GREEN}> {line}{RESET}"
        if get_state(windows[i].hwnd) == WDA_EXCLUDEFROMCAPTURE:
            return f"{CYAN}  {line}{RESET}"
        return f"  {line}"

    def draw_status() -> None:
        sys.stdout.write(f"\x1b[{page_h + 4}H\x1b[K{status[0]}")
        sys.stdout.flush()

    def save_to_config(i: int) -> None:
        """Add the selected window's process name to the config file."""
        name = os.path.splitext(get_process_name(windows[i].pid))[0].lower()
        path = os.path.abspath(config_path or "protect.txt")
        base = os.path.basename(path)
        try:
            existing: list[str] = []
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    existing = [ln.strip().lower() for ln in f]
            if name in existing:
                msg = f"'{name}' is already in {base}"
            else:
                with open(path, "a", encoding="utf-8") as f:
                    f.write(f"{name}\n")
                msg = f"Added '{name}' to {base}"
                log.info("Config: added '%s' to %s", name, path)
        except OSError as e:
            log.error("Config: unable to write %s: %s", path, e)
            msg = f"Unable to write {base}"
        status[0] = msg[: width - 1]
        draw_status()

    def draw_all() -> None:
        sys.stdout.write("\x1b[H\x1b[J")  # cursor home + clear screen
        sys.stdout.write(f"{header}\n{sep}\n")
        for i in range(offset, offset + page_h):
            if i >= len(body):
                break
            sys.stdout.write(paint(i, i == idx[0]) + "\n")
        sys.stdout.write("\n" + hint + "\n")
        draw_status()
        sys.stdout.flush()

    def draw_line(i: int, selected: bool) -> None:
        """Redraw ONLY line i (anti-flicker)."""
        if not (offset <= i < offset + page_h):
            return
        sys.stdout.write(f"\x1b[{3 + i - offset}H\x1b[K")
        sys.stdout.write(paint(i, selected))
        sys.stdout.flush()

    def protect_one(i: int) -> bool:
        """Protect window i, update its row and the bottom status line."""
        hwnd, pid, title = windows[i]
        if is_chromium(pid) and get_state(hwnd) != WDA_EXCLUDEFROMCAPTURE:
            msg = f"[SKIP] '{title}' (pid {pid}) {CHROMIUM_UNSUPPORTED}"
            log.warning("SKIP: '%s' (pid %s): Chromium, no safe protection", title, pid)
            status[0] = msg[: width - 1]
            draw_status()
            return False
        ok, method = apply_affinity(hwnd, WDA_EXCLUDEFROMCAPTURE, False)
        states[hwnd] = window_affinity(hwnd)
        ok = ok and states[hwnd] == WDA_EXCLUDEFROMCAPTURE
        if ok:
            msg = f"[OK] ({method}) '{title}' (pid {pid}) injected"
            log.info(
                "OK (%s): '%s' (pid %s, hwnd %s) injected", method, title, pid, hwnd
            )
        else:
            msg = f"[FAILED] '{title}' (pid {pid})"
            log.error("FAILED: '%s' (pid %s)", title, pid)
        status[0] = msg[: width - 1]
        draw_line(i, i == idx[0])
        draw_status()
        return ok

    set_console_logging(logging.CRITICAL)
    try:
        draw_all()
        while True:
            key = msvcrt.getwch()
            if key in ("\xe0", "\x00"):  # arrows / extended keys
                k2 = msvcrt.getwch()
                if k2 == "H":
                    new = (idx[0] - 1) % len(body)
                elif k2 == "P":
                    new = (idx[0] + 1) % len(body)
                else:
                    continue
                prev = idx[0]
                idx[0] = new
                if new < offset or new >= offset + page_h:
                    # page change: full redraw (rare)
                    offset = new if new < offset else new - page_h + 1
                    draw_all()
                else:
                    draw_line(prev, False)
                    draw_line(new, True)
            elif key == "\r":
                protect_one(idx[0])
            elif key == "\x03":  # Ctrl+C
                return
            elif key == "a":
                log.debug("Protect all (%d)", len(windows))
                ok_count = sum(1 for i in range(len(windows)) if protect_one(i))
                if ok_count == len(windows):
                    status[0] = f"[OK] {len(windows)} window(s) injected"[: width - 1]
                else:
                    status[0] = (
                        f"[FAILED] {len(windows) - ok_count}/{len(windows)} window(s)"
                    )[: width - 1]
                draw_all()
            elif key == "q":
                return
            elif key == "s":
                save_to_config(idx[0])
            elif key in ("r", "R"):
                log.debug("Refreshing window list...")
                refreshed = list_windows()
                if not refreshed:
                    return
                windows = refreshed
                states.clear()
                header, sep, *_ = render_windows(windows)
                body = list(windows)
                if idx[0] >= len(body):
                    idx[0] = len(body) - 1
                offset = min(offset, max(0, len(body) - page_h))
                draw_all()
    finally:
        set_console_logging(logging.WARNING)


def apply_affinity(
    hwnd: int, affinity: int, force_inject: bool
) -> tuple[bool, str | None]:
    """Try the direct call, otherwise in-process injection. Returns (ok, method)."""
    if not force_inject and SetWindowDisplayAffinity(hwnd, affinity):
        return True, "direct"
    if force_inject or ctypes.get_last_error() == 5:
        log.info("Direct call failed, trying in-process injection...")
        try:
            if inject(hwnd, affinity):
                return True, "injection"
            log.error("Injection executed but SetWindowDisplayAffinity returned FALSE.")
        except OSError as e:
            log.error("Injection failed: %s", e)
    else:
        log.error("Direct call failed (error %s).", ctypes.get_last_error())
    return False, None


def protect(
    windows: list[Window], clear: bool = False, force_inject: bool = False
) -> bool:
    affinity = WDA_NONE if clear else WDA_EXCLUDEFROMCAPTURE
    log.debug(
        "Applying affinity %s (clear=%s) to %d window(s)",
        hex(affinity),
        clear,
        len(windows),
    )
    ok = True
    for hwnd, pid, title in windows:
        if (
            affinity == WDA_EXCLUDEFROMCAPTURE
            and is_chromium(pid)
            and window_affinity(hwnd) != WDA_EXCLUDEFROMCAPTURE
        ):
            ok = False
            print(f"[SKIP] '{title}' (pid {pid}) {CHROMIUM_UNSUPPORTED}.")
            log.warning("SKIP: '%s' (pid %s): Chromium, no safe protection", title, pid)
            continue
        success, method = apply_affinity(hwnd, affinity, force_inject)
        state = window_affinity(hwnd)
        if success and state == affinity:
            result = "injected" if affinity == WDA_EXCLUDEFROMCAPTURE else "uninjected"
            print(f"[OK] ({method}) '{title}' (pid {pid}) {result}")
            log.info(
                "OK (%s): '%s' (pid %s, hwnd %s) %s", method, title, pid, hwnd, result
            )
        else:
            ok = False
            print(f"[FAILED] '{title}' (pid {pid})")
    return ok


def show_status(windows: list[Window]) -> None:
    for hwnd, pid, title in windows:
        print(f"[{affinity_label(hwnd)}] {get_process_name(pid)} (pid {pid}) {title}")
        log.debug(
            "state: pid=%s hwnd=%s affinity=%s title='%s'",
            pid,
            hwnd,
            affinity_label(hwnd),
            title,
        )


# ---------------------------------------------------------- injection


def build_shellcode(
    affinity: int, set_affinity_addr: int, exit_thread_addr: int
) -> bytes:
    # x64: SetWindowDisplayAffinity(hwnd=RCX, affinity), then ExitThread(result)
    sc = bytearray()
    sc += b"\x48\xba" + struct.pack("<Q", affinity)  # movabs rdx, affinity
    sc += b"\x48\xb8" + struct.pack(
        "<Q", set_affinity_addr
    )  # movabs rax, SetWindowDisplayAffinity
    sc += b"\xff\xd0"  # call rax
    sc += b"\x89\xc1"  # mov ecx, eax (exit code = call result)
    sc += b"\x48\xb8" + struct.pack("<Q", exit_thread_addr)  # movabs rax, ExitThread
    sc += b"\xff\xd0"  # call rax
    sc += b"\xc3"  # ret
    return bytes(sc)


def build_shellcode_x86(
    affinity: int, set_affinity_addr: int, exit_thread_addr: int
) -> bytes:
    # x86 stdcall: SetWindowDisplayAffinity(hwnd=[esp+4], affinity), then ExitThread
    sc = bytearray()
    sc += b"\x8b\x44\x24\x04"  # mov eax, [esp+4]  (hwnd param from CreateRemoteThread)
    sc += b"\xba" + struct.pack("<I", affinity)  # mov edx, affinity
    sc += b"\x52"  # push edx (affinity)
    sc += b"\xff\x74\x24\x08"  # push [esp+8] (hwnd)
    sc += b"\xb8" + struct.pack(
        "<I", set_affinity_addr
    )  # mov eax, SetWindowDisplayAffinity
    sc += b"\xff\xd0"  # call eax
    sc += b"\x50"  # push eax (exit code = call result)
    sc += b"\xb8" + struct.pack("<I", exit_thread_addr)  # mov eax, ExitThread
    sc += b"\xff\xd0"  # call eax
    sc += b"\xc3"  # ret
    return bytes(sc)


def pe_export(
    path: str, name: str
) -> tuple[int, int, int, Callable[[int], int]] | None:
    """Export info of a function in a PE file: (rva, exp_start, exp_end, read_off).
    Returns None if not found. read_off(rva) maps an RVA to a file offset."""
    with open(path, "rb") as f:
        data = f.read()
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        return None
    num_sections = struct.unpack_from("<H", data, e_lfanew + 6)[0]
    size_opt = struct.unpack_from("<H", data, e_lfanew + 20)[0]
    opt_off = e_lfanew + 24
    magic = struct.unpack_from("<H", data, opt_off)[0]
    dd_off = opt_off + (96 if magic == 0x10B else 112)
    exp_rva, exp_size = struct.unpack_from("<II", data, dd_off)
    if not exp_rva:
        return None
    sec_off = opt_off + size_opt

    def read_off(rva):
        for i in range(num_sections):
            s = sec_off + 40 * i
            va, vsize, raw_off, raw_size = struct.unpack_from("<IIII", data, s + 12)
            if va <= rva < va + max(vsize, raw_size):
                return raw_off + (rva - va)
        return rva

    exp_off = read_off(exp_rva)
    num_names = struct.unpack_from("<I", data, exp_off + 24)[0]
    addr_funcs = read_off(struct.unpack_from("<I", data, exp_off + 28)[0])
    addr_names = read_off(struct.unpack_from("<I", data, exp_off + 32)[0])
    addr_ords = read_off(struct.unpack_from("<I", data, exp_off + 36)[0])
    target = name.encode()
    for i in range(num_names):
        name_off = read_off(struct.unpack_from("<I", data, addr_names + 4 * i)[0])
        end = data.find(b"\x00", name_off)
        if data[name_off:end] == target:
            ordinal = struct.unpack_from("<H", data, addr_ords + 2 * i)[0]
            rva = struct.unpack_from("<I", data, addr_funcs + 4 * ordinal)[0]
            return rva, exp_rva, exp_rva + exp_size, read_off
    return None


def resolve_x86_export(h: int, dll: str, func: str) -> int | None:
    """Absolute address of a function in a 32-bit target process (follows
    forwarded exports like kernel32!ExitThread -> KERNELBASE!ExitThread)."""
    syswow = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "SysWOW64")
    for _ in range(8):
        base = module_base(h, dll, LIST_MODULES_32BIT)
        if not base:
            return None
        path = os.path.join(syswow, dll)
        exp = pe_export(path, func)
        if not exp:
            return None
        rva, exp_start, exp_end, read_off = exp
        if not (exp_start <= rva < exp_end):
            return base + rva
        with open(path, "rb") as f:
            data = f.read()
        off = read_off(rva)
        end = data.find(b"\x00", off)
        fwd = data[off:end].decode("ascii", "replace")
        if "." not in fwd:
            return None
        dll, func = fwd.split(".", 1)
        dll = dll.lower() + ".dll"
    return None


def module_base(h: int, name: str, flags: int) -> int | None:
    """Base address of a loaded module in a process (psapi), or None."""
    needed = wintypes.DWORD()
    if not EnumProcessModulesEx(h, None, 0, ctypes.byref(needed), flags):
        return None
    count = needed.value // ctypes.sizeof(wintypes.HMODULE)
    mods = (wintypes.HMODULE * count)()
    if not EnumProcessModulesEx(
        h,
        ctypes.cast(mods, wintypes.LPVOID),
        needed.value,
        ctypes.byref(needed),
        flags,
    ):
        return None
    buf = ctypes.create_unicode_buffer(260)
    for m in mods:
        if GetModuleBaseNameW(h, m, buf, 260) and buf.value.lower() == name:
            return m
    return None


def resolve_x86_addresses(h: int) -> tuple[int, int]:
    """Resolve SetWindowDisplayAffinity/ExitThread in a 32-bit target process."""
    swda = resolve_x86_export(h, "user32.dll", "SetWindowDisplayAffinity")
    exit_thread = resolve_x86_export(h, "kernel32.dll", "ExitThread")
    if not swda or not exit_thread:
        raise OSError("unable to resolve x86 API addresses in target")
    return swda, exit_thread


def inject(hwnd: int, affinity: int) -> bool:
    """Call SetWindowDisplayAffinity from inside the target process (x64/x86 shellcode).
    Runs in-process to bypass the access denied (error 5) on cross-process calls."""
    if struct.calcsize("P") != 8:
        raise OSError("x64 injection requires a 64-bit Python.")

    swda = ctypes.cast(user32.SetWindowDisplayAffinity, ctypes.c_void_p).value
    exit_thread = ctypes.cast(kernel32.ExitThread, ctypes.c_void_p).value
    if not swda or not exit_thread:
        raise OSError("Unable to resolve API addresses.")
    shellcode = build_shellcode(affinity, swda, exit_thread)

    pid = wintypes.DWORD()
    GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    log.debug(
        "Injecting into PID %s (%d bytes of shellcode)", pid.value, len(shellcode)
    )

    remote = None
    with safe_handle(
        OpenProcess(
            PROCESS_CREATE_THREAD
            | PROCESS_VM_OPERATION
            | PROCESS_VM_READ
            | PROCESS_VM_WRITE,
            False,
            pid.value,
        )
    ) as h:
        if not h:
            raise OSError(f"OpenProcess failed (error {ctypes.get_last_error()})")
        try:
            is_wow64 = wintypes.BOOL()
            if IsWow64Process(h, ctypes.byref(is_wow64)) and is_wow64.value:
                shellcode = build_shellcode_x86(affinity, *resolve_x86_addresses(h))
                log.debug("Injected shellcode is x86 (%d bytes)", len(shellcode))
            else:
                shellcode = build_shellcode(affinity, swda, exit_thread)
            if process_suspended(pid.value):
                raise OSError(
                    "target process is suspended (background app); open it first"
                )

            remote = VirtualAllocEx(
                h,
                None,
                len(shellcode),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            )
            if not remote:
                raise OSError(
                    f"VirtualAllocEx failed (error {ctypes.get_last_error()})"
                )

            buf = ctypes.create_string_buffer(shellcode)
            written = ctypes.c_size_t()
            if not WriteProcessMemory(
                h, remote, buf, len(shellcode), ctypes.byref(written)
            ):
                raise OSError(
                    f"WriteProcessMemory failed (error {ctypes.get_last_error()})"
                )

            tid = wintypes.DWORD()
            with safe_handle(
                CreateRemoteThread(
                    h, None, 0, remote, ctypes.c_void_p(hwnd), 0, ctypes.byref(tid)
                )
            ) as thread:
                if not thread:
                    raise OSError(
                        f"CreateRemoteThread failed (error {ctypes.get_last_error()})"
                    )

                WaitForSingleObject(thread, 5000)
                code = wintypes.DWORD()
                GetExitCodeThread(thread, ctypes.byref(code))
                log.debug("Injected thread result: %s", code.value)
                if code.value == STILL_ACTIVE:
                    remote = None  # leave the stub: the thread may still run it
                    raise OSError(
                        "injected thread did not finish in time (process suspended?)"
                    )
                if code.value >= 0x80000000:
                    raise OSError(
                        f"injected thread crashed (exit code 0x{code.value:08X})"
                    )
                VirtualFreeEx(h, remote, 0, MEM_RELEASE)
                remote = None
                return bool(code.value)
        finally:
            if remote:
                VirtualFreeEx(h, remote, 0, MEM_RELEASE)


# ---------------------------------------------------------------- CLI


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Protect a window against screen capture (OBS, Discord...)"
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    target = parser.add_argument_group("target (otherwise interactive selection)")
    target.add_argument("-p", "--pid", type=int, help="process PID")
    target.add_argument("-n", "--name", help="exact process name (e.g. notepad)")
    target.add_argument("-t", "--title", help="window title substring")
    target.add_argument(
        "-a",
        "--all",
        action="store_true",
        help="apply to all windows matching the criteria",
    )

    action = parser.add_argument_group("action")
    action.add_argument(
        "-l", "--list", action="store_true", help="list windows and exit"
    )
    action.add_argument(
        "-s",
        "--status",
        action="store_true",
        help="show protection state without modifying",
    )
    action.add_argument(
        "-c", "--clear", action="store_true", help="remove protection (WDA_NONE)"
    )
    action.add_argument(
        "--check",
        action="store_true",
        help="check config targets and propose to inject the unprotected ones",
    )

    opt = parser.add_argument_group("options")
    opt.add_argument(
        "-x",
        "--inject",
        action="store_true",
        help="force in-process injection (no direct attempt)",
    )
    opt.add_argument(
        "--config",
        metavar="FILE",
        help="batch-protect from a file (one target per line, # comments)",
    )
    return parser.parse_args()


def load_config(path: str) -> list[str]:
    """Read targets from a config file (one per line, # comments allowed)."""
    with open(path, "r", encoding="utf-8") as f:
        lines = [ln.strip() for ln in f]
    return [ln for ln in lines if ln and not ln.startswith("#")]


def config_matches(windows: list[Window], path: str) -> list[Window]:
    """Windows matching any line of a config file (name or title substring)."""
    names = load_config(path)
    matched: list[Window] = []
    seen: set[int] = set()
    for name in names:
        needle = name.lower()
        for w in windows:
            if w.hwnd in seen:
                continue
            if needle in get_process_name(w.pid).lower() or needle in w.title.lower():
                seen.add(w.hwnd)
                matched.append(w)
    return matched


def find_targets(
    windows: list[Window], args: argparse.Namespace
) -> list[Window] | None:
    """Return the list of target windows according to the CLI criteria."""
    if args.pid:
        return [w for w in windows if w.pid == args.pid]
    if args.name:
        name = args.name.lower()
        return [w for w in windows if get_process_name(w.pid).lower() == name]
    if args.title:
        t = args.title.lower()
        return [w for w in windows if t in w.title.lower()]
    if args.all:
        return windows
    return None


def ask_yes_no(prompt: str) -> bool:
    """Ask a y/N question on the console (works after stdio rebinding)."""
    try:
        print(f"{prompt} ", end="")
        sys.stdout.flush()
        answer = msvcrt.getch().lower()
        print()
        return answer == b"y"
    except (EOFError, OSError):
        return False


def load_config_targets(windows: list[Window], path: str) -> list[Window] | None:
    """Config targets, or None if the file is missing (creation offered)."""
    try:
        return config_matches(windows, path)
    except OSError:
        log.error("Config file not found: %s", path)
        print(f"Config file not found: {path}")
        created = False
        if ask_yes_no("Create it now? (y/N)"):
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write("# one target per line (process name or window title)\n")
                print(f"Created {path} - add one target per line, then run again.")
                created = True
            except OSError:
                log.error("Unable to create config file: %s", path)
                print(f"Unable to create config file: {path}")
        wait_key()
        sys.exit(0 if created else 1)


def wait_key() -> None:
    """Keep the console open until a key is pressed."""
    try:
        print("\nPress any key to close...")
        msvcrt.getch()
    except (EOFError, OSError):
        pass


def main() -> int:
    args = parse_args()
    ensure_admin()
    setup_console_logging()
    log.debug("Arguments: %s", vars(args))

    windows = list_windows()
    log.debug("%d visible window(s)", len(windows))

    if args.list:
        print_windows(windows)
        return 0

    if args.config:
        targets = load_config_targets(windows, args.config)
        if not targets:
            print("No windows matched the config file.")
            wait_key()
            return 1
        log.debug("Config: %d window(s) matched", len(targets))
        ok = protect(targets, clear=args.clear, force_inject=args.inject)
        if ok:
            verb = "removed" if args.clear else "applied"
            print(
                f"[VERIFIED] Protection {verb} and verified for {len(targets)} window(s)."
            )
        wait_key()
        return 0 if ok else 1

    if args.check:
        path = args.config or "protect.txt"
        targets = load_config_targets(windows, path)
        if not targets:
            print("No windows matched the config file.")
            wait_key()
            return 1
        for name in load_config(path):
            needle = name.lower()
            hit = any(
                needle in get_process_name(w.pid).lower() or needle in w.title.lower()
                for w in windows
            )
            if not hit:
                print(f"[--] no window for: {name}")
        unprotected = [
            w for w in targets if window_affinity(w.hwnd) != WDA_EXCLUDEFROMCAPTURE
        ]
        for w in targets:
            if window_affinity(w.hwnd) == WDA_EXCLUDEFROMCAPTURE:
                print(f"[OK] '{w.title}' (pid {w.pid}) injected")
            else:
                print(f"[--] '{w.title}' (pid {w.pid}) not injected")
        if unprotected and ask_yes_no(
            f"Inject the {len(unprotected)} unprotected window(s)? (y/N)"
        ):
            ok = protect(unprotected, force_inject=args.inject)
            if ok:
                print(
                    f"[VERIFIED] Protection applied and verified "
                    f"for {len(unprotected)} window(s)."
                )
        wait_key()
        return 0

    targets = find_targets(windows, args)
    if targets is None:
        if not windows:
            print("No visible windows found.")
            return 1
        select_interactive(windows, args.config)
        return 0

    if not targets:
        print("No windows found.")
        return 1

    if args.status:
        show_status(targets)
        return 0

    log.debug("Selected target(s): %s", targets)
    ok = protect(targets, clear=args.clear, force_inject=args.inject)
    if ok:
        verb = "removed" if args.clear else "applied"
        print(
            f"[VERIFIED] Protection {verb} and verified for {len(targets)} window(s)."
        )
    wait_key()
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
