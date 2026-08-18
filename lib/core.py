"""Core: Window model, constants, ctypes bindings, safe_handle."""

from __future__ import annotations

import ctypes
import logging
from contextlib import contextmanager
from ctypes import wintypes
from dataclasses import dataclass
from typing import Any

log = logging.getLogger("recspoof")


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


@contextmanager
def safe_handle(handle: wintypes.HANDLE) -> Any:
    """Close a Win32 handle on exit, even on exception."""
    try:
        yield handle
    finally:
        if handle and handle != INVALID_HANDLE_VALUE:
            CloseHandle(handle)
