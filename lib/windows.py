"""Window and process queries."""

from __future__ import annotations

import ctypes
import functools
import os
from ctypes import wintypes

from lib.core import (
    AFFINITY_NAMES,
    CHROMIUM,
    INVALID_HANDLE_VALUE,
    PROCESS_QUERY_LIMITED_INFORMATION,
    TH32CS_SNAPTHREAD,
    THREAD_SUSPENDED,
    THREADENTRY32,
    CreateToolhelp32Snapshot,
    EnumWindows,
    EnumWindowsProc,
    GetWindowDisplayAffinity,
    GetWindowTextLengthW,
    GetWindowTextW,
    GetWindowThreadProcessId,
    IsWindowVisible,
    OpenProcess,
    QueryFullProcessImageNameW,
    Thread32First,
    Thread32Next,
    Window,
    safe_handle,
)


class WindowQuery:
    """Window and process queries."""

    @staticmethod
    def get_window_title(hwnd: int) -> str:
        length = GetWindowTextLengthW(hwnd)
        if length == 0:
            return ""
        buf = ctypes.create_unicode_buffer(length + 1)
        GetWindowTextW(hwnd, buf, length + 1)
        return buf.value

    @staticmethod
    @functools.lru_cache(maxsize=256)
    def get_process_name(pid: int) -> str:
        with safe_handle(
            OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        ) as h:
            if not h:
                return f"pid {pid}"
            size = wintypes.DWORD(260)
            buf = ctypes.create_unicode_buffer(260)
            if QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
                return os.path.basename(buf.value)
            return f"pid {pid}"

    @staticmethod
    def list_windows() -> list[Window]:
        windows: list[Window] = []

        @EnumWindowsProc
        def callback(hwnd, lparam) -> bool:
            if IsWindowVisible(hwnd):
                title = WindowQuery.get_window_title(hwnd)
                if title:
                    pid = wintypes.DWORD()
                    GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
                    windows.append(Window(hwnd, pid.value, title))
            return True

        EnumWindows(callback, 0)
        return windows

    @staticmethod
    def window_affinity(hwnd: int) -> int | None:
        state = wintypes.UINT()
        if GetWindowDisplayAffinity(hwnd, ctypes.byref(state)):
            return state.value
        return None

    @staticmethod
    def affinity_label(hwnd: int, state: int | None = None) -> str:
        if state is None:
            state = WindowQuery.window_affinity(hwnd)
        if state is None:
            return "?"
        return AFFINITY_NAMES.get(state, f"unknown ({state})")

    @staticmethod
    def is_chromium(pid: int) -> bool:
        name = os.path.splitext(WindowQuery.get_process_name(pid))[0].lower()
        return name in CHROMIUM

    @staticmethod
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
