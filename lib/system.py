"""Console, logging and elevation helpers."""

from __future__ import annotations

import ctypes
import logging
import msvcrt
import os
import subprocess
import sys
from ctypes import wintypes

from lib.core import (
    ATTACH_PARENT_PROCESS,
    ENABLE_VIRTUAL_TERMINAL_PROCESSING,
    SEE_MASK_NO_CONSOLE,
    SEE_MASK_NOCLOSEPROCESS,
    SHELLEXECUTEINFOW,
    STD_ERROR_HANDLE,
    STD_INPUT_HANDLE,
    STD_OUTPUT_HANDLE,
    AllocConsole,
    AttachConsole,
    GetConsoleMode,
    GetExitCodeProcess,
    GetStdHandle,
    IsUserAnAdmin,
    SetConsoleMode,
    SetStdHandle,
    ShellExecuteExW,
    WaitForSingleObject,
    log,
    safe_handle,
)


class System:
    """Console, logging and elevation helpers."""

    @staticmethod
    def enable_ansi() -> None:
        """Enable ANSI color sequences on the Windows console."""
        h = GetStdHandle(STD_OUTPUT_HANDLE)
        mode = wintypes.DWORD()
        if GetConsoleMode(h, ctypes.byref(mode)):
            SetConsoleMode(h, mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING)

    @staticmethod
    def setup_console_logging() -> None:
        """Configure console-only logging (WARNING and above)."""
        stream = logging.StreamHandler()
        stream.setLevel(logging.WARNING)
        logging.basicConfig(
            level=logging.WARNING,
            format="%(levelname)s: %(message)s",
            handlers=[stream],
        )

    @staticmethod
    def set_console_logging(level: int) -> None:
        """Set the console log level (WARNING and above only)."""
        for logger in (logging.getLogger(), log):
            for handler in logger.handlers:
                if type(handler) is logging.StreamHandler:
                    handler.setLevel(level)

    @staticmethod
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

    @staticmethod
    def attach_parent_console() -> None:
        """Attach to the console of the launching process (UAC relaunch)."""
        attached = bool(AttachConsole(ATTACH_PARENT_PROCESS))
        if not attached:
            attached = bool(AllocConsole())
        if attached:
            System.rebind_console_stdio()

    @staticmethod
    def relaunch_elevated() -> int:
        """Relaunch elevated via UAC, then wait for it in the same console."""
        script = os.path.abspath(sys.argv[0])
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

    @staticmethod
    def ensure_admin() -> None:
        """Request UAC elevation at launch, keeping the same console window."""
        if IsUserAnAdmin():
            System.attach_parent_console()
            return
        sys.exit(System.relaunch_elevated())

    @staticmethod
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

    @staticmethod
    def wait_key() -> None:
        """Keep the console open until a key is pressed."""
        try:
            print("\nPress any key to close...")
            msvcrt.getch()
        except (EOFError, OSError):
            pass
