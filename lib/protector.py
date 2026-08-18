"""Protection actions: direct call and verified batch protection."""

import ctypes

from lib.core import (
    CHROMIUM_UNSUPPORTED,
    WDA_EXCLUDEFROMCAPTURE,
    WDA_NONE,
    SetWindowDisplayAffinity,
    Window,
    log,
)
from lib.injector import Injector
from lib.windows import WindowQuery


class Protector:
    """Apply or clear SetWindowDisplayAffinity on windows."""

    @staticmethod
    def apply_affinity(
        hwnd: int, affinity: int, force_inject: bool
    ) -> tuple[bool, str | None]:
        """Apply affinity directly, falling back to in-process injection."""
        if not force_inject:
            ok = SetWindowDisplayAffinity(hwnd, affinity)
            if ok:
                return True, "direct"
            err = ctypes.get_last_error()
            log.warning(
                "Direct call failed (error %s), trying in-process injection...", err
            )
        try:
            Injector.inject(hwnd, affinity)
            return True, "injection"
        except OSError as exc:
            log.error("Injection failed: %s", exc)
            return False, None

    @staticmethod
    def protect(
        windows: list[Window], clear: bool = False, force_inject: bool = False
    ) -> bool:
        """Protect (or clear) each window; report verified results only."""
        affinity = WDA_NONE if clear else WDA_EXCLUDEFROMCAPTURE
        ok = True
        for window in windows:
            title = window.title
            pid = window.pid
            if (
                not clear
                and WindowQuery.is_chromium(pid)
                and WindowQuery.window_affinity(window.hwnd) != WDA_EXCLUDEFROMCAPTURE
            ):
                ok = False
                print(f"[SKIP] '{title}' (pid {pid}) {CHROMIUM_UNSUPPORTED}")
                log.warning("SKIP: '%s' (pid %s) %s", title, pid, CHROMIUM_UNSUPPORTED)
                continue
            success, method = Protector.apply_affinity(
                window.hwnd, affinity, force_inject
            )
            state = WindowQuery.window_affinity(window.hwnd)
            if success and state == affinity:
                result = (
                    "injected" if affinity == WDA_EXCLUDEFROMCAPTURE else "uninjected"
                )
                print(f"[OK] ({method}) '{title}' (pid {pid}) {result}")
                log.info(
                    "OK (%s): '%s' (pid %s, hwnd %s) %s",
                    method,
                    title,
                    pid,
                    window.hwnd,
                    result,
                )
            else:
                ok = False
                print(f"[FAILED] '{title}' (pid {pid})")
        return ok
