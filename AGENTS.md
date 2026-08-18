# AGENTS.md

## Project

Single-file Windows tool (`recspoof.py`) that hides app windows from screen capture (OBS, Discord) via `SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)`. Zero third-party dependencies (ctypes only). No tests, no build. Python 3.10+ — **64-bit Python required** (`inject()` raises on 32-bit Python).

## Commands

- Lint/format: `python -m ruff check recspoof.py` then `python -m ruff format recspoof.py` (ruff installed globally; run after every change, must end 0 errors)
- Sanity check: `python -c "import recspoof"` (module import works)

## Testing gotchas (critical)

- **Never run `python recspoof.py` from the opencode tool shell**: `main()` calls `ensure_admin()` first, which relaunches via UAC into a new console — the tool shell captures no output. Test logic via direct calls instead:
  `import recspoof; recspoof.print_windows(recspoof.list_windows())`, `recspoof.apply_affinity(hwnd, 0x11, True)`, etc.
- The interactive menu (`select_interactive`) is msvcrt-based and cannot be auto-tested.
- PowerShell 5.1 cannot parse inline `python -c` strings containing `{`/`%` — write temp `.py` files (in `C:\Users\x\AppData\Local\Temp\opencode`) instead.
- Live injection tests crash nothing on normal apps (notepad, Electron, voicemeeter) but **Chromium browsers crash on ANY remote thread** — never inject into them.

## Architecture notes

- `Window = tuple[int, int, str]` (hwnd, pid, title); `api(dll, name, restype, *argtypes)` wraps ctypes bindings.
- Injection: `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread` with shellcode that calls `SetWindowDisplayAffinity` then `ExitThread`; exit code = call result (thread's `mov ecx, eax`). x86 (WOW64) targets use stdcall stack args and PE-export resolution with **forwarded export chasing** (`kernel32!ExitThread` → `KERNELBASE!ExitThread`).
- Injection guards: `process_suspended(pid)` (Toolhelp `THREAD_SUSPENDED`), `STILL_ACTIVE` (259) after 5 s wait, exit codes ≥ 0x80000000 = crash.
- `[OK]` is only printed when a follow-up `window_affinity()` read-back matches the requested state.
- Chromium browsers (CHROMIUM frozenset) are marked `unsupported` in the INJ column and SKIPPED by `protect_one()`/`protect()` — direct call fails error 5 even elevated, injection crashes the process.
- `main()` order: `parse_args` → `ensure_admin` (UAC, same-console via `ShellExecuteExW` + `AttachConsole`) → `setup_console_logging` (console-only, WARNING+, no log files).

## Conventions

- User-facing strings are English; window state is labeled `injected` / `not injected` (NOT "protected").
- Interactive menu: absolute ANSI row positioning (`\x1b[{row}H\x1b[K`), live re-rendered rows from `states` cache, status line at bottom, console logging silenced (CRITICAL) during the menu, restored after.
- Comments and messages ASCII-only. Console mojibake for non-ASCII window titles is cosmetic/accepted.
- Script was renamed `maskapp.py` → `recspoof.py`; git remote is `origin` = `https://github.com/lighscent/RecSpoof.git`, branch `master`. Commit/push only on explicit request.