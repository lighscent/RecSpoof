# RecSpoof

Windows tool that protects application windows against screen capture by applying `SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE)`.

Protected windows appear black or empty in capture tools, while remaining fully visible on screen.

## Requirements

- Windows 10/11 (64-bit)
- Python 3 (64-bit, 3.10+) — no third-party dependencies, only the standard library (`ctypes`)
- Administrator rights (a UAC prompt appears on launch; the elevated process reattaches to the same console)

## Usage

```
python recspoof.py                       interactive selection, then protect
python recspoof.py -l                    list windows and their state
python recspoof.py -s -t Discord         show state without modifying
python recspoof.py -n notepad            protect by process name
python recspoof.py -t Discord -c         remove protection
python recspoof.py -n brave -a           protect all matching windows
python recspoof.py -p 1234 -x            force in-process injection
```

### Options

| Option | Description |
| --- | --- |
| `-p, --pid` | Target a window by process ID (exact) |
| `-n, --name` | Target by process name (exact) |
| `-t, --title` | Target by window title (substring) |
| `-a, --all` | Apply to all matching windows |
| `-l, --list` | List windows and their protection state |
| `-s, --status` | Show protection state only (no elevation) |
| `-c, --clear` | Remove protection (`WDA_NONE`) |
| `-x, --inject` | Force in-process injection instead of the direct call |

### Interactive menu

When launched without criteria, an arrow-key menu shows every visible window:

- `Up` / `Down` — navigate the list (rows already protected are cyan)
- `Enter` — protect the selected window (result shown in the status line at the bottom)
- `a` — protect all windows
- `r` — refresh the window list
- `q` / `Ctrl+C` — quit (closes the script immediately)

The `INJ` column indicates windows that cannot be protected safely (see below).

## How it works

1. Enumerates visible windows (`EnumWindows`).
2. Tries the direct call: `SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE)`.
3. If the direct call is denied (`ERROR_ACCESS_DENIED`), it falls back to **in-process injection**: a small shellcode stub is written into the target process (`VirtualAllocEx` + `WriteProcessMemory`), a remote thread calls `SetWindowDisplayAffinity` with the window handle, and the thread exits via `ExitThread`.
4. The result is verified by reading the affinity back (`GetWindowDisplayAffinity`); `[OK]` is only reported when the state actually changed.

Both 64-bit and 32-bit (WOW64) target processes are supported. For 32-bit targets, the shellcode uses the x86 `stdcall` convention and API addresses are resolved from the `SysWOW64` PE export tables (including forwarded exports like `kernel32!ExitThread` → `KERNELBASE!ExitThread`).

## Limitations

- **Chromium-based browsers** (`chrome`, `brave`, `edge`, `opera`, `vivaldi`, `chromium`) cannot be protected by this tool: the direct call is denied by Windows (error 5, even elevated), and creating a remote thread in the browser process crashes it. They are marked `unsupported` in the window list.
- Suspended background apps (e.g. some UWP apps like Calculator) cannot be protected until they are brought to the foreground; the script reports the failure instead of hanging.
- A protected window shows up black/frozen in capture tools by design — restart or re-select the OBS/Discord source once after protecting to get a clean result.