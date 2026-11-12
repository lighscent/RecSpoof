# RecSpoof

Windows tool that protects application windows against screen capture by applying `SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE)`.

Protected windows appear black or empty in capture tools, while remaining fully visible on screen.

## Requirements

- Windows 10/11 (64-bit)
- CMake 3.25+ and MSVC (Visual Studio 2022 Build Tools are enough) to build — the result is a single `RecSpoof.exe` with no runtime dependencies
- Administrator rights: the tool elevates itself, and opens exactly one console window for the interface (the same one when launched from an existing terminal)

## Build

```
cmake -S . -B build -G Ninja
cmake --build build
```

Run the checks with `ctest --test-dir build --output-on-failure`. The executable is `build/RecSpoof.exe`.

## Structure

```
src/main.cpp                  argument parsing and dispatch
src/platform/WindowsAPI.cpp   console, elevation, UTF-8 output, RAII handles
src/core/WindowManager.cpp    window enumeration, affinity read/write
src/core/ProcessManager.cpp   process names, Chromium detection, WOW64, suspended threads
src/core/ProtectionManager.cpp  direct call, x64/x86 injection, PE export reader
src/config/ConfigManager.cpp  protect.txt parsing, matching, create prompt
src/ui/ConsoleUI.cpp          window table and the arrow-key menu
include/                      headers for the above
tests/selfcheck.cpp           PE export reader and shellcode encoder checks
```

## Usage

```
RecSpoof.exe                       interactive selection, then protect
RecSpoof.exe -l                    list windows and their state
RecSpoof.exe -s -t Discord         show state without modifying
RecSpoof.exe -n notepad            protect by process name
RecSpoof.exe -t Discord -c         remove protection
RecSpoof.exe -n brave -a           protect all matching windows
RecSpoof.exe -p 1234 -x            force in-process injection
RecSpoof.exe --config protect.txt  batch-protect from a file
RecSpoof.exe --check               check config targets, inject the rest
```

### Options

| Option | Description |
| ---------------- | ----------- |
| `-p, --pid <PID>` | Target a window by process ID (exact) |
| `-n, --name <NAME>` | Target by process name (exact) |
| `-t, --title <TITLE>` | Target by window title (substring) |
| `-a, --all` | Apply to all matching windows |
| `-l, --list` | List windows and their injection state |
| `-s, --status` | Show injection state only (no elevation) |
| `-c, --clear` | Remove injection (`WDA_NONE`) |
| `-x, --inject` | Force in-process injection instead of the direct call |
| `--config <FILE>` | Batch-protect from a file: one target per line (`#` comments allowed), each line matches process name or window title (substring, case-insensitive). If the file does not exist, the tool offers to create it. |
| `--check` | Check the config targets: reports injected / not injected windows, apps that are not running, then offers to inject the unprotected ones (uses `--config FILE`, or `protect.txt` by default) |
| `--version` | Print the version |
| `-h, --help` | Print the help text |

Example `protect.txt`:

```
# my streaming setup
discord
obs
voicemeeter
```

### Interactive menu

When launched without criteria, an arrow-key menu shows every visible window:

- `Up` / `Down` — navigate the list (rows already injected are cyan)
- `Enter` — inject the selected window (result shown in the status line at the bottom)
- `a` — inject all windows
- `s` — add the selected window to the config file (`protect.txt` by default, or the `--config` file)
- `r` — refresh the window list
- `q` / `Ctrl+C` — quit (closes the tool immediately)

The `INJ` column indicates windows that cannot be injected safely (see below).

## How it works

1. Enumerates visible windows (`EnumWindows`).
2. Tries the direct call: `SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE)`.
3. If the direct call is denied (`ERROR_ACCESS_DENIED`), it falls back to **in-process injection**: a small shellcode stub is written into the target process (`VirtualAllocEx` + `WriteProcessMemory`), a remote thread calls `SetWindowDisplayAffinity` with the window handle, and the thread exits via `ExitThread`.
4. The result is verified by reading the affinity back (`GetWindowDisplayAffinity`); `[OK]` is only reported when the state actually changed.

Both 64-bit and 32-bit (WOW64) target processes are supported. For 32-bit targets, the shellcode uses the x86 `stdcall` convention and API addresses are resolved from the `SysWOW64` PE export tables (including forwarded exports like `kernel32!ExitThread` → `KERNELBASE!ExitThread`).

## Limitations

- **Chromium-based browsers** (`chrome`, `brave`, `edge`, `opera`, `vivaldi`, `chromium`) cannot be protected by this tool: the direct call is denied by Windows (error 5, even elevated), and creating a remote thread in the browser process crashes it. They are marked `unsupported` in the window list.
- Suspended background apps (e.g. some UWP apps like Calculator) cannot be protected until they are brought to the foreground; the tool reports the failure instead of hanging.
- A window that was injected shows up black/frozen in capture tools by design — restart or re-select the OBS/Discord source once after injecting to get a clean result.
