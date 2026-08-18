"""In-process shellcode injection (x64 and x86/WOW64)."""

from __future__ import annotations

import ctypes
import os
import struct
from collections.abc import Callable
from ctypes import wintypes

from lib.core import (
    LIST_MODULES_32BIT,
    MEM_COMMIT,
    MEM_RELEASE,
    MEM_RESERVE,
    PAGE_EXECUTE_READWRITE,
    PROCESS_CREATE_THREAD,
    PROCESS_VM_OPERATION,
    PROCESS_VM_READ,
    PROCESS_VM_WRITE,
    STILL_ACTIVE,
    CreateRemoteThread,
    EnumProcessModulesEx,
    GetExitCodeThread,
    GetModuleBaseNameW,
    GetWindowThreadProcessId,
    IsWow64Process,
    OpenProcess,
    VirtualAllocEx,
    VirtualFreeEx,
    WaitForSingleObject,
    WriteProcessMemory,
    kernel32,
    log,
    safe_handle,
    user32,
)
from lib.windows import WindowQuery


class Injector:
    """Shellcode builders and remote-thread injection."""

    @staticmethod
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
        sc += b"\x48\xb8" + struct.pack(
            "<Q", exit_thread_addr
        )  # movabs rax, ExitThread
        sc += b"\xff\xd0"  # call rax
        sc += b"\xc3"  # ret
        return bytes(sc)

    @staticmethod
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

    @staticmethod
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

    @staticmethod
    def resolve_x86_export(h: int, dll: str, func: str) -> int | None:
        """Absolute address of a function in a 32-bit target process (follows
        forwarded exports like kernel32!ExitThread -> KERNELBASE!ExitThread)."""
        syswow = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "SysWOW64")
        for _ in range(8):
            base = Injector.module_base(h, dll, LIST_MODULES_32BIT)
            if not base:
                return None
            path = os.path.join(syswow, dll)
            exp = Injector.pe_export(path, func)
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

    @staticmethod
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

    @staticmethod
    def resolve_x86_addresses(h: int) -> tuple[int, int]:
        """Resolve SetWindowDisplayAffinity/ExitThread in a 32-bit target process."""
        swda = Injector.resolve_x86_export(h, "user32.dll", "SetWindowDisplayAffinity")
        exit_thread = Injector.resolve_x86_export(h, "kernel32.dll", "ExitThread")
        if not swda or not exit_thread:
            raise OSError("unable to resolve x86 API addresses in target")
        return swda, exit_thread

    @staticmethod
    def inject(hwnd: int, affinity: int) -> bool:
        """Call SetWindowDisplayAffinity from inside the target process (x64/x86 shellcode).
        Runs in-process to bypass the access denied (error 5) on cross-process calls."""
        if struct.calcsize("P") != 8:
            raise OSError("x64 injection requires a 64-bit Python.")

        swda = ctypes.cast(user32.SetWindowDisplayAffinity, ctypes.c_void_p).value
        exit_thread = ctypes.cast(kernel32.ExitThread, ctypes.c_void_p).value
        if not swda or not exit_thread:
            raise OSError("Unable to resolve API addresses.")
        shellcode = Injector.build_shellcode(affinity, swda, exit_thread)

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
                    shellcode = Injector.build_shellcode_x86(
                        affinity, *Injector.resolve_x86_addresses(h)
                    )
                    log.debug("Injected shellcode is x86 (%d bytes)", len(shellcode))
                else:
                    shellcode = Injector.build_shellcode(affinity, swda, exit_thread)
                if WindowQuery.process_suspended(pid.value):
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
