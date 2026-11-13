#include "ProtectionManager.hpp"

#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iterator>
#include <stdexcept>

#include "ProcessManager.hpp"
#include "WindowsAPI.hpp"

namespace recspoof {
namespace {

constexpr DWORD kInjectAccess =
    PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE;
constexpr DWORD kStillActive = 259;

template <typename T>
std::optional<T> read_at(const std::vector<uint8_t>& data, size_t offset) {
    if (offset > data.size() || data.size() - offset < sizeof(T)) return std::nullopt;
    T value;
    std::memcpy(&value, data.data() + offset, sizeof(T));
    return value;
}

std::optional<std::vector<uint8_t>> read_file(const std::wstring& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) return std::nullopt;
    return std::vector<uint8_t>(std::istreambuf_iterator<char>(file),
                                std::istreambuf_iterator<char>());
}

struct PeExport {
    uint32_t rva = 0;
    bool forwarded = false;
    std::string forwarder;  // "KERNELBASE.ExitThread"
};

// Reads an export from a PE image on disk, detecting forwarded exports.
std::optional<PeExport> read_export(const std::vector<uint8_t>& data, const std::string& name) {
    const auto pe_offset = read_at<uint32_t>(data, 0x3C);
    if (!pe_offset) return std::nullopt;
    if (data.size() < *pe_offset + 4 || std::memcmp(data.data() + *pe_offset, "PE\0\0", 4) != 0)
        return std::nullopt;

    const auto num_sections = read_at<uint16_t>(data, *pe_offset + 6);
    const auto size_opt = read_at<uint16_t>(data, *pe_offset + 20);
    if (!num_sections || !size_opt) return std::nullopt;

    const size_t opt_off = *pe_offset + 24;
    const auto magic = read_at<uint16_t>(data, opt_off);
    if (!magic) return std::nullopt;

    const size_t dd_off = opt_off + (*magic == 0x10B ? 96 : 112);
    const auto exp_rva = read_at<uint32_t>(data, dd_off);
    const auto exp_size = read_at<uint32_t>(data, dd_off + 4);
    if (!exp_rva || !exp_size || *exp_rva == 0) return std::nullopt;

    const size_t sec_off = opt_off + *size_opt;
    const auto file_offset = [&data, sec_off, &num_sections](uint32_t rva) -> std::optional<uint32_t> {
        for (uint16_t i = 0; i < *num_sections; ++i) {
            const size_t section = sec_off + 40 * static_cast<size_t>(i);
            const auto va = read_at<uint32_t>(data, section + 12);
            const auto vsize = read_at<uint32_t>(data, section + 16);
            const auto raw_off = read_at<uint32_t>(data, section + 20);
            const auto raw_size = read_at<uint32_t>(data, section + 24);
            if (!va || !vsize || !raw_off || !raw_size) return std::nullopt;
            const uint32_t span = std::max(*vsize, *raw_size);
            if (*va <= rva && rva < *va + span) return *raw_off + (rva - *va);
        }
        return rva;
    };

    const auto exp_off = file_offset(*exp_rva);
    if (!exp_off) return std::nullopt;
    const auto num_names = read_at<uint32_t>(data, *exp_off + 24);
    const auto funcs_rva = read_at<uint32_t>(data, *exp_off + 28);
    const auto names_rva = read_at<uint32_t>(data, *exp_off + 32);
    const auto ords_rva = read_at<uint32_t>(data, *exp_off + 36);
    if (!num_names || !funcs_rva || !names_rva || !ords_rva) return std::nullopt;
    const auto funcs = file_offset(*funcs_rva);
    const auto names = file_offset(*names_rva);
    const auto ords = file_offset(*ords_rva);
    if (!funcs || !names || !ords) return std::nullopt;

    for (uint32_t i = 0; i < *num_names; ++i) {
        const auto name_rva = read_at<uint32_t>(data, *names + 4 * static_cast<size_t>(i));
        if (!name_rva) return std::nullopt;
        const auto name_off = file_offset(*name_rva);
        if (!name_off) return std::nullopt;

        size_t end = *name_off;
        while (end < data.size() && data[end] != 0) ++end;
        if (end == data.size()) return std::nullopt;
        if (std::string(data.begin() + *name_off, data.begin() + end) != name) continue;

        const auto ordinal = read_at<uint16_t>(data, *ords + 2 * static_cast<size_t>(i));
        if (!ordinal) return std::nullopt;
        const auto rva = read_at<uint32_t>(data, *funcs + 4 * static_cast<size_t>(*ordinal));
        if (!rva) return std::nullopt;

        PeExport found{*rva, false, {}};
        if (*exp_rva <= *rva && *rva < *exp_rva + *exp_size) {
            const auto forwarder_off = file_offset(*rva);
            if (!forwarder_off) return std::nullopt;
            size_t forwarder_end = *forwarder_off;
            while (forwarder_end < data.size() && data[forwarder_end] != 0) ++forwarder_end;
            if (forwarder_end == data.size()) return std::nullopt;
            found.forwarded = true;
            found.forwarder.assign(data.begin() + *forwarder_off, data.begin() + forwarder_end);
        }
        return found;
    }
    return std::nullopt;
}

std::wstring syswow64_dir() {
    wchar_t buffer[MAX_PATH];
    const UINT length = GetSystemWow64DirectoryW(buffer, MAX_PATH);
    if (length == 0) return L"C:\\Windows\\SysWOW64";
    return std::wstring(buffer, length);
}

std::optional<uint64_t> module_base(HANDLE process, const std::wstring& name) {
    DWORD needed = 0;
    if (!EnumProcessModulesEx(process, nullptr, 0, &needed, LIST_MODULES_32BIT)) return std::nullopt;
    if (needed == 0) return std::nullopt;

    std::vector<HMODULE> modules(needed / sizeof(HMODULE));
    if (!EnumProcessModulesEx(process, modules.data(), needed, &needed, LIST_MODULES_32BIT))
        return std::nullopt;

    wchar_t buffer[MAX_PATH];
    const std::wstring wanted = lower(name);
    for (const HMODULE module : modules) {
        if (!GetModuleBaseNameW(process, module, buffer, MAX_PATH)) continue;
        if (lower(buffer) == wanted) return reinterpret_cast<uint64_t>(module);
    }
    return std::nullopt;
}

// Absolute address of a function in a 32-bit target process; follows forwarded
// exports such as kernel32!ExitThread -> KERNELBASE!ExitThread.
std::optional<uint64_t> resolve_x86_export(HANDLE process, std::wstring dll, std::string function) {
    const std::wstring directory = syswow64_dir();
    for (int attempt = 0; attempt < 8; ++attempt) {
        const auto base = module_base(process, dll);
        if (!base) return std::nullopt;
        const auto image = read_file(directory + L"\\" + dll);
        if (!image) return std::nullopt;
        const auto exported = read_export(*image, function);
        if (!exported) return std::nullopt;
        if (!exported->forwarded) return *base + exported->rva;

        const size_t dot = exported->forwarder.find('.');
        if (dot == std::string::npos) return std::nullopt;
        dll = lower(widen(exported->forwarder.substr(0, dot))) + L".dll";
        function = exported->forwarder.substr(dot + 1);
    }
    return std::nullopt;
}

void append64(std::vector<uint8_t>& code, uint64_t value) {
    for (int i = 0; i < 8; ++i) code.push_back(static_cast<uint8_t>(value >> (8 * i)));
}

void append32(std::vector<uint8_t>& code, uint32_t value) {
    for (int i = 0; i < 4; ++i) code.push_back(static_cast<uint8_t>(value >> (8 * i)));
}

uint64_t own_address(const wchar_t* dll, const char* name) {
    HMODULE module = GetModuleHandleW(dll);
    return module ? reinterpret_cast<uint64_t>(GetProcAddress(module, name)) : 0;
}

std::wstring thread_exit_code(DWORD code) {
    wchar_t buffer[16];
    std::swprintf(buffer, 16, L"0x%08X", code);
    return buffer;
}

bool inject(HWND hwnd, UINT affinity) {
    static_assert(sizeof(void*) == 8, "injection requires a 64-bit build");

    const uint64_t set_affinity64 = own_address(L"user32.dll", "SetWindowDisplayAffinity");
    const uint64_t exit_thread64 = own_address(L"kernel32.dll", "ExitThread");
    if (!set_affinity64 || !exit_thread64) throw std::runtime_error("Unable to resolve API addresses.");

    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    UniqueHandle process(OpenProcess(kInjectAccess, FALSE, pid));
    if (!process) {
        throw std::runtime_error("OpenProcess failed (" +
                                 narrow(format_error(GetLastError())) + ")");
    }
    if (process_suspended(pid)) {
        throw std::runtime_error("target process is suspended (background app); open it first");
    }

    std::vector<uint8_t> shellcode;
    if (is_wow64(process.get())) {
        const auto set_affinity =
            resolve_x86_export(process.get(), L"user32.dll", "SetWindowDisplayAffinity");
        const auto exit_thread = resolve_x86_export(process.get(), L"kernel32.dll", "ExitThread");
        if (!set_affinity || !exit_thread) {
            throw std::runtime_error("unable to resolve x86 API addresses in target");
        }
        shellcode = build_shellcode_x86(affinity, static_cast<uint32_t>(*set_affinity),
                                        static_cast<uint32_t>(*exit_thread));
    } else {
        shellcode = build_shellcode_x64(affinity, set_affinity64, exit_thread64);
    }

    void* remote = VirtualAllocEx(process.get(), nullptr, shellcode.size(),
                                  MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote) {
        throw std::runtime_error("VirtualAllocEx failed (" +
                                 narrow(format_error(GetLastError())) + ")");
    }

    try {
        SIZE_T written = 0;
        if (!WriteProcessMemory(process.get(), remote, shellcode.data(), shellcode.size(), &written)) {
            throw std::runtime_error("WriteProcessMemory failed (" +
                                     narrow(format_error(GetLastError())) + ")");
        }

        UniqueHandle thread(CreateRemoteThread(
            process.get(), nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(remote),
            reinterpret_cast<LPVOID>(hwnd), 0, nullptr));
        if (!thread) {
            throw std::runtime_error("CreateRemoteThread failed (" +
                                     narrow(format_error(GetLastError())) + ")");
        }

        WaitForSingleObject(thread.get(), 5000);
        DWORD code = 0;
        GetExitCodeThread(thread.get(), &code);
        if (code == kStillActive) {
            // Leave the stub: the thread may still run it.
            remote = nullptr;
            throw std::runtime_error("injected thread did not finish in time (process suspended?)");
        }
        if (code >= 0x80000000u) {
            throw std::runtime_error("injected thread crashed (exit code " +
                                     narrow(thread_exit_code(code)) + ")");
        }

        VirtualFreeEx(process.get(), remote, 0, MEM_RELEASE);
        remote = nullptr;
        return code != 0;
    } catch (...) {
        if (remote) VirtualFreeEx(process.get(), remote, 0, MEM_RELEASE);
        throw;
    }
}

}  // namespace

std::vector<uint8_t> build_shellcode_x64(UINT affinity, uint64_t set_affinity,
                                         uint64_t exit_thread) {
    // SetWindowDisplayAffinity(hwnd=RCX, affinity), then ExitThread(result).
    std::vector<uint8_t> code;
    code.insert(code.end(), {0x48, 0xBA});
    append64(code, affinity);  // movabs rdx, affinity
    code.insert(code.end(), {0x48, 0xB8});
    append64(code, set_affinity);  // movabs rax, SetWindowDisplayAffinity
    code.insert(code.end(), {0xFF, 0xD0});  // call rax
    code.insert(code.end(), {0x89, 0xC1});  // mov ecx, eax (exit code = call result)
    code.insert(code.end(), {0x48, 0xB8});
    append64(code, exit_thread);            // movabs rax, ExitThread
    code.insert(code.end(), {0xFF, 0xD0, 0xC3});  // call rax; ret
    return code;
}

std::vector<uint8_t> build_shellcode_x86(UINT affinity, uint32_t set_affinity,
                                         uint32_t exit_thread) {
    // stdcall: SetWindowDisplayAffinity(hwnd=[esp+4], affinity), then ExitThread.
    std::vector<uint8_t> code;
    code.insert(code.end(), {0x8B, 0x44, 0x24, 0x04});  // mov eax, [esp+4] (hwnd)
    code.insert(code.end(), {0xBA});
    append32(code, affinity);                     // mov edx, affinity
    code.insert(code.end(), {0x52});              // push edx (affinity)
    code.insert(code.end(), {0xFF, 0x74, 0x24, 0x08});  // push [esp+8] (hwnd)
    code.insert(code.end(), {0xB8});
    append32(code, set_affinity);                 // mov eax, SetWindowDisplayAffinity
    code.insert(code.end(), {0xFF, 0xD0});        // call eax
    code.insert(code.end(), {0x50});              // push eax (exit code = call result)
    code.insert(code.end(), {0xB8});
    append32(code, exit_thread);                  // mov eax, ExitThread
    code.insert(code.end(), {0xFF, 0xD0, 0xC3});  // call eax; ret
    return code;
}

std::optional<uint32_t> pe_export_rva(const std::wstring& path, const std::string& name) {
    const auto image = read_file(path);
    if (!image) return std::nullopt;
    const auto exported = read_export(*image, name);
    if (!exported) return std::nullopt;
    return exported->rva;
}

std::pair<bool, const char*> apply_affinity(HWND hwnd, UINT affinity, bool force_inject) {
    if (!force_inject) {
        if (SetWindowDisplayAffinity(hwnd, affinity)) return {true, "direct"};
        warn(L"Direct call failed (" + format_error(GetLastError()) +
             L"), trying in-process injection...");
    }
    try {
        inject(hwnd, affinity);
        return {true, "injection"};
    } catch (const std::exception& error) {
        warn(L"Injection failed: " + widen(error.what()));
        return {false, nullptr};
    }
}

bool protect(const std::vector<Window>& windows, bool clear, bool force_inject) {
    const UINT affinity = clear ? kAffinityNone : kExcludeFromCapture;
    bool ok = true;
    for (const Window& window : windows) {
        const std::wstring where = L"'" + window.title + L"' (pid " + std::to_wstring(window.pid) + L")";
        if (!clear && is_chromium(window.pid) &&
            window_affinity(window.hwnd) != kExcludeFromCapture) {
            ok = false;
            write_line(L"[SKIP] " + where + L" " + CHROMIUM_UNSUPPORTED);
            warn(L"SKIP: " + where + L" " + CHROMIUM_UNSUPPORTED);
            continue;
        }
        const auto [success, method] = apply_affinity(window.hwnd, affinity, force_inject);
        const auto state = window_affinity(window.hwnd);
        if (success && state && *state == affinity) {
            write_line(L"[OK] (" + widen(method) + L") " + where + L" " +
                       (clear ? L"uninjected" : L"injected"));
        } else {
            ok = false;
            write_line(L"[FAILED] " + where);
        }
    }
    return ok;
}

}  // namespace recspoof
