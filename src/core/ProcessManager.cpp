#include "ProcessManager.hpp"

#include <windows.h>
#include <tlhelp32.h>

#include <map>

#include "WindowsAPI.hpp"

namespace recspoof {
namespace {

constexpr const wchar_t* const kChromium[] = {L"chrome",  L"brave",  L"msedge",
                                             L"opera",   L"vivaldi", L"chromium"};
constexpr DWORD kThreadSuspended = 0x0004;

std::wstring strip_extension(std::wstring name) {
    const size_t dot = name.find_last_of(L'.');
    if (dot != std::wstring::npos) name.erase(dot);
    return name;
}

}  // namespace

std::wstring process_name(DWORD pid) {
    static std::map<DWORD, std::wstring> cache;
    if (const auto found = cache.find(pid); found != cache.end()) return found->second;

    std::wstring name = L"pid " + std::to_wstring(pid);
    UniqueHandle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
    if (process) {
        wchar_t buffer[MAX_PATH];
        DWORD size = MAX_PATH;
        if (QueryFullProcessImageNameW(process.get(), 0, buffer, &size)) {
            name.assign(buffer, size);
            const size_t slash = name.find_last_of(L"\\/");
            if (slash != std::wstring::npos) name.erase(0, slash + 1);
        }
    }
    cache[pid] = name;
    return name;
}

std::wstring process_base_name(DWORD pid) { return lower(strip_extension(process_name(pid))); }

bool is_chromium(DWORD pid) {
    const std::wstring name = process_base_name(pid);
    for (const wchar_t* candidate : kChromium) {
        if (name == candidate) return true;
    }
    return false;
}

bool is_wow64(HANDLE process) {
    BOOL wow64 = FALSE;
    return IsWow64Process(process, &wow64) && wow64;
}

bool process_suspended(DWORD pid) {
    UniqueHandle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, pid));
    if (!snapshot) return false;
    THREADENTRY32 entry{};
    entry.dwSize = sizeof(entry);
    if (!Thread32First(snapshot.get(), &entry)) return false;
    do {
        if (entry.th32OwnerProcessID == pid && (entry.dwFlags & kThreadSuspended)) return true;
    } while (Thread32Next(snapshot.get(), &entry));
    return false;
}

}  // namespace recspoof
