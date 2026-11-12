// Asserts the parts that cannot be exercised without injectable targets:
// the PE export reader and the shellcode encoders.

#include <windows.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "ProtectionManager.hpp"
#include "WindowManager.hpp"

namespace {

int failures = 0;

void check(bool condition, const char* message) {
    if (condition) return;
    std::printf("FAIL: %s\n", message);
    ++failures;
}

}  // namespace

int main() {
    using namespace recspoof;

    wchar_t directory[MAX_PATH] = {};
    if (GetSystemWow64DirectoryW(directory, MAX_PATH) == 0) {
        std::printf("SKIP: no SysWOW64 directory\n");
        return 0;
    }
    const std::wstring kernel32 = std::wstring(directory) + L"\\kernel32.dll";

    check(pe_export_rva(kernel32, "ExitThread").has_value(),
          "ExitThread is exported by SysWOW64 kernel32.dll");
    check(!pe_export_rva(kernel32, "NoSuchExportForSelfcheck").has_value(),
          "missing export resolves to nullopt");
    check(!pe_export_rva(L"Z:\\missing\\kernel32.dll", "ExitThread").has_value(),
          "missing file resolves to nullopt");

    const std::vector<uint8_t> x64 =
        build_shellcode_x64(kExcludeFromCapture, 0x1122334455667788ULL, 0x99AABBCCDDEEFF00ULL);
    check(x64.size() == 37, "x64 shellcode length");
    uint64_t affinity = 0;
    std::memcpy(&affinity, x64.data() + 2, sizeof(affinity));
    check(affinity == kExcludeFromCapture, "x64 shellcode carries the affinity");
    uint64_t set_affinity = 0;
    std::memcpy(&set_affinity, x64.data() + 12, sizeof(set_affinity));
    check(set_affinity == 0x1122334455667788ULL, "x64 shellcode carries the API address");

    const std::vector<uint8_t> x86 = build_shellcode_x86(kAffinityNone, 0x11223344U, 0x55667788U);
    check(x86.size() == 30, "x86 shellcode length");

    if (failures == 0) std::printf("selfcheck: all checks passed\n");
    return failures == 0 ? 0 : 1;
}
