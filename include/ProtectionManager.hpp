#pragma once

#include <windows.h>

#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "WindowManager.hpp"

namespace recspoof {

// Applies affinity directly and falls back to in-process injection.
// Returns {success, method} where method is "direct", "injection" or nullptr.
std::pair<bool, const char*> apply_affinity(HWND hwnd, UINT affinity, bool force_inject);

// Protects (or clears) each window; prints [OK]/[FAILED]/[SKIP] per window.
bool protect(const std::vector<Window>& windows, bool clear = false, bool force_inject = false);

// Internals exposed for the self-check executable.
std::vector<uint8_t> build_shellcode_x64(UINT affinity, uint64_t set_affinity, uint64_t exit_thread);
std::vector<uint8_t> build_shellcode_x86(UINT affinity, uint32_t set_affinity, uint32_t exit_thread);

// RVA of an export in a PE file on disk, or nullopt when the file has no such export.
std::optional<uint32_t> pe_export_rva(const std::wstring& path, const std::string& name);

}  // namespace recspoof
