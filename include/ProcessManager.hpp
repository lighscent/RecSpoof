#pragma once

#include <windows.h>

#include <string>

namespace recspoof {

// File name with extension ("notepad.exe"), or "pid 1234" when unavailable.
std::wstring process_name(DWORD pid);

// Lowercase file name without extension ("notepad") - the config file form.
std::wstring process_base_name(DWORD pid);

bool is_chromium(DWORD pid);
bool is_wow64(HANDLE process);
bool process_suspended(DWORD pid);

}  // namespace recspoof
