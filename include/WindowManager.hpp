#pragma once

#include <windows.h>

#include <optional>
#include <string>
#include <vector>

namespace recspoof {

struct Window {
    HWND hwnd = nullptr;
    DWORD pid = 0;
    std::wstring title;
};

// WDA_NONE / WDA_EXCLUDEFROMCAPTURE are int macros in winuser.h; keep unsigned
// constants so optional<UINT> comparisons stay warning-free.
constexpr UINT kAffinityNone = WDA_NONE;
constexpr UINT kExcludeFromCapture = WDA_EXCLUDEFROMCAPTURE;

constexpr const wchar_t* CHROMIUM_UNSUPPORTED =
    L"cannot be protected: the direct call is denied (error 5) and "
    L"thread injection crashes the browser";

std::wstring window_title(HWND hwnd);
std::optional<UINT> window_affinity(HWND hwnd);
std::wstring affinity_label(HWND hwnd, std::optional<UINT> state = std::nullopt);
std::vector<Window> list_windows();

}  // namespace recspoof
