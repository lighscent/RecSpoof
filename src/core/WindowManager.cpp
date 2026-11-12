#include "WindowManager.hpp"

#include <windows.h>

#include <utility>

#include "WindowsAPI.hpp"

namespace recspoof {
namespace {

BOOL CALLBACK collect(HWND hwnd, LPARAM param) {
    if (!IsWindowVisible(hwnd)) return TRUE;
    std::wstring title = window_title(hwnd);
    if (title.empty()) return TRUE;
    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    reinterpret_cast<std::vector<Window>*>(param)->push_back({hwnd, pid, std::move(title)});
    return TRUE;
}

}  // namespace

std::wstring window_title(HWND hwnd) {
    const int length = GetWindowTextLengthW(hwnd);
    if (length <= 0) return {};
    std::wstring buffer(static_cast<size_t>(length) + 1, L'\0');
    const int copied = GetWindowTextW(hwnd, buffer.data(), length + 1);
    buffer.resize(copied > 0 ? static_cast<size_t>(copied) : 0);
    return buffer;
}

std::optional<UINT> window_affinity(HWND hwnd) {
    DWORD state = 0;
    if (GetWindowDisplayAffinity(hwnd, &state)) return static_cast<UINT>(state);
    return std::nullopt;
}

std::wstring affinity_label(HWND hwnd, std::optional<UINT> state) {
    if (!state) state = window_affinity(hwnd);
    if (!state) return L"?";
    if (*state == kAffinityNone) return L"not injected";
    if (*state == kExcludeFromCapture) return L"injected";
    return L"unknown (" + std::to_wstring(*state) + L")";
}

std::vector<Window> list_windows() {
    std::vector<Window> windows;
    EnumWindows(collect, reinterpret_cast<LPARAM>(&windows));
    return windows;
}

}  // namespace recspoof
