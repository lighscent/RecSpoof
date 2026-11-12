#pragma once

#include <string>
#include <vector>

#include "WindowManager.hpp"

namespace recspoof {

std::wstring header_line(const std::vector<Window>& windows);
std::wstring separator_line(const std::vector<Window>& windows);
std::vector<std::wstring> render_windows(const std::vector<Window>& windows);
void print_windows(const std::vector<Window>& windows);
void show_status(const std::vector<Window>& windows);

// Arrow-key menu over the visible windows; returns when the user quits.
void run_menu(std::vector<Window> windows, const std::wstring& config_path);

}  // namespace recspoof
