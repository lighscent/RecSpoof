#pragma once

#include <optional>
#include <string>
#include <vector>

#include "WindowManager.hpp"

namespace recspoof {

// Non-empty, non-comment lines; nullopt when the file cannot be read.
std::optional<std::vector<std::wstring>> load_config(const std::wstring& path);

// Windows matching any line (process name or title substring, case-insensitive).
std::vector<Window> config_matches(const std::vector<Window>& windows,
                                   const std::vector<std::wstring>& lines);

// Matches the config file; offers to create it when missing (then exits).
std::optional<std::vector<Window>> load_config_targets(const std::vector<Window>& windows,
                                                      const std::wstring& path);

}  // namespace recspoof
