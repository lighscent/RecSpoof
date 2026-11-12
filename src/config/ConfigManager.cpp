#include "ConfigManager.hpp"

#include <windows.h>

#include <cstdlib>
#include <fstream>
#include <set>
#include <string>

#include "ProcessManager.hpp"
#include "WindowsAPI.hpp"

namespace recspoof {
namespace {

std::wstring trim(const std::wstring& text) {
    const size_t first = text.find_first_not_of(L" \t\r\n");
    if (first == std::wstring::npos) return {};
    const size_t last = text.find_last_not_of(L" \t\r\n");
    return text.substr(first, last - first + 1);
}

bool is_comment(const std::wstring& line) {
    const size_t first = line.find_first_not_of(L" \t");
    return first != std::wstring::npos && line[first] == L'#';
}

}  // namespace

std::optional<std::vector<std::wstring>> load_config(const std::wstring& path) {
    std::ifstream file(path);
    if (!file) return std::nullopt;

    std::vector<std::wstring> lines;
    std::string raw;
    while (std::getline(file, raw)) {
        std::wstring line = trim(widen(raw));
        if (line.empty() || is_comment(line)) continue;
        lines.push_back(std::move(line));
    }
    return lines;
}

std::vector<Window> config_matches(const std::vector<Window>& windows,
                                   const std::vector<std::wstring>& lines) {
    std::vector<Window> targets;
    std::set<HWND> seen;
    for (const std::wstring& line : lines) {
        const std::wstring needle = lower(line);
        for (const Window& window : windows) {
            if (seen.contains(window.hwnd)) continue;
            if (lower(process_name(window.pid)).find(needle) != std::wstring::npos ||
                lower(window.title).find(needle) != std::wstring::npos) {
                seen.insert(window.hwnd);
                targets.push_back(window);
            }
        }
    }
    return targets;
}

std::optional<std::vector<Window>> load_config_targets(const std::vector<Window>& windows,
                                                      const std::wstring& path) {
    const auto lines = load_config(path);
    if (lines) return config_matches(windows, *lines);

    warn(L"Config file not found: " + path);
    write_line(L"Config file not found: " + path);
    const bool created = ask_yes_no(L"Create it now? (y/N)") && [&path] {
        std::ofstream file(path);
        if (!file) {
            warn(L"Unable to create config file: " + path);
            return false;
        }
        file << "# one target per line (process name or window title)\n";
        return true;
    }();
    if (created) write_line(L"Created " + path + L" - add one target per line, then run again.");
    wait_key();
    std::exit(created ? 0 : 1);
}

}  // namespace recspoof
