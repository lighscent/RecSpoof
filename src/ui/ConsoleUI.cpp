#include "ConsoleUI.hpp"

#include <windows.h>
#include <conio.h>

#include <algorithm>
#include <fstream>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "ProcessManager.hpp"
#include "ProtectionManager.hpp"
#include "WindowsAPI.hpp"

namespace recspoof {
namespace {

constexpr const wchar_t* kGreen = L"\x1b[32m";
constexpr const wchar_t* kCyan = L"\x1b[36m";
constexpr const wchar_t* kReset = L"\x1b[0m";
constexpr const wchar_t* kHint =
    L"Up/Down: navigate | Enter: protect | a: all | s: save to config | r: refresh | q: quit";

std::wstring trim(const std::wstring& text) {
    const size_t first = text.find_first_not_of(L" \t\r\n");
    if (first == std::wstring::npos) return {};
    const size_t last = text.find_last_not_of(L" \t\r\n");
    return text.substr(first, last - first + 1);
}

std::wstring pad(const std::wstring& text, size_t width, bool right = false) {
    if (text.size() >= width) return text;
    const std::wstring fill(width - text.size(), L' ');
    return right ? fill + text : text + fill;
}

size_t process_column(const std::vector<Window>& windows) {
    size_t widest = 0;
    for (const Window& window : windows) widest = std::max(widest, process_name(window.pid).size());
    return std::min(widest, static_cast<size_t>(40));
}

std::wstring format_row(const Window& window, size_t index, size_t proc_w,
                        std::optional<UINT> state) {
    std::wstring inj;
    if (is_chromium(window.pid) && state != kExcludeFromCapture) inj = L"unsupported";
    return pad(std::to_wstring(index + 1), 4, true) + L"  " +
           pad(std::to_wstring(window.pid), 6, true) + L"  " +
           pad(process_name(window.pid), proc_w) + L" " +
           pad(affinity_label(window.hwnd, state), 15) + L" " + pad(inj, 11) + L" " +
           window.title;
}

void console_size(int& columns, int& lines) {
    CONSOLE_SCREEN_BUFFER_INFO info{};
    if (GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &info)) {
        columns = info.srWindow.Right - info.srWindow.Left + 1;
        lines = info.srWindow.Bottom - info.srWindow.Top + 1;
    } else {
        columns = 80;
        lines = 25;
    }
}

class Menu {
public:
    Menu(std::vector<Window> windows, std::wstring config_path)
        : windows_(std::move(windows)), config_path_(std::move(config_path)) {
        int columns = 80;
        int lines = 25;
        console_size(columns, lines);
        width_ = columns;
        page_h_ = static_cast<size_t>(std::max(lines - 5, 3));
        proc_w_ = process_column(windows_);
        header_ = header_line(windows_);
        separator_ = separator_line(windows_);
        enable_ansi();
    }

    void run() {
        quiet = true;
        struct RestoreWarnings {
            ~RestoreWarnings() { quiet = false; }
        } restore;

        draw_all();
        for (;;) {
            const int key = _getch();
            if (key == 0xE0 || key == 0x00) {  // arrow prefix
                const int arrow = _getch();
                if (arrow == 'H') {
                    move_up();
                } else if (arrow == 'P') {
                    move_down();
                }
                continue;
            }
            if (key == '\r') {
                protect_one(index_);
            } else if (key == 3 || key == 'q') {
                return;
            } else if (key == 'a') {
                protect_all();
            } else if (key == 's') {
                save_to_config(index_);
            } else if (key == 'r' || key == 'R') {
                if (!refresh()) return;
            }
        }
    }

private:
    std::optional<UINT> get_state(HWND hwnd) {
        const auto found = states_.find(hwnd);
        if (found != states_.end()) return found->second;
        states_[hwnd] = window_affinity(hwnd);
        return states_[hwnd];
    }

    std::wstring row_text(size_t i) { return format_row(windows_[i], i, proc_w_, get_state(windows_[i].hwnd)); }

    std::wstring paint(size_t i, bool selected) {
        std::wstring text = row_text(i);
        const size_t limit = width_ > 3 ? static_cast<size_t>(width_ - 3) : 0;
        if (text.size() > limit) text.resize(limit);
        if (selected) return std::wstring(kGreen) + L"> " + text + kReset;
        if (get_state(windows_[i].hwnd) == kExcludeFromCapture)
            return std::wstring(kCyan) + L"  " + text + kReset;
        return L"  " + text;
    }

    void set_status(std::wstring status) {
        if (status.size() >= static_cast<size_t>(width_)) status.resize(static_cast<size_t>(width_));
        status_ = std::move(status);
    }

    void draw_status() {
        write(L"\x1b[" + std::to_wstring(page_h_ + 4) + L"H\x1b[K" + status_);
    }

    void draw_all() {
        std::wstring out = L"\x1b[H\x1b[J" + header_ + L"\n" + separator_;
        for (size_t i = offset_; i < std::min(offset_ + page_h_, windows_.size()); ++i) {
            out += L"\n" + paint(i, i == index_);
        }
        out += L"\n" + std::wstring(kHint) + L"\n";
        write(out);
        draw_status();
    }

    void draw_line(size_t i, bool selected) {
        if (i < offset_ || i >= offset_ + page_h_) return;
        write(L"\x1b[" + std::to_wstring(3 + i - offset_) + L"H\x1b[K" + paint(i, selected));
    }

    void move_up() {
        const size_t count = windows_.size();
        const size_t next = (index_ + count - 1) % count;
        if (next < offset_) {
            offset_ = next;
            draw_all();
        } else if (next >= offset_ + page_h_) {
            offset_ = next - page_h_ + 1;
            draw_all();
        } else {
            draw_line(index_, false);
            draw_line(next, true);
        }
        index_ = next;
    }

    void move_down() {
        const size_t count = windows_.size();
        const size_t next = (index_ + 1) % count;
        if (next >= offset_ + page_h_) {
            offset_ = next - page_h_ + 1;
            draw_all();
        } else if (next < offset_) {
            offset_ = next;
            draw_all();
        } else {
            draw_line(index_, false);
            draw_line(next, true);
        }
        index_ = next;
    }

    void save_to_config(size_t i) {
        const std::wstring name = process_base_name(windows_[i].pid);
        const std::wstring path = config_path_.empty() ? L"protect.txt" : config_path_;
        std::wstring base = path;
        if (const size_t slash = base.find_last_of(L"\\/"); slash != std::wstring::npos)
            base.erase(0, slash + 1);

        std::vector<std::wstring> existing;
        std::ifstream file(path);
        if (file) {
            std::string raw;
            while (std::getline(file, raw)) {
                std::wstring line = trim(widen(raw));
                if (!line.empty()) existing.push_back(lower(line));
            }
        }
        if (std::find(existing.begin(), existing.end(), name) != existing.end()) {
            set_status(L"'" + name + L"' is already in " + base);
        } else {
            std::ofstream out(path, std::ios::app);
            if (!out) {
                set_status(L"Unable to write " + base);
            } else {
                out << narrow(name) << '\n';
                set_status(L"Added '" + name + L"' to " + base);
            }
        }
        draw_status();
    }

    bool protect_one(size_t i) {
        const Window& window = windows_[i];
        const std::wstring where =
            L"'" + window.title + L"' (pid " + std::to_wstring(window.pid) + L")";
        if (is_chromium(window.pid) && get_state(window.hwnd) != kExcludeFromCapture) {
            set_status(L"[SKIP] " + where + L" " + CHROMIUM_UNSUPPORTED);
            warn(L"SKIP: " + where + L" " + CHROMIUM_UNSUPPORTED);
            draw_line(i, i == index_);
            draw_status();
            return false;
        }
        const auto [ok, method] = apply_affinity(window.hwnd, kExcludeFromCapture, false);
        states_[window.hwnd] = window_affinity(window.hwnd);
        const bool injected = states_[window.hwnd] == kExcludeFromCapture;
        set_status(ok && injected ? L"[OK] (" + widen(method) + L") " + where + L" injected"
                                  : L"[FAILED] " + where);
        draw_line(i, i == index_);
        draw_status();
        return ok && injected;
    }

    void protect_all() {
        size_t applied = 0;
        for (size_t i = 0; i < windows_.size(); ++i) {
            if (protect_one(i)) ++applied;
        }
        set_status(applied == windows_.size()
                       ? L"[OK] " + std::to_wstring(applied) + L" window(s) injected"
                       : L"[FAILED] " + std::to_wstring(windows_.size() - applied) + L"/" +
                             std::to_wstring(windows_.size()) + L" window(s)");
        draw_all();
    }

    bool refresh() {
        auto refreshed = list_windows();
        if (refreshed.empty()) return false;
        windows_ = std::move(refreshed);
        states_.clear();
        proc_w_ = process_column(windows_);
        header_ = header_line(windows_);
        separator_ = separator_line(windows_);
        index_ = std::min(index_, windows_.size() - 1);
        const size_t max_offset = windows_.size() > page_h_ ? windows_.size() - page_h_ : 0;
        offset_ = std::min(offset_, max_offset);
        draw_all();
        return true;
    }

    std::vector<Window> windows_;
    std::wstring config_path_;
    std::map<HWND, std::optional<UINT>> states_;
    size_t index_ = 0;
    size_t offset_ = 0;
    size_t page_h_ = 3;
    size_t proc_w_ = 0;
    int width_ = 80;
    std::wstring header_;
    std::wstring separator_;
    std::wstring status_;
};

}  // namespace

std::wstring header_line(const std::vector<Window>& windows) {
    const size_t proc_w = process_column(windows);
    return pad(L"#", 4, true) + L"  " + pad(L"PID", 6, true) + L"    " + pad(L"PROC", proc_w) +
           L" " + pad(L"STATE", 15) + L" " + pad(L"INJ", 11) + L" TITLE";
}

std::wstring separator_line(const std::vector<Window>& windows) {
    return std::wstring(header_line(windows).size(), L'-');
}

std::vector<std::wstring> render_windows(const std::vector<Window>& windows) {
    if (windows.empty()) return {};
    const size_t proc_w = process_column(windows);
    std::vector<std::wstring> rows{header_line(windows), separator_line(windows)};
    for (size_t i = 0; i < windows.size(); ++i) {
        rows.push_back(format_row(windows[i], i, proc_w, window_affinity(windows[i].hwnd)));
    }
    return rows;
}

void print_windows(const std::vector<Window>& windows) {
    const std::vector<std::wstring> rows = render_windows(windows);
    std::wstring out;
    for (size_t i = 0; i < rows.size(); ++i) {
        if (i != 0) out += L'\n';
        out += rows[i];
    }
    write_line(L"\n" + out);
}

void show_status(const std::vector<Window>& windows) {
    for (const Window& window : windows) {
        write_line(L"[" + affinity_label(window.hwnd) + L"] " + process_name(window.pid) +
                   L" (pid " + std::to_wstring(window.pid) + L") " + window.title);
    }
}

void run_menu(std::vector<Window> windows, const std::wstring& config_path) {
    Menu menu(std::move(windows), config_path);
    menu.run();
}

}  // namespace recspoof
