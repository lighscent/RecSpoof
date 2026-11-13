#include "ConsoleUI.hpp"

#include <windows.h>

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
constexpr const wchar_t* kRed = L"\x1b[31m";
constexpr const wchar_t* kYellow = L"\x1b[33m";
constexpr const wchar_t* kTitle = L"\x1b[1;36m";
constexpr const wchar_t* kDim = L"\x1b[2m";
constexpr const wchar_t* kReverse = L"\x1b[7m";
constexpr const wchar_t* kReset = L"\x1b[0m";
constexpr const wchar_t* kHint =
    L" up/down move   enter inject   a all   s save   r refresh   q quit";
constexpr const wchar_t* kRule = L"\u2500";  // box-drawing horizontal
constexpr size_t kStateWidth = 12;

enum class Tone { info, ok, fail, skip };

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

// Plain table used by --list: fixed columns, no colors, pipe friendly.
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

// Window size changes only arrive through ReadConsoleInput when this is set.
void enable_window_input() {
    HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    if (GetConsoleMode(input, &mode)) SetConsoleMode(input, mode | ENABLE_WINDOW_INPUT);
}

enum class Input { none, up, down, enter, all, save, refresh, quit, resize };

Input read_input() {
    INPUT_RECORD record{};
    DWORD count = 0;
    if (!ReadConsoleInputW(GetStdHandle(STD_INPUT_HANDLE), &record, 1, &count) || count == 0)
        return Input::none;
    if (record.EventType == WINDOW_BUFFER_SIZE_EVENT) return Input::resize;
    if (record.EventType != KEY_EVENT || !record.Event.KeyEvent.bKeyDown) return Input::none;

    switch (record.Event.KeyEvent.wVirtualKeyCode) {
        case VK_UP:
            return Input::up;
        case VK_DOWN:
            return Input::down;
        case VK_RETURN:
            return Input::enter;
        default:
            break;
    }
    switch (record.Event.KeyEvent.uChar.UnicodeChar) {
        case 3:
        case L'q':
            return Input::quit;
        case L'a':
            return Input::all;
        case L's':
            return Input::save;
        case L'r':
        case L'R':
            return Input::refresh;
        default:
            return Input::none;
    }
}

std::wstring state_label(const Window& window, std::optional<UINT> state) {
    if (state == kExcludeFromCapture) return L"injected";
    if (is_chromium(window.pid)) return L"unsupported";
    return L"not injected";
}

const wchar_t* state_color(const Window& window, std::optional<UINT> state) {
    if (state == kExcludeFromCapture) return kGreen;
    if (is_chromium(window.pid)) return kRed;
    return kDim;
}

const wchar_t* tone_color(Tone tone) {
    switch (tone) {
        case Tone::ok:
            return kGreen;
        case Tone::fail:
            return kRed;
        case Tone::skip:
            return kYellow;
        case Tone::info:
            break;
    }
    return L"";
}

// One menu row: marker, index, pid, process, truncated title, right-aligned state.
std::wstring menu_row(const Window& window, size_t index, size_t proc_w,
                      std::optional<UINT> state, size_t line_width) {
    const std::wstring prefix = L"  " + pad(std::to_wstring(index + 1), 4, true) + L"  " +
                                pad(std::to_wstring(window.pid), 6, true) + L"  " +
                                pad(process_name(window.pid), proc_w) + L" ";
    const std::wstring suffix = L" " + pad(state_label(window, state), kStateWidth, true);

    size_t available = 0;
    if (line_width > prefix.size() + suffix.size()) {
        available = line_width - prefix.size() - suffix.size();
    }
    std::wstring title = window.title;
    if (title.size() > available) {
        title = available > 3 ? title.substr(0, available - 3) + L"..." : title.substr(0, available);
    }
    return prefix + pad(title, available) + suffix;
}

class Menu {
public:
    Menu(std::vector<Window> windows, std::wstring config_path)
        : windows_(std::move(windows)), config_path_(std::move(config_path)) {
        int columns = 80;
        int lines = 25;
        console_size(columns, lines);
        width_ = static_cast<size_t>(std::max(columns, 20));
        page_h_ = static_cast<size_t>(std::max(lines - 6, 3));
        proc_w_ = process_column(windows_);
        enable_ansi();
        enable_window_input();
    }

    void run() {
        quiet = true;
        struct RestoreWarnings {
            ~RestoreWarnings() { quiet = false; }
        } restore;

        draw_all();
        for (;;) {
            switch (read_input()) {
                case Input::resize:
                    relayout();
                    break;
                case Input::up:
                    move_up();
                    break;
                case Input::down:
                    move_down();
                    break;
                case Input::enter:
                    protect_one(index_);
                    break;
                case Input::all:
                    protect_all();
                    break;
                case Input::save:
                    save_to_config(index_);
                    break;
                case Input::refresh:
                    if (!refresh()) return;
                    break;
                case Input::quit:
                    return;
                case Input::none:
                    break;
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

    size_t injected_count() {
        size_t injected = 0;
        for (const Window& window : windows_) {
            if (get_state(window.hwnd) == kExcludeFromCapture) ++injected;
        }
        return injected;
    }

    std::wstring title_bar() {
        const size_t total = windows_.size();
        const std::wstring count =
            std::to_wstring(total) + (total == 1 ? L" window" : L" windows");
        return L" " + std::wstring(kTitle) + L"RecSpoof" + kReset + L"  " + kDim + count +
               kReset + L"  " + kGreen + std::to_wstring(injected_count()) + L" injected" +
               kReset;
    }

    std::wstring rule() const { return std::wstring(width_ - 1, kRule[0]); }

    std::wstring column_header() const {
        const std::wstring prefix = L"  " + pad(L"#", 4, true) + L"  " + pad(L"PID", 6, true) +
                                    L"  " + pad(L"PROCESS", proc_w_) + L" ";
        const std::wstring suffix = L" " + pad(L"STATE", kStateWidth, true);
        const size_t available =
            width_ > prefix.size() + suffix.size() ? width_ - prefix.size() - suffix.size() : 0;
        return prefix + pad(L"WINDOW", available) + suffix;
    }

    std::wstring paint(size_t i, bool selected) {
        const Window& window = windows_[i];
        const std::optional<UINT> state = get_state(window.hwnd);
        std::wstring line = menu_row(window, i, proc_w_, state, width_);
        if (selected) return std::wstring(kReverse) + L"> " + line.substr(2) + kReset;

        const size_t tail = line.size() >= kStateWidth ? line.size() - kStateWidth : 0;
        return line.substr(0, tail) + state_color(window, state) + line.substr(tail) + kReset;
    }

    void set_status(std::wstring status, Tone tone) {
        if (status.size() >= width_) status.resize(width_ - 1);
        status_ = std::move(status);
        tone_ = tone;
    }

    void draw_status() {
        write(L"\x1b[" + std::to_wstring(page_h_ + 6) + L"H\x1b[K " + tone_color(tone_) +
              status_ + kReset);
    }

    void draw_header() { write(L"\x1b[1H\x1b[K" + title_bar()); }

    void draw_all() {
        std::wstring out = L"\x1b[H\x1b[J";
        out += title_bar() + L"\n";
        out += rule() + L"\n";
        out += kDim + column_header() + kReset + L"\n";
        size_t drawn = 0;
        for (size_t i = offset_; i < std::min(offset_ + page_h_, windows_.size()); ++i) {
            out += paint(i, i == index_) + L"\n";
            ++drawn;
        }
        for (; drawn < page_h_; ++drawn) out += L"\n";  // keep the footer at the bottom
        out += rule() + L"\n" + kDim + kHint + kReset + L"\n";
        write(out);
        draw_status();
    }

    void draw_line(size_t i, bool selected) {
        if (i < offset_ || i >= offset_ + page_h_) return;
        write(L"\x1b[" + std::to_wstring(4 + i - offset_) + L"H\x1b[K" + paint(i, selected));
    }

    // Re-read the console size after a resize and repaint the whole frame.
    void relayout() {
        int columns = 80;
        int lines = 25;
        console_size(columns, lines);
        width_ = static_cast<size_t>(std::max(columns, 20));
        page_h_ = static_cast<size_t>(std::max(lines - 6, 3));

        const size_t last = windows_.empty() ? 0 : windows_.size() - 1;
        index_ = std::min(index_, last);
        if (index_ < offset_) {
            offset_ = index_;
        } else if (index_ >= offset_ + page_h_) {
            offset_ = index_ - page_h_ + 1;
        }
        const size_t max_offset = windows_.size() > page_h_ ? windows_.size() - page_h_ : 0;
        offset_ = std::min(offset_, max_offset);
        draw_all();
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
            set_status(L"'" + name + L"' is already in " + base, Tone::info);
        } else {
            std::ofstream out(path, std::ios::app);
            if (!out) {
                set_status(L"Unable to write " + base, Tone::fail);
            } else {
                out << narrow(name) << '\n';
                set_status(L"Added '" + name + L"' to " + base, Tone::ok);
            }
        }
        draw_status();
    }

    bool protect_one(size_t i) {
        const Window& window = windows_[i];
        const std::wstring where =
            L"'" + window.title + L"' (pid " + std::to_wstring(window.pid) + L")";
        if (is_chromium(window.pid) && get_state(window.hwnd) != kExcludeFromCapture) {
            set_status(L"SKIP " + where + L" " + CHROMIUM_UNSUPPORTED, Tone::skip);
            warn(L"SKIP: " + where + L" " + CHROMIUM_UNSUPPORTED);
            draw_line(i, i == index_);
            draw_status();
            return false;
        }
        const auto [ok, method] = apply_affinity(window.hwnd, kExcludeFromCapture, false);
        states_[window.hwnd] = window_affinity(window.hwnd);
        const bool injected = states_[window.hwnd] == kExcludeFromCapture;
        set_status(ok && injected ? L"OK (" + widen(method) + L") " + where + L" injected"
                                  : L"FAILED " + where,
                   ok && injected ? Tone::ok : Tone::fail);
        draw_line(i, i == index_);
        draw_header();
        draw_status();
        return ok && injected;
    }

    void protect_all() {
        size_t applied = 0;
        for (size_t i = 0; i < windows_.size(); ++i) {
            if (protect_one(i)) ++applied;
        }
        set_status(applied == windows_.size()
                       ? L"OK " + std::to_wstring(applied) + L" window(s) injected"
                       : L"FAILED " + std::to_wstring(windows_.size() - applied) + L"/" +
                             std::to_wstring(windows_.size()) + L" window(s)",
                   applied == windows_.size() ? Tone::ok : Tone::fail);
        draw_all();
    }

    bool refresh() {
        auto refreshed = list_windows();
        if (refreshed.empty()) return false;
        windows_ = std::move(refreshed);
        states_.clear();
        proc_w_ = process_column(windows_);
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
    size_t width_ = 80;
    std::wstring status_;
    Tone tone_ = Tone::info;
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
