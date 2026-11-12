#include <windows.h>

#include <algorithm>
#include <cstdlib>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "ConfigManager.hpp"
#include "ConsoleUI.hpp"
#include "ProcessManager.hpp"
#include "ProtectionManager.hpp"
#include "WindowManager.hpp"
#include "WindowsAPI.hpp"

namespace {

using namespace recspoof;

constexpr const wchar_t* kVersion = L"2.0.0";

struct Options {
    std::optional<DWORD> pid;
    std::optional<std::wstring> name;
    std::optional<std::wstring> title;
    bool all = false;
    bool list = false;
    bool status = false;
    bool clear = false;
    bool check = false;
    bool inject = false;
    std::optional<std::wstring> config;
};

void print_usage() {
    write(
        L"usage: recspoof [-h] [--version] [-p PID] [-n NAME] [-t TITLE] [-a] [-l] [-s] [-c]\n"
        L"                [--config FILE] [--check] [-x]\n"
        L"\n"
        L"Hide windows from screen capture via SetWindowDisplayAffinity.\n"
        L"\n"
        L"target:\n"
        L"  -p, --pid PID         target a window by PID (exact)\n"
        L"  -n, --name NAME       target by process name (exact)\n"
        L"  -t, --title TITLE     target by window title (substring)\n"
        L"  -a, --all             all matching windows\n"
        L"\n"
        L"action:\n"
        L"  -l, --list            list windows\n"
        L"  -s, --status          show state only\n"
        L"  -c, --clear           remove protection\n"
        L"  --config FILE         batch-protect from a file (one target per line, # comments)\n"
        L"  --check               check config targets and propose to inject the unprotected ones\n"
        L"\n"
        L"options:\n"
        L"  -h, --help            show this help message and exit\n"
        L"  --version             show program's version number and exit\n"
        L"  -x, --inject          force in-process injection\n");
}

[[noreturn]] void die(const std::wstring& message) {
    write_error(L"recspoof: error: " + message);
    print_usage();
    std::exit(2);
}

Options parse_args(int argc, wchar_t** argv) {
    Options options;
    for (int i = 1; i < argc; ++i) {
        std::wstring argument = argv[i];
        std::wstring inline_value;
        if (argument.rfind(L"--", 0) == 0) {
            const size_t equals = argument.find(L'=');
            if (equals != std::wstring::npos) {
                inline_value = argument.substr(equals + 1);
                argument.erase(equals);
            }
        }
        const auto value = [&]() -> std::wstring {
            if (!inline_value.empty()) return inline_value;
            if (i + 1 < argc) return argv[++i];
            write_error(L"recspoof: error: " + argument + L" expects a value");
            print_usage();
            std::exit(2);
        };

        if (argument == L"-h" || argument == L"--help") {
            print_usage();
            std::exit(0);
        } else if (argument == L"--version") {
            write_line(std::wstring(L"recspoof ") + kVersion);
            std::exit(0);
        } else if (argument == L"-p" || argument == L"--pid") {
            const std::wstring text = value();
            try {
                size_t used = 0;
                const unsigned long parsed = std::stoul(text, &used);
                if (used != text.size()) throw std::invalid_argument("trailing characters");
                options.pid = static_cast<DWORD>(parsed);
            } catch (const std::exception&) {
                die(L"invalid --pid value: " + text);
            }
        } else if (argument == L"-n" || argument == L"--name") {
            options.name = value();
        } else if (argument == L"-t" || argument == L"--title") {
            options.title = value();
        } else if (argument == L"-a" || argument == L"--all") {
            options.all = true;
        } else if (argument == L"-l" || argument == L"--list") {
            options.list = true;
        } else if (argument == L"-s" || argument == L"--status") {
            options.status = true;
        } else if (argument == L"-c" || argument == L"--clear") {
            options.clear = true;
        } else if (argument == L"--config") {
            options.config = value();
        } else if (argument == L"--check") {
            options.check = true;
        } else if (argument == L"-x" || argument == L"--inject") {
            options.inject = true;
        } else {
            die(L"unrecognized argument: " + argument);
        }
    }
    return options;
}

// Matching windows for CLI criteria, or nullopt for interactive mode.
std::optional<std::vector<Window>> find_targets(const std::vector<Window>& windows,
                                               const Options& options) {
    if (!options.pid && !options.name && !options.title) return std::nullopt;

    std::vector<Window> selected;
    for (const Window& window : windows) {
        bool match = true;
        if (options.pid) match = match && window.pid == *options.pid;
        if (options.name)
            match = match && lower(process_name(window.pid)) == lower(*options.name);
        if (options.title)
            match = match && lower(window.title).find(lower(*options.title)) != std::wstring::npos;
        if (match) selected.push_back(window);
    }
    if (!options.all && !selected.empty()) selected.resize(1);
    return selected;
}

std::wstring quote_title(const Window& window) {
    return L"'" + window.title + L"' (pid " + std::to_wstring(window.pid) + L")";
}

int check_config(const std::vector<Window>& windows, const Options& options) {
    const std::wstring path = options.config.value_or(L"protect.txt");
    const auto targets = load_config_targets(windows, path);
    if (!targets) return 1;

    const std::vector<std::wstring> lines = load_config(path).value_or(std::vector<std::wstring>{});
    for (const std::wstring& line : lines) {
        const std::wstring needle = lower(line);
        const bool found = std::any_of(targets->begin(), targets->end(), [&needle](const Window& window) {
            return lower(process_name(window.pid)).find(needle) != std::wstring::npos ||
                   lower(window.title).find(needle) != std::wstring::npos;
        });
        if (!found) write_line(L"[--] no window for: " + line);
    }

    std::vector<Window> unprotected;
    for (const Window& window : *targets) {
        const bool injected = window_affinity(window.hwnd) == kExcludeFromCapture;
        write_line(std::wstring(injected ? L"[OK] " : L"[--] ") + quote_title(window) +
                   (injected ? L" injected" : L" not injected"));
        if (!injected) unprotected.push_back(window);
    }

    if (!unprotected.empty() &&
        ask_yes_no(L"Inject the " + std::to_wstring(unprotected.size()) +
                   L" unprotected window(s)? (y/N)")) {
        if (protect(unprotected, false, options.inject)) {
            write_line(L"[VERIFIED] Protection applied and verified for " +
                       std::to_wstring(unprotected.size()) + L" window(s).");
        }
    }
    wait_key();
    return 0;
}

int protect_config(const std::vector<Window>& windows, const Options& options) {
    const auto targets = load_config_targets(windows, *options.config);
    if (!targets || targets->empty()) {
        write_line(L"No windows matched the config file.");
        wait_key();
        return 1;
    }
    const bool ok = protect(*targets, options.clear, options.inject);
    if (ok) {
        write_line(std::wstring(L"[VERIFIED] Protection ") +
                   (options.clear ? L"removed" : L"applied") + L" and verified for " +
                   std::to_wstring(targets->size()) + L" window(s).");
    }
    wait_key();
    return ok ? 0 : 1;
}

int run(int argc, wchar_t** argv) {
    const Options options = parse_args(argc, argv);
    const std::vector<std::wstring> args(argv + 1, argv + argc);
    ensure_admin(args);
    utf8_console();

    const std::vector<Window> windows = list_windows();

    if (options.list) {
        print_windows(windows);
        return 0;
    }
    if (options.check) return check_config(windows, options);
    if (options.config) return protect_config(windows, options);

    const auto targets = find_targets(windows, options);
    if (!targets) {
        if (windows.empty()) {
            write_line(L"No visible windows found.");
            return 1;
        }
        run_menu(windows, options.config.value_or(L"protect.txt"));
        return 0;
    }
    if (targets->empty()) {
        write_line(L"No windows found.");
        return 1;
    }
    if (options.status) {
        show_status(*targets);
        return 0;
    }

    const bool ok = protect(*targets, options.clear, options.inject);
    if (ok) {
        write_line(std::wstring(L"[VERIFIED] Protection ") +
                   (options.clear ? L"removed" : L"applied") + L" and verified for " +
                   std::to_wstring(targets->size()) + L" window(s).");
    }
    wait_key();
    return ok ? 0 : 1;
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    try {
        return run(argc, argv);
    } catch (const std::exception& error) {
        write_error(L"ERROR: " + recspoof::widen(error.what()));
        return 1;
    }
}
