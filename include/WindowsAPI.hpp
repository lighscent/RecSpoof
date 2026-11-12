#pragma once

#include <windows.h>

#include <string>
#include <vector>

namespace recspoof {

// Console warnings are silenced while the interactive menu owns the screen.
extern bool quiet;

// Closes a Win32 handle on scope exit (skips null and INVALID_HANDLE_VALUE).
class UniqueHandle {
public:
    UniqueHandle() = default;
    explicit UniqueHandle(HANDLE handle) : handle_(handle) {}
    UniqueHandle(const UniqueHandle&) = delete;
    UniqueHandle& operator=(const UniqueHandle&) = delete;
    UniqueHandle(UniqueHandle&& other) noexcept : handle_(other.release()) {}
    UniqueHandle& operator=(UniqueHandle&& other) noexcept {
        if (this != &other) reset(other.release());
        return *this;
    }
    ~UniqueHandle() { reset(); }

    HANDLE get() const { return handle_; }
    explicit operator bool() const { return handle_ && handle_ != INVALID_HANDLE_VALUE; }
    HANDLE release() {
        HANDLE handle = handle_;
        handle_ = nullptr;
        return handle;
    }
    void reset(HANDLE handle = nullptr) {
        if (handle_ && handle_ != INVALID_HANDLE_VALUE) CloseHandle(handle_);
        handle_ = handle;
    }

private:
    HANDLE handle_ = nullptr;
};

std::string narrow(const std::wstring& text);  // wide -> UTF-8
std::wstring widen(const std::string& text);   // UTF-8 -> wide
std::wstring lower(std::wstring text);
std::wstring format_error(DWORD code);         // "Access is denied. (error 5)"

void write(const std::wstring& text);          // UTF-8 to stdout, flushed
void write_line(const std::wstring& text = L"");
void write_error(const std::wstring& text);
void warn(const std::wstring& text);           // "WARNING: ..." to stderr unless quiet

bool is_admin();
std::wstring exe_path();
std::wstring join_args(const std::vector<std::wstring>& args);
int relaunch_elevated(const std::vector<std::wstring>& args);
void ensure_admin(const std::vector<std::wstring>& args);

// Console acquisition: the executable is a GUI-subsystem binary, so no console
// exists until one is attached or allocated.
bool attach_parent_console();  // attach to the launching console; true when one exists
void allocate_console();       // AllocConsole when the process has none
void ensure_console();         // attach, else allocate (cached per process)
void enable_ansi();
void utf8_console();
bool ask_yes_no(const std::wstring& prompt);
void wait_key();

}  // namespace recspoof
