#include "WindowsAPI.hpp"

#include <windows.h>

#include <shellapi.h>
#include <conio.h>
#include <io.h>

#include <cstdio>
#include <cwctype>

namespace recspoof {

bool quiet = false;

std::string narrow(const std::wstring& text) {
    if (text.empty()) return {};
    const int size = WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()),
                                         nullptr, 0, nullptr, nullptr);
    std::string out(static_cast<size_t>(size), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), out.data(), size,
                        nullptr, nullptr);
    return out;
}

std::wstring widen(const std::string& text) {
    if (text.empty()) return {};
    const int size =
        MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
    std::wstring out(static_cast<size_t>(size), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), out.data(), size);
    return out;
}

std::wstring lower(std::wstring text) {
    for (wchar_t& ch : text) ch = static_cast<wchar_t>(std::towlower(ch));
    return text;
}

std::wstring format_error(DWORD code) {
    wchar_t* buffer = nullptr;
    const DWORD length = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, code, 0, reinterpret_cast<wchar_t*>(&buffer), 0, nullptr);
    std::wstring message = buffer ? std::wstring(buffer, length) : L"unknown error";
    if (buffer) LocalFree(buffer);
    while (!message.empty() && std::iswspace(message.back())) message.pop_back();
    return message + L" (error " + std::to_wstring(code) + L")";
}

void write(const std::wstring& text) {
    ensure_console();
    const std::string bytes = narrow(text);
    std::fwrite(bytes.data(), 1, bytes.size(), stdout);
    std::fflush(stdout);
}

void write_line(const std::wstring& text) { write(text + L"\n"); }

void write_error(const std::wstring& text) {
    ensure_console();
    const std::string bytes = narrow(text + L"\n");
    std::fwrite(bytes.data(), 1, bytes.size(), stderr);
    std::fflush(stderr);
}

void warn(const std::wstring& text) {
    if (!quiet) write_error(L"WARNING: " + text);
}

bool is_admin() {
    BOOL admin = FALSE;
    SID_IDENTIFIER_AUTHORITY authority = SECURITY_NT_AUTHORITY;
    PSID administrators = nullptr;
    if (AllocateAndInitializeSid(&authority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                 DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &administrators)) {
        CheckTokenMembership(nullptr, administrators, &admin);
        FreeSid(administrators);
    }
    return admin != FALSE;
}

std::wstring exe_path() {
    std::wstring buffer(MAX_PATH, L'\0');
    for (;;) {
        const DWORD length = GetModuleFileNameW(nullptr, buffer.data(),
                                                static_cast<DWORD>(buffer.size()));
        if (length == 0) return {};
        if (length < buffer.size()) {
            buffer.resize(length);
            return buffer;
        }
        buffer.resize(buffer.size() * 2);
    }
}

namespace {

std::wstring quote(const std::wstring& arg) {
    if (arg.find_first_of(L" \t\"") == std::wstring::npos) return arg;
    std::wstring out = L"\"";
    for (const wchar_t ch : arg) {
        if (ch == L'"') out += L'\\';
        out += ch;
    }
    return out + L"\"";
}

void rebind_std_handle(DWORD which, const wchar_t* name, DWORD access) {
    HANDLE handle = CreateFileW(name, access, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                OPEN_EXISTING, 0, nullptr);
    if (handle != INVALID_HANDLE_VALUE) SetStdHandle(which, handle);
}

void rebind_stdio() {
    rebind_std_handle(STD_INPUT_HANDLE, L"CONIN$", GENERIC_READ | GENERIC_WRITE);
    rebind_std_handle(STD_OUTPUT_HANDLE, L"CONOUT$", GENERIC_READ | GENERIC_WRITE);
    rebind_std_handle(STD_ERROR_HANDLE, L"CONOUT$", GENERIC_READ | GENERIC_WRITE);
    FILE* reopened = nullptr;
    freopen_s(&reopened, "CONIN$", "r", stdin);
    freopen_s(&reopened, "CONOUT$", "w", stdout);
    freopen_s(&reopened, "CONOUT$", "w", stderr);
}

// Redirected stdout (a pipe from ctest, a file) must survive console acquisition.
DWORD stdout_type() {
    const int descriptor = _fileno(stdout);
    if (descriptor < 0) return FILE_TYPE_UNKNOWN;
    const HANDLE handle = reinterpret_cast<HANDLE>(_get_osfhandle(descriptor));
    if (handle == INVALID_HANDLE_VALUE) return FILE_TYPE_UNKNOWN;
    SetLastError(0);
    return GetFileType(handle);
}

bool stdout_redirected() {
    const DWORD type = stdout_type();
    return type == FILE_TYPE_PIPE || type == FILE_TYPE_DISK;
}

}  // namespace

std::wstring join_args(const std::vector<std::wstring>& args) {
    std::wstring out;
    for (const std::wstring& arg : args) {
        if (!out.empty()) out += L' ';
        out += quote(arg);
    }
    return out;
}

int relaunch_elevated(const std::vector<std::wstring>& args) {
    const std::wstring exe = exe_path();
    const std::wstring params = join_args(args);

    SHELLEXECUTEINFOW info{};
    info.cbSize = sizeof(info);
    info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NO_CONSOLE;
    info.lpVerb = L"runas";
    info.lpFile = exe.c_str();
    info.lpParameters = params.empty() ? nullptr : params.c_str();
    info.lpDirectory = nullptr;
    info.nShow = SW_SHOWNORMAL;

    if (!ShellExecuteExW(&info)) {
        const DWORD error = GetLastError();
        if (error == ERROR_CANCELLED) {
            warn(L"Elevation cancelled.");
        } else {
            warn(L"Elevation failed: " + format_error(error));
        }
        return 0;
    }

    UniqueHandle process(info.hProcess);
    WaitForSingleObject(process.get(), INFINITE);  // keep the console alive
    DWORD code = 0;
    GetExitCodeProcess(process.get(), &code);
    return static_cast<int>(code);
}

bool attach_parent_console() {
    if (GetConsoleWindow()) return true;
    if (!AttachConsole(ATTACH_PARENT_PROCESS)) return false;
    if (!stdout_redirected()) rebind_stdio();
    return true;
}

void allocate_console() {
    if (GetConsoleWindow()) return;
    if (!AllocConsole()) return;
    SetConsoleTitleW(L"RecSpoof");
    if (!stdout_redirected()) rebind_stdio();  // the inherited stdout was never this console
}

void ensure_console() {
    static bool done = false;
    if (done) return;
    if (attach_parent_console()) {
        done = true;
        return;
    }
    if (stdout_redirected()) {  // captured output: no window wanted
        done = true;
        return;
    }
    allocate_console();
    done = GetConsoleWindow() != nullptr;
}

void ensure_admin(const std::vector<std::wstring>& args) {
    if (is_admin()) {
        if (!attach_parent_console()) allocate_console();  // the UI needs a console
        return;
    }
    std::exit(relaunch_elevated(args));
}

void enable_ansi() {
    HANDLE handle = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (GetConsoleMode(handle, &mode)) SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
}

void utf8_console() { SetConsoleOutputCP(CP_UTF8); }

bool ask_yes_no(const std::wstring& prompt) {
    write(prompt + L" ");
    const int key = _getch();
    return key == 'y' || key == 'Y';
}

void wait_key() {
    write_line();
    write_line(L"Press any key to close...");
    _getch();
}

}  // namespace recspoof
