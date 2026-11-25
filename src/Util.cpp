#include "Util.h"

#include <sddl.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <system_error>

namespace pipesec {

const char* severityName(Severity severity) noexcept {
    switch (severity) {
        case Severity::Info: return "info";
        case Severity::Low: return "low";
        case Severity::Medium: return "medium";
        case Severity::High: return "high";
        case Severity::Critical: return "critical";
    }
    return "unknown";
}

std::optional<Severity> parseSeverity(const std::string& text) noexcept {
    std::string lower;
    lower.reserve(text.size());
    for (char c : text) lower.push_back(static_cast<char>(::tolower(static_cast<unsigned char>(c))));
    if (lower == "info" || lower == "informational") return Severity::Info;
    if (lower == "low") return Severity::Low;
    if (lower == "medium" || lower == "med") return Severity::Medium;
    if (lower == "high") return Severity::High;
    if (lower == "critical" || lower == "crit") return Severity::Critical;
    return std::nullopt;
}

}  // namespace pipesec

namespace pipesec::util {

std::wstring utf8ToWide(const std::string& value) {
    if (value.empty()) return {};
    int count = ::MultiByteToWideChar(CP_UTF8, 0, value.data(),
                                      static_cast<int>(value.size()), nullptr, 0);
    if (count <= 0) return {};
    std::wstring result(static_cast<size_t>(count), L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()),
                          result.data(), count);
    return result;
}

std::string wideToUtf8(const std::wstring& value) {
    if (value.empty()) return {};
    int count = ::WideCharToMultiByte(CP_UTF8, 0, value.data(),
                                      static_cast<int>(value.size()), nullptr, 0,
                                      nullptr, nullptr);
    if (count <= 0) return {};
    std::string result(static_cast<size_t>(count), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()),
                          result.data(), count, nullptr, nullptr);
    return result;
}

std::string wideToUtf8(PCWSTR value) {
    if (!value) return {};
    return wideToUtf8(std::wstring(value));
}

std::wstring lowerWide(std::wstring value) {
    if (value.empty()) return value;
    int needed = ::LCMapStringEx(LOCALE_NAME_INVARIANT, LCMAP_LOWERCASE, value.data(),
                                 static_cast<int>(value.size()), value.data(),
                                 static_cast<int>(value.size()), nullptr, nullptr, 0);
    if (needed == 0) {
        for (wchar_t& c : value) c = static_cast<wchar_t>(::towlower(c));
    }
    return value;
}

std::string lowerAscii(std::string value) {
    for (char& c : value) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    return value;
}

bool startsWithIgnoreCase(std::wstring_view value, std::wstring_view prefix) {
    if (value.size() < prefix.size()) return false;
    return ::CompareStringOrdinal(value.data(), static_cast<int>(prefix.size()),
                                  prefix.data(), static_cast<int>(prefix.size()), TRUE) == CSTR_EQUAL;
}

bool containsIgnoreCase(std::wstring_view value, std::wstring_view needle) {
    if (needle.empty()) return true;
    if (value.size() < needle.size()) return false;
    for (size_t i = 0; i + needle.size() <= value.size(); ++i) {
        if (::CompareStringOrdinal(value.data() + i, static_cast<int>(needle.size()),
                                   needle.data(), static_cast<int>(needle.size()), TRUE)
            == CSTR_EQUAL) {
            return true;
        }
    }
    return false;
}

bool equalsIgnoreCase(std::wstring_view a, std::wstring_view b) {
    if (a.size() != b.size()) return false;
    return ::CompareStringOrdinal(a.data(), static_cast<int>(a.size()), b.data(),
                                  static_cast<int>(b.size()), TRUE) == CSTR_EQUAL;
}

std::string jsonEscape(std::string_view value) {
    std::string out;
    out.reserve(value.size() + 8);
    for (unsigned char c : value) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out.push_back(static_cast<char>(c));
                }
        }
    }
    return out;
}

std::string toJson(const std::wstring& value) {
    return "\"" + jsonEscape(wideToUtf8(value)) + "\"";
}

std::string toJson(const std::string& value) {
    return "\"" + jsonEscape(value) + "\"";
}

std::string fileTimeToUtcString(uint64_t fileTime100ns) {
    if (fileTime100ns == 0) return {};
    constexpr uint64_t kTicksPerSecond = 10000000ULL;
    constexpr uint64_t kEpochDifference = 116444736000000000ULL;
    if (fileTime100ns < kEpochDifference) return {};
    time_t unixSeconds = static_cast<time_t>((fileTime100ns - kEpochDifference) / kTicksPerSecond);
    std::tm tm{};
    if (gmtime_s(&tm, &unixSeconds) != 0) return {};
    char buffer[32];
    if (std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", &tm) == 0) return {};
    return buffer;
}

std::string nowUtcString() {
    return fileTimeToUtcString(static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count() / 100) + 116444736000000000ULL);
}

int64_t unixSecondsNow() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::string unixSecondsToUtcString(int64_t seconds) {
    time_t t = static_cast<time_t>(seconds);
    std::tm tm{};
    if (gmtime_s(&tm, &t) != 0) return {};
    char buffer[32];
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buffer;
}

std::wstring sidToString(PSID sid) {
    if (!sid || !::IsValidSid(sid)) return L"";
    LPWSTR raw = nullptr;
    if (!::ConvertSidToStringSidW(sid, &raw) || !raw) return L"";
    std::wstring result(raw);
    ::LocalFree(raw);
    return result;
}

bool equalWellKnownSid(PSID sid, WELL_KNOWN_SID_TYPE type) {
    if (!sid || !::IsValidSid(sid)) return false;
    DWORD size = SECURITY_MAX_SID_SIZE;
    std::vector<unsigned char> storage(size);
    PSID wellKnown = reinterpret_cast<PSID>(storage.data());
    if (!::CreateWellKnownSid(type, nullptr, wellKnown, &size)) return false;
    return ::EqualSid(sid, wellKnown) != FALSE;
}

SidInfo lookupSid(PSID sid) {
    SidInfo info;
    if (!sid || !::IsValidSid(sid)) return info;
    info.sid = sidToString(sid);

    wchar_t name[256] = {};
    wchar_t domain[256] = {};
    DWORD nameSize = static_cast<DWORD>(std::size(name));
    DWORD domainSize = static_cast<DWORD>(std::size(domain));
    SID_NAME_USE use = SidTypeUnknown;
    if (::LookupAccountSidW(nullptr, sid, name, &nameSize, domain, &domainSize, &use)) {
        info.name = name;
        info.domain = domain;
        info.displayName = info.domain.empty() ? info.name : info.domain + L"\\" + info.name;
    } else {
        info.displayName = info.sid;
    }

    auto addTag = [&](const char* tag) { info.tags.emplace_back(tag); };

    if (equalWellKnownSid(sid, WinWorldSid)) {
        info.broadUntrusted = true;
        addTag("everyone");
    }
    if (equalWellKnownSid(sid, WinAnonymousSid)) {
        info.broadUntrusted = true;
        addTag("anonymous");
    }
    if (equalWellKnownSid(sid, WinAuthenticatedUserSid)) {
        info.broadUntrusted = true;
        addTag("authenticated-users");
    }
    if (equalWellKnownSid(sid, WinBuiltinUsersSid)) {
        info.broadUntrusted = true;
        addTag("builtin-users");
    }
    if (equalWellKnownSid(sid, WinBuiltinGuestsSid)) {
        info.broadUntrusted = true;
        addTag("guests");
    }
    if (equalWellKnownSid(sid, WinInteractiveSid)) {
        info.broadUntrusted = true;
        addTag("interactive");
    }
    if (equalWellKnownSid(sid, WinNetworkSid)) {
        info.broadUntrusted = true;
        addTag("network-logon");
    }
    if (equalWellKnownSid(sid, WinBuiltinAnyPackageSid)) {
        info.broadUntrusted = true;
        addTag("all-application-packages");
    }
    if (equalWellKnownSid(sid, WinRestrictedCodeSid)) {
        info.broadUntrusted = true;
        addTag("restricted-code");
    }
    if (equalWellKnownSid(sid, WinLocalSystemSid)) {
        info.privileged = true;
        addTag("local-system");
    }
    if (equalWellKnownSid(sid, WinBuiltinAdministratorsSid)) {
        info.privileged = true;
        addTag("administrators");
    }
    if (equalWellKnownSid(sid, WinLocalServiceSid)) addTag("local-service");
    if (equalWellKnownSid(sid, WinNetworkServiceSid)) addTag("network-service");

    if (info.sid.rfind(L"S-1-15-2-", 0) == 0) {
        // S-1-15-2-1 is All Application Packages and is caught above. Other
        // S-1-15-2-* values are package-specific rather than broad groups.
        if (info.sid == L"S-1-15-2-2") {
            info.broadUntrusted = true;
            addTag("all-restricted-app-packages");
        } else {
            addTag("app-container-package");
        }
    }
    return info;
}

SidInfo lookupSidString(const std::wstring& sidString) {
    SidInfo info;
    PSID rawSid = nullptr;
    if (!::ConvertStringSidToSidW(sidString.c_str(), &rawSid) || !rawSid) {
        info.sid = sidString;
        info.displayName = sidString;
        return info;
    }
    info = lookupSid(rawSid);
    ::LocalFree(rawSid);
    return info;
}

bool enablePrivilege(const wchar_t* privilegeName) {
    HANDLE token = nullptr;
    if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        return false;
    }
    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    bool ok = false;
    if (::LookupPrivilegeValueW(nullptr, privilegeName, &tp.Privileges[0].Luid)) {
        ok = ::AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr) != FALSE
             && ::GetLastError() != ERROR_NOT_ALL_ASSIGNED;
    }
    ::CloseHandle(token);
    return ok;
}

bool isElevated() {
    HANDLE token = nullptr;
    if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
    TOKEN_ELEVATION elevation{};
    DWORD size = sizeof(elevation);
    bool elevated = false;
    if (::GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size)) {
        elevated = elevation.TokenIsElevated != 0;
    }
    ::CloseHandle(token);
    return elevated;
}

std::wstring currentHostName() {
    wchar_t buffer[MAX_COMPUTERNAME_LENGTH + 1] = {};
    DWORD size = static_cast<DWORD>(std::size(buffer));
    if (::GetComputerNameW(buffer, &size)) return buffer;
    return L"";
}

std::wstring formatWindowsError(DWORD error) {
    LPWSTR message = nullptr;
    DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM
                  | FORMAT_MESSAGE_IGNORE_INSERTS;
    DWORD size = ::FormatMessageW(flags, nullptr, error, 0,
                                  reinterpret_cast<LPWSTR>(&message), 0, nullptr);
    std::wstring result;
    if (size && message) {
        result.assign(message, size);
        while (!result.empty() && (result.back() == L'\r' || result.back() == L'\n'
                                   || result.back() == L' ')) {
            result.pop_back();
        }
    } else {
        result = L"Error " + std::to_wstring(error);
    }
    if (message) ::LocalFree(message);
    return result;
}

std::optional<std::vector<unsigned char>> readFileBytes(
    const std::wstring& path, size_t maxBytes) {
    HANDLE file = ::CreateFileW(path.c_str(), GENERIC_READ,
                                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return std::nullopt;

    LARGE_INTEGER fileSize{};
    std::vector<unsigned char> bytes;
    if (::GetFileSizeEx(file, &fileSize) && fileSize.QuadPart > 0
        && static_cast<uint64_t>(fileSize.QuadPart) <= maxBytes) {
        bytes.resize(static_cast<size_t>(fileSize.QuadPart));
        DWORD read = 0;
        size_t offset = 0;
        bool ok = true;
        while (offset < bytes.size()) {
            DWORD chunk = static_cast<DWORD>(std::min<size_t>(1u << 20, bytes.size() - offset));
            if (!::ReadFile(file, bytes.data() + offset, chunk, &read, nullptr) || read == 0) {
                ok = false;
                break;
            }
            offset += read;
        }
        if (!ok) bytes.clear();
    }
    ::CloseHandle(file);
    if (bytes.empty()) return std::nullopt;
    return bytes;
}

std::wstring expandPath(const std::wstring& rawPath) {
    if (rawPath.empty()) return rawPath;
    std::wstring replaced = rawPath;
    if (startsWithIgnoreCase(replaced, L"\\SystemRoot\\")) {
        wchar_t windowsDir[MAX_PATH] = {};
        DWORD n = ::GetWindowsDirectoryW(windowsDir, MAX_PATH);
        if (n > 0 && n < MAX_PATH) {
            replaced = std::wstring(windowsDir) + L"\\" + replaced.substr(12);
        }
    }
    DWORD needed = ::ExpandEnvironmentStringsW(replaced.c_str(), nullptr, 0);
    if (needed == 0) return replaced;
    std::wstring result(needed, L'\0');
    DWORD written = ::ExpandEnvironmentStringsW(replaced.c_str(), result.data(), needed);
    if (written == 0) return replaced;
    result.resize(written - 1);
    return result;
}

std::wstring extractImagePath(const std::wstring& binPath) {
    std::wstring s = binPath;
    while (!s.empty() && (s.front() == L' ' || s.front() == L'\t')) s.erase(s.begin());
    if (s.empty()) return L"";

    if (s.front() == L'"') {
        size_t end = s.find(L'"', 1);
        if (end != std::wstring::npos) return s.substr(1, end - 1);
    }

    // Unquoted service paths frequently contain arguments. Prefer to cut at
    // ".exe"; otherwise cut at the first whitespace.
    std::wstring lower = lowerWide(s);
    size_t exe = lower.find(L".exe");
    if (exe != std::wstring::npos) return s.substr(0, exe + 4);

    size_t space = s.find_first_of(L" \t");
    return space == std::wstring::npos ? s : s.substr(0, space);
}

}  // namespace pipesec::util
