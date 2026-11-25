#include "ServiceHunter.h"

#include "Util.h"

#include <windows.h>

#include <algorithm>
#include <unordered_set>

namespace pipesec {

namespace {

bool isNameChar(uint32_t ch) {
    if (ch < 0x21 || ch == 0x7f) return false;
    switch (ch) {
        case L'"': case L'\'': case L'<': case L'>': case L'|':
        case L'?': case L'*': case L'\\': case L'/':
        case L',': case L';':
            return false;
        default:
            return true;
    }
}

bool narrowPrefixAt(const std::vector<unsigned char>& bytes, size_t pos,
                    const char* prefix) {
    size_t len = std::char_traits<char>::length(prefix);
    if (pos + len > bytes.size()) return false;
    for (size_t i = 0; i < len; ++i) {
        unsigned char a = bytes[pos + i];
        unsigned char b = static_cast<unsigned char>(prefix[i]);
        if (a >= 'A' && a <= 'Z') a = static_cast<unsigned char>(a - 'A' + 'a');
        if (b >= 'A' && b <= 'Z') b = static_cast<unsigned char>(b - 'A' + 'a');
        if (a != b) return false;
    }
    return true;
}

bool widePrefixAt(const std::vector<unsigned char>& bytes, size_t pos,
                  const char* asciiPrefix) {
    size_t len = std::char_traits<char>::length(asciiPrefix);
    if (pos + len * 2 > bytes.size()) return false;
    for (size_t i = 0; i < len; ++i) {
        unsigned char expected = static_cast<unsigned char>(asciiPrefix[i]);
        unsigned char actual = bytes[pos + i * 2];
        unsigned char zero = bytes[pos + i * 2 + 1];
        if (actual >= 'A' && actual <= 'Z') actual = static_cast<unsigned char>(actual + 32);
        if (expected >= 'A' && expected <= 'Z') expected = static_cast<unsigned char>(expected + 32);
        if (zero != 0 || actual != expected) return false;
    }
    return true;
}

std::wstring parseNarrowName(const std::vector<unsigned char>& bytes, size_t start) {
    size_t end = start;
    while (end < bytes.size() && isNameChar(bytes[end])) ++end;
    if (end <= start) return {};
    std::string raw(reinterpret_cast<const char*>(bytes.data() + start), end - start);
    return util::utf8ToWide(raw);
}

std::wstring parseWideName(const std::vector<unsigned char>& bytes, size_t start) {
    std::wstring name;
    size_t pos = start;
    while (pos + 1 < bytes.size()) {
        uint32_t ch = static_cast<uint32_t>(bytes[pos])
                      | (static_cast<uint32_t>(bytes[pos + 1]) << 8);
        if (!isNameChar(ch)) break;
        name.push_back(static_cast<wchar_t>(ch));
        pos += 2;
    }
    return name;
}

std::wstring readServiceDll(const std::wstring& serviceName) {
    std::wstring subkey = L"SYSTEM\\CurrentControlSet\\Services\\" + serviceName + L"\\Parameters";
    HKEY key = nullptr;
    if (::RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey.c_str(), 0,
                        KEY_READ | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS) {
        return {};
    }

    DWORD type = 0;
    DWORD size = 0;
    LSTATUS rc = ::RegQueryValueExW(key, L"ServiceDll", nullptr, &type, nullptr, &size);
    if (rc != ERROR_SUCCESS || size < sizeof(wchar_t)) {
        ::RegCloseKey(key);
        return {};
    }

    std::vector<unsigned char> buffer(size + sizeof(wchar_t));
    rc = ::RegQueryValueExW(key, L"ServiceDll", nullptr, &type, buffer.data(), &size);
    ::RegCloseKey(key);
    if (rc != ERROR_SUCCESS) return {};

    auto* text = reinterpret_cast<wchar_t*>(buffer.data());
    size_t chars = size / sizeof(wchar_t);
    text[chars] = L'\0';
    std::wstring path(text);
    if (type == REG_EXPAND_SZ) path = util::expandPath(path);
    return path;
}

bool containsTokenNarrow(const std::vector<unsigned char>& bytes, const char* token) {
    std::string_view needle(token);
    if (needle.empty() || bytes.size() < needle.size()) return false;
    for (size_t i = 0; i + needle.size() <= bytes.size(); ++i) {
        bool match = true;
        for (size_t j = 0; j < needle.size(); ++j) {
            unsigned char a = bytes[i + j];
            unsigned char b = static_cast<unsigned char>(needle[j]);
            if (a >= 'A' && a <= 'Z') a += 32;
            if (b >= 'A' && b <= 'Z') b += 32;
            if (a != b) { match = false; break; }
        }
        if (match) return true;
    }
    return false;
}

bool containsTokenWide(const std::vector<unsigned char>& bytes, const char* token) {
    size_t len = std::char_traits<char>::length(token);
    if (bytes.size() < len * 2) return false;
    for (size_t i = 0; i + len * 2 <= bytes.size(); i += 2) {
        if (widePrefixAt(bytes, i, token)) return true;
    }
    return false;
}

}  // namespace

std::vector<std::wstring> extractPipeNamesFromBytes(const std::vector<unsigned char>& bytes) {
    static const char* kPrefixes[] = {
        "\\\\.\\pipe\\",
        "\\\\?\\pipe\\",
        "\\Device\\NamedPipe\\"
    };

    std::vector<std::wstring> names;
    std::unordered_set<std::wstring> seen;

    auto add = [&](std::wstring name) {
        while (!name.empty() && (name.back() == L'.' || name.back() == L' ')) name.pop_back();
        if (name.size() < 3 || name.size() > 255) return;
        bool hasAlpha = false;
        for (wchar_t c : name) {
            if ((c >= L'a' && c <= L'z') || (c >= L'A' && c <= L'Z')) hasAlpha = true;
        }
        if (!hasAlpha) return;
        std::wstring key = util::lowerWide(name);
        if (seen.insert(key).second) names.push_back(std::move(name));
    };

    for (size_t i = 0; i < bytes.size(); ++i) {
        if (bytes[i] != '\\') continue;

        for (const char* prefix : kPrefixes) {
            size_t prefixLen = std::char_traits<char>::length(prefix);
            if (narrowPrefixAt(bytes, i, prefix)) {
                add(parseNarrowName(bytes, i + prefixLen));
                break;
            }
        }

        if (i + 1 < bytes.size() && bytes[i + 1] == 0) {
            for (const char* prefix : kPrefixes) {
                size_t prefixLen = std::char_traits<char>::length(prefix);
                if (widePrefixAt(bytes, i, prefix)) {
                    add(parseWideName(bytes, i + prefixLen * 2));
                    break;
                }
            }
        }
    }
    return names;
}

bool bytesContainImpersonationHint(const std::vector<unsigned char>& bytes) {
    static const char* kToken = "ImpersonateNamedPipeClient";
    return containsTokenNarrow(bytes, kToken) || containsTokenWide(bytes, kToken);
}

std::vector<ServiceInfo> enumerateServices() {
    std::vector<ServiceInfo> result;
    SC_HANDLE scm = ::OpenSCManagerW(nullptr, nullptr,
                                     SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) return result;

    DWORD needed = 0;
    DWORD count = 0;
    DWORD resume = 0;
    ::EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
                            SERVICE_STATE_ALL, nullptr, 0, &needed, &count, &resume, nullptr);
    if (needed == 0) {
        ::CloseServiceHandle(scm);
        return result;
    }

    std::vector<unsigned char> buffer(needed);
    if (!::EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
                                 SERVICE_STATE_ALL, buffer.data(),
                                 static_cast<DWORD>(buffer.size()), &needed, &count,
                                 &resume, nullptr)) {
        ::CloseServiceHandle(scm);
        return result;
    }

    auto* services = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(buffer.data());
    result.reserve(count);
    for (DWORD i = 0; i < count; ++i) {
        ServiceInfo info;
        info.name = services[i].lpServiceName ? services[i].lpServiceName : L"";
        info.displayName = services[i].lpDisplayName ? services[i].lpDisplayName : L"";
        info.state = services[i].ServiceStatusProcess.dwCurrentState;
        info.pid = services[i].ServiceStatusProcess.dwProcessId;

        SC_HANDLE service = ::OpenServiceW(scm, info.name.c_str(), SERVICE_QUERY_CONFIG);
        if (service) {
            DWORD configNeeded = 0;
            ::QueryServiceConfigW(service, nullptr, 0, &configNeeded);
            if (configNeeded) {
                std::vector<unsigned char> configBuffer(configNeeded);
                auto* config = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(configBuffer.data());
                if (::QueryServiceConfigW(service, config, configNeeded, &configNeeded)) {
                    info.startType = config->dwStartType;
                    info.binaryPath = config->lpBinaryPathName ? config->lpBinaryPathName : L"";
                    info.startAccount = config->lpServiceStartName ? config->lpServiceStartName : L"";
                    std::wstring account = util::lowerWide(info.startAccount);
                    info.systemAccount = info.startAccount.empty()
                        || account.find(L"localsystem") != std::wstring::npos
                        || account.find(L"\\system") != std::wstring::npos
                        || account == L"s-1-5-18";
                }
            }
            ::CloseServiceHandle(service);
        }
        result.push_back(std::move(info));
    }

    ::CloseServiceHandle(scm);
    return result;
}

std::vector<ServicePipeReference> findServicePipeReferences(
    const std::vector<ServiceInfo>& services,
    const AuditOptions& options) {
    std::vector<ServicePipeReference> references;
    if (!options.scanServiceBinaries) return references;

    for (const ServiceInfo& service : services) {
        std::vector<std::wstring> files;
        std::unordered_set<std::wstring> fileSeen;

        std::wstring image = util::extractImagePath(util::expandPath(service.binaryPath));
        if (!image.empty() && fileSeen.insert(util::lowerWide(image)).second) {
            files.push_back(image);
        }

        std::wstring serviceDll = readServiceDll(service.name);
        if (!serviceDll.empty() && fileSeen.insert(util::lowerWide(serviceDll)).second) {
            files.push_back(serviceDll);
        }

        for (const std::wstring& file : files) {
            auto bytes = util::readFileBytes(file, options.maxBinaryBytes);
            if (!bytes) continue;

            bool impersonationHint = bytesContainImpersonationHint(*bytes);
            std::vector<std::wstring> names = extractPipeNamesFromBytes(*bytes);
            for (const std::wstring& name : names) {
                ServicePipeReference ref;
                ref.pipeName = name;
                ref.normalizedName = util::lowerWide(name);
                ref.serviceName = service.name;
                ref.serviceDisplayName = service.displayName;
                ref.binaryPath = service.binaryPath;
                ref.scannedFile = file;
                ref.servicePid = service.pid;
                ref.startType = service.startType;
                ref.startAccount = service.startAccount;
                ref.runningAsSystem = service.systemAccount;
                ref.impersonateApiHint = impersonationHint;
                ref.formatTemplate = name.find(L'%') != std::wstring::npos;
                references.push_back(std::move(ref));
            }
        }
    }

    return references;
}

}  // namespace pipesec
