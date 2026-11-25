#include "ProcessInspector.h"

#include "Util.h"

#include <tlhelp32.h>

namespace pipesec {

void ProcessResolver::setServices(const std::vector<ServiceInfo>& services) {
    serviceNamesByPid_.clear();
    for (const auto& service : services) {
        if (service.pid != 0) serviceNamesByPid_[service.pid].push_back(service.name);
    }
}

void ProcessResolver::ensureParentMap() {
    if (parentsBuilt_) return;
    parentsBuilt_ = true;

    HANDLE snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (::Process32FirstW(snapshot, &entry)) {
        do {
            parents_[entry.th32ProcessID] = entry.th32ParentProcessID;
        } while (::Process32NextW(snapshot, &entry));
    }
    ::CloseHandle(snapshot);
}

ProcessInfo ProcessResolver::get(uint32_t pid) {
    auto cached = cache_.find(pid);
    if (cached != cache_.end()) return cached->second;

    ensureParentMap();
    ProcessInfo info;
    info.pid = pid;
    if (auto parent = parents_.find(pid); parent != parents_.end()) {
        info.parentPid = parent->second;
    }
    if (auto services = serviceNamesByPid_.find(pid); services != serviceNamesByPid_.end()) {
        info.services = services->second;
    }

    if (pid == 0) {
        info.name = L"[System Idle Process]";
        info.system = true;
        info.accountName = L"NT AUTHORITY\\SYSTEM";
        info.accountSid = L"S-1-5-18";
    } else if (pid == 4) {
        info.name = L"System";
        info.system = true;
        info.accountName = L"NT AUTHORITY\\SYSTEM";
        info.accountSid = L"S-1-5-18";
    }

    HANDLE process = ::OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    bool limited = false;
    if (!process) {
        process = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        limited = process != nullptr;
    }

    if (process) {
        wchar_t imagePath[MAX_PATH * 2] = {};
        DWORD size = static_cast<DWORD>(std::size(imagePath));
        if (::QueryFullProcessImageNameW(process, 0, imagePath, &size)) {
            info.imagePath = imagePath;
            size_t slash = info.imagePath.find_last_of(L"\\/");
            info.name = slash == std::wstring::npos ? info.imagePath
                                                    : info.imagePath.substr(slash + 1);
        } else if (info.name.empty()) {
            info.errors.push_back(L"QueryFullProcessImageName: "
                                  + util::formatWindowsError());
        }

        FILETIME createTime{}, exitTime{}, kernelTime{}, userTime{};
        if (::GetProcessTimes(process, &createTime, &exitTime, &kernelTime, &userTime)) {
            ULARGE_INTEGER value{};
            value.LowPart = createTime.dwLowDateTime;
            value.HighPart = createTime.dwHighDateTime;
            info.creationTime100ns = value.QuadPart;
            info.creationTimeUtc = util::fileTimeToUtcString(value.QuadPart);
        }

        if (!limited) {
            HANDLE token = nullptr;
            if (::OpenProcessToken(process, TOKEN_QUERY, &token)) {
                DWORD needed = 0;
                ::GetTokenInformation(token, TokenUser, nullptr, 0, &needed);
                if (needed) {
                    std::vector<unsigned char> buffer(needed);
                    TOKEN_USER* user = reinterpret_cast<TOKEN_USER*>(buffer.data());
                    if (::GetTokenInformation(token, TokenUser, user, needed, &needed)) {
                        SidInfo sid = util::lookupSid(user->User.Sid);
                        info.accountSid = sid.sid;
                        info.accountName = sid.displayName;
                        info.system = util::equalWellKnownSid(user->User.Sid, WinLocalSystemSid);
                        info.localService =
                            util::equalWellKnownSid(user->User.Sid, WinLocalServiceSid);
                        info.networkService =
                            util::equalWellKnownSid(user->User.Sid, WinNetworkServiceSid);
                    }
                }

                TOKEN_ELEVATION elevation{};
                DWORD returnLength = 0;
                if (::GetTokenInformation(token, TokenElevation, &elevation,
                                          sizeof(elevation), &returnLength)) {
                    info.elevated = elevation.TokenIsElevated != 0;
                }
                ::CloseHandle(token);
            } else {
                info.errors.push_back(L"OpenProcessToken: " + util::formatWindowsError());
            }
        }
        ::CloseHandle(process);
    } else if (pid != 0 && pid != 4) {
        info.errors.push_back(L"OpenProcess: " + util::formatWindowsError());
    }

    if (info.system) info.elevated = true;
    cache_[pid] = info;
    return info;
}

}  // namespace pipesec
