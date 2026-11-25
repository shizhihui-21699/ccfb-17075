#include "pipesec/SecurePipe.h"

#include "ProcessInspector.h"
#include "Util.h"

#include <sddl.h>
#include <winsvc.h>

#include <algorithm>

namespace pipesec {

UniqueHandle::UniqueHandle(HANDLE handle) noexcept {
    reset(handle);
}

UniqueHandle::~UniqueHandle() {
    reset();
}

UniqueHandle::UniqueHandle(UniqueHandle&& other) noexcept : handle_(other.release()) {}

UniqueHandle& UniqueHandle::operator=(UniqueHandle&& other) noexcept {
    if (this != &other) {
        reset();
        handle_ = other.release();
    }
    return *this;
}

HANDLE UniqueHandle::release() noexcept {
    HANDLE result = handle_;
    handle_ = nullptr;
    return result;
}

void UniqueHandle::reset(HANDLE handle) noexcept {
    if (handle_ && handle_ != INVALID_HANDLE_VALUE) ::CloseHandle(handle_);
    handle_ = (handle == INVALID_HANDLE_VALUE) ? nullptr : handle;
}

std::wstring pipePath(const std::wstring& name) {
    if (util::startsWithIgnoreCase(name, L"\\\\.\\pipe\\")
        || util::startsWithIgnoreCase(name, L"\\\\?\\pipe\\")) {
        return name;
    }
    return L"\\\\.\\pipe\\" + name;
}

namespace {

UniqueHandle createInstance(const ServerOptions& options, bool first, std::wstring* error) {
    if (options.name.empty()) {
        if (error) *error = L"pipe name is empty";
        return {};
    }

    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!options.sddl.empty()) {
        if (!::ConvertStringSecurityDescriptorToSecurityDescriptorW(
                options.sddl.c_str(), SDDL_REVISION_1, &sd, nullptr)) {
            if (error) {
                *error = L"ConvertStringSecurityDescriptorToSecurityDescriptor failed: "
                          + util::formatWindowsError();
            }
            return {};
        }
    }

    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = sd;
    sa.bInheritHandle = FALSE;

    DWORD openMode = options.openAccess;
    if (first) openMode |= FILE_FLAG_FIRST_PIPE_INSTANCE;

    DWORD pipeMode = options.pipeType | options.readMode;
    pipeMode |= options.blocking ? PIPE_WAIT : PIPE_NOWAIT;
    if (options.rejectRemoteClients) pipeMode |= PIPE_REJECT_REMOTE_CLIENTS;

    HANDLE handle = ::CreateNamedPipeW(
        pipePath(options.name).c_str(), openMode, pipeMode, options.maxInstances,
        options.outputBufferSize, options.inputBufferSize, options.defaultTimeoutMs,
        options.sddl.empty() ? nullptr : &sa);

    if (sd) ::LocalFree(sd);

    if (handle == INVALID_HANDLE_VALUE) {
        if (error) *error = L"CreateNamedPipe failed: " + util::formatWindowsError();
        return {};
    }
    return UniqueHandle(handle);
}

bool expectedServicePidMatches(const std::wstring& serviceName, DWORD serverPid) {
    if (serviceName.empty()) return false;
    SC_HANDLE scm = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return false;
    SC_HANDLE service = ::OpenServiceW(scm, serviceName.c_str(), SERVICE_QUERY_STATUS);
    if (!service) {
        ::CloseServiceHandle(scm);
        return false;
    }

    DWORD needed = 0;
    std::vector<unsigned char> buffer(8192);
    auto* status = reinterpret_cast<SERVICE_STATUS_PROCESS*>(buffer.data());
    bool match = false;
    if (::QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
                               reinterpret_cast<LPBYTE>(status),
                               static_cast<DWORD>(buffer.size()), &needed)) {
        match = status->dwProcessId == serverPid;
    }

    ::CloseServiceHandle(service);
    ::CloseServiceHandle(scm);
    return match;
}

bool verifyServer(HANDLE handle, const ClientOptions& options,
                  ServerIdentity& identity, std::wstring& error) {
    ULONG pid = 0;
    if (!::GetNamedPipeServerProcessId(handle, &pid)) {
        error = L"GetNamedPipeServerProcessId failed: " + util::formatWindowsError();
        return false;
    }
    identity.processId = pid;
    ::GetNamedPipeServerSessionId(handle, reinterpret_cast<PULONG>(&identity.sessionId));

    ProcessResolver resolver;
    ProcessInfo process = resolver.get(pid);
    identity.imagePath = process.imagePath;
    identity.accountName = process.accountName;
    identity.accountSid = process.accountSid;
    identity.system = process.system;
    identity.elevated = process.elevated;

    if (!options.expectedImagePath.empty()) {
        std::wstring expected = options.expectedImagePath;
        bool matches;
        if (expected.find(L'\\') == std::wstring::npos
            && expected.find(L'/') == std::wstring::npos) {
            matches = util::equalsIgnoreCase(process.name, expected);
        } else {
            matches = util::equalsIgnoreCase(process.imagePath, util::expandPath(expected));
        }
        identity.expectedImageMatched = matches;
        if (!matches) {
            error = L"pipe server image mismatch: actual=" + process.imagePath
                     + L" expected=" + expected;
            return false;
        }
    }

    if (!options.expectedServiceName.empty()) {
        identity.expectedServiceMatched =
            expectedServicePidMatches(options.expectedServiceName, pid);
        if (!identity.expectedServiceMatched) {
            error = L"pipe server PID " + std::to_wstring(pid)
                     + L" does not host service " + options.expectedServiceName;
            return false;
        }
    }

    if (options.requireSystemOrElevated && !identity.system && !identity.elevated) {
        error = L"pipe server is not SYSTEM or elevated: " + identity.accountName;
        return false;
    }
    return true;
}

}  // namespace

UniqueHandle createFirstServerInstance(const ServerOptions& options, std::wstring* error) {
    return createInstance(options, true, error);
}

UniqueHandle createServerInstance(const ServerOptions& options, std::wstring* error) {
    return createInstance(options, false, error);
}

bool waitForClient(HANDLE serverPipe, std::wstring* error) {
    if (::ConnectNamedPipe(serverPipe, nullptr)) return true;
    DWORD gle = ::GetLastError();
    if (gle == ERROR_PIPE_CONNECTED) return true;
    if (error) *error = L"ConnectNamedPipe failed: " + util::formatWindowsError(gle);
    return false;
}

ClientImpersonation::ClientImpersonation(HANDLE serverPipe) noexcept {
    if (!serverPipe || serverPipe == INVALID_HANDLE_VALUE) return;
    if (!::ImpersonateNamedPipeClient(serverPipe)) return;
    identity_.impersonated = true;

    HANDLE token = nullptr;
    if (!::OpenThreadToken(::GetCurrentThread(), TOKEN_QUERY, FALSE, &token)) {
        ::OpenThreadToken(::GetCurrentThread(), TOKEN_QUERY, TRUE, &token);
    }
    if (token) {
        DWORD needed = 0;
        ::GetTokenInformation(token, TokenUser, nullptr, 0, &needed);
        if (needed) {
            std::vector<unsigned char> buffer(needed);
            auto* user = reinterpret_cast<TOKEN_USER*>(buffer.data());
            if (::GetTokenInformation(token, TokenUser, user, needed, &needed)) {
                SidInfo sid = util::lookupSid(user->User.Sid);
                identity_.sid = sid.sid;
                identity_.accountName = sid.displayName;
                identity_.system = util::equalWellKnownSid(user->User.Sid, WinLocalSystemSid);
            }
        }

        TOKEN_ELEVATION elevation{};
        DWORD size = sizeof(elevation);
        if (::GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size)) {
            identity_.elevated = elevation.TokenIsElevated != 0;
        }
        ::CloseHandle(token);
    }
}

ClientImpersonation::~ClientImpersonation() {
    if (identity_.impersonated) ::RevertToSelf();
}

UniqueHandle connectSecureClient(const ClientOptions& options,
                                 ServerIdentity* serverIdentity,
                                 std::wstring* error) {
    if (options.name.empty()) {
        if (error) *error = L"pipe name is empty";
        return {};
    }
    if (options.allowImpersonation && !options.acknowledgeImpersonationRace) {
        if (error) {
            *error = L"allowImpersonation=true requires acknowledgeImpersonationRace=true; "
                     L"an untrusted server can duplicate the client token before post-connect checks";
        }
        return {};
    }

    ULONGLONG deadline = ::GetTickCount64() + options.timeoutMs;
    std::wstring path = pipePath(options.name);
    DWORD sqos = SECURITY_SQOS_PRESENT
                 | (options.allowImpersonation ? SECURITY_IMPERSONATION
                                               : SECURITY_IDENTIFICATION);

    while (true) {
        HANDLE raw = ::CreateFileW(path.c_str(), options.desiredAccess, 0, nullptr,
                                   OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | sqos, nullptr);
        if (raw != INVALID_HANDLE_VALUE) {
            UniqueHandle handle(raw);
            ServerIdentity identity;
            std::wstring verifyError;
            if (options.verifyServer
                && !verifyServer(handle.get(), options, identity, verifyError)) {
                if (serverIdentity) *serverIdentity = identity;
                if (error) *error = verifyError;
                return {};
            }
            if (serverIdentity) *serverIdentity = identity;
            return handle;
        }

        DWORD gle = ::GetLastError();
        ULONGLONG now = ::GetTickCount64();
        if (now >= deadline) {
            if (error) *error = L"connect timed out/failed: " + util::formatWindowsError(gle);
            return {};
        }

        DWORD remaining = static_cast<DWORD>(deadline - now);
        if (gle == ERROR_PIPE_BUSY) {
            DWORD waitMs = std::min<DWORD>(remaining, 1000);
            if (!::WaitNamedPipeW(path.c_str(), waitMs)) {
                // Retry CreateFile until the overall deadline.
            }
            continue;
        }
        if (gle == ERROR_FILE_NOT_FOUND || gle == ERROR_PATH_NOT_FOUND) {
            ::Sleep(std::min<DWORD>(50, remaining));
            continue;
        }
        if (gle == ERROR_ACCESS_DENIED) {
            if (error) *error = L"access denied by pipe ACL: " + util::formatWindowsError(gle);
            return {};
        }
        ::Sleep(std::min<DWORD>(50, remaining));
    }
}

}  // namespace pipesec
