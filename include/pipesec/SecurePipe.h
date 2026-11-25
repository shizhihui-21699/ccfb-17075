#pragma once

// Secure named-pipe creation and client connection wrappers for Windows.
//
// The defaults are deliberately conservative:
//   * protected DACL granting only SYSTEM and Administrators;
//   * FILE_FLAG_FIRST_PIPE_INSTANCE for the first server instance;
//   * PIPE_REJECT_REMOTE_CLIENTS;
//   * clients present SecurityIdentification, not SecurityImpersonation;
//   * clients verify the server PID/image/service identity after connecting.
//
// Important token-theft note:
// A high-privilege client that opens a rogue server with SecurityImpersonation
// may be impersonated and have a token duplicated before the client performs a
// post-connect PID check. Therefore keep allowImpersonation=false unless the
// pipe DACL guarantees that only a trusted service SID can create instances and
// your deployment controls the service-start race. SecurityIdentification lets
// the server identify/authorize the client but does not yield an impersonation
// token usable to access objects as that client.

#include <cstdint>
#include <string>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

namespace pipesec {

class UniqueHandle {
public:
    UniqueHandle() = default;
    explicit UniqueHandle(HANDLE handle) noexcept;
    ~UniqueHandle();

    UniqueHandle(const UniqueHandle&) = delete;
    UniqueHandle& operator=(const UniqueHandle&) = delete;
    UniqueHandle(UniqueHandle&& other) noexcept;
    UniqueHandle& operator=(UniqueHandle&& other) noexcept;

    HANDLE get() const noexcept { return handle_; }
    HANDLE release() noexcept;
    void reset(HANDLE handle = nullptr) noexcept;
    explicit operator bool() const noexcept { return handle_ != nullptr; }

private:
    HANDLE handle_ = nullptr;
};

struct ServerOptions {
    std::wstring name;
    // Override with a SID-specific DACL for production, for example adding
    // NT SERVICE\<YourService> and a dedicated client group.
    std::wstring sddl = L"D:P(A;;GA;;;SY)(A;;GA;;;BA)";

    DWORD openAccess = PIPE_ACCESS_DUPLEX;
    DWORD pipeType = PIPE_TYPE_MESSAGE;
    DWORD readMode = PIPE_READMODE_MESSAGE;
    bool blocking = true;
    bool rejectRemoteClients = true;

    DWORD maxInstances = PIPE_UNLIMITED_INSTANCES;
    DWORD outputBufferSize = 64 * 1024;
    DWORD inputBufferSize = 64 * 1024;
    DWORD defaultTimeoutMs = 50;
};

// Creates the first instance and atomically fails if another creator already
// owns the name (including a squatting low-privilege process).
UniqueHandle createFirstServerInstance(const ServerOptions& options,
                                       std::wstring* error = nullptr);

// Creates an additional instance. Do not add FILE_FLAG_FIRST_PIPE_INSTANCE here.
UniqueHandle createServerInstance(const ServerOptions& options,
                                  std::wstring* error = nullptr);

bool waitForClient(HANDLE serverPipe, std::wstring* error = nullptr);

struct ClientIdentity {
    bool impersonated = false;
    std::wstring sid;
    std::wstring accountName;
    bool system = false;
    bool elevated = false;
};

// Calls ImpersonateNamedPipeClient and automatically RevertToSelf on destruction.
class ClientImpersonation {
public:
    explicit ClientImpersonation(HANDLE serverPipe) noexcept;
    ~ClientImpersonation();

    ClientImpersonation(const ClientImpersonation&) = delete;
    ClientImpersonation& operator=(const ClientImpersonation&) = delete;

    bool ok() const noexcept { return identity_.impersonated; }
    const ClientIdentity& identity() const noexcept { return identity_; }

private:
    ClientIdentity identity_;
};

struct ServerIdentity {
    uint32_t processId = 0;
    uint32_t sessionId = 0;
    std::wstring imagePath;
    std::wstring accountName;
    std::wstring accountSid;
    bool system = false;
    bool elevated = false;
    bool expectedImageMatched = false;
    bool expectedServiceMatched = false;
};

struct ClientOptions {
    std::wstring name;
    DWORD desiredAccess = GENERIC_READ | GENERIC_WRITE;
    uint32_t timeoutMs = 5000;

    // Default false is critical for high-privilege clients that may meet a rogue server.
    bool allowImpersonation = false;
    // Must be set together with allowImpersonation. This forces callers to acknowledge
    // the connect-time token-theft race described above.
    bool acknowledgeImpersonationRace = false;

    bool verifyServer = true;
    bool requireSystemOrElevated = true;
    std::wstring expectedImagePath;
    std::wstring expectedServiceName;
};

UniqueHandle connectSecureClient(const ClientOptions& options,
                                 ServerIdentity* serverIdentity = nullptr,
                                 std::wstring* error = nullptr);

// Returns \\.\pipe\<name>.
std::wstring pipePath(const std::wstring& name);

}  // namespace pipesec
