// Minimal secure named-pipe client example.
// By default it uses SecurityIdentification and verifies that the server is
// SYSTEM/elevated. This prevents a medium-integrity squatter from obtaining a
// usable impersonation token from an elevated client.

#include "pipesec/SecurePipe.h"

#include <iostream>

int wmain(int argc, wchar_t** argv) {
    pipesec::ClientOptions options;
    options.name = L"PipeSecExample";
    options.timeoutMs = 5000;

    for (int i = 1; i < argc; ++i) {
        std::wstring arg = argv[i];
        if (arg == L"--allow-non-elevated") {
            options.requireSystemOrElevated = false;
        } else if (arg == L"--allow-impersonation") {
            // Dangerous against an untrusted/squatted endpoint. This explicit
            // flag also acknowledges the connect-time token duplication race.
            options.allowImpersonation = true;
            options.acknowledgeImpersonationRace = true;
        } else if (arg == L"--expect-service" && i + 1 < argc) {
            options.expectedServiceName = argv[++i];
        } else if (arg == L"--expect-image" && i + 1 < argc) {
            options.expectedImagePath = argv[++i];
        } else if (arg.rfind(L"--", 0) != 0) {
            options.name = arg;
        }
    }

    pipesec::ServerIdentity server;
    std::wstring error;
    pipesec::UniqueHandle pipe = pipesec::connectSecureClient(options, &server, &error);
    if (!pipe) {
        std::wcerr << L"Secure connect failed: " << error << L"\n";
        return 1;
    }

    std::wcout << L"Connected to verified server pid=" << server.processId
               << L" account=" << server.accountName
               << L" image=" << server.imagePath << L"\n";

    std::string message = "ping from secure client\n";
    DWORD written = 0;
    if (!::WriteFile(pipe.get(), message.data(), static_cast<DWORD>(message.size()),
                     &written, nullptr)) {
        std::wcerr << L"WriteFile failed: " << ::GetLastError() << L"\n";
        return 2;
    }

    char reply[1024] = {};
    DWORD bytesRead = 0;
    if (::ReadFile(pipe.get(), reply, sizeof(reply) - 1, &bytesRead, nullptr)) {
        std::cout << "Reply: " << std::string(reply, bytesRead) << "\n";
    }
    return 0;
}
