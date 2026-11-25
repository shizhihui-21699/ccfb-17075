// Minimal secure named-pipe server example.
// Build: cmake --build build --target secure_server
// Run in an elevated terminal for the strict SYSTEM/Administrators SDDL.

#include "pipesec/SecurePipe.h"

#include <iostream>

int wmain(int argc, wchar_t** argv) {
    std::wstring name = L"PipeSecExample";
    if (argc > 1) name = argv[1];

    pipesec::ServerOptions options;
    options.name = name;

    // For a real service, append the service SID and a dedicated client group:
    // options.sddl = L"D:P(A;;GA;;;SY)(A;;GA;;;BA)"
    //                L"(A;;GA;;;S-1-5-80-<your-service-sid>)"
    //                L"(A;;GRGW;;;S-1-5-21-...-<client-group-rid>)";
    options.sddl = L"D:P(A;;GA;;;SY)(A;;GA;;;BA)";

    std::wstring error;
    pipesec::UniqueHandle pipe = pipesec::createFirstServerInstance(options, &error);
    if (!pipe) {
        std::wcerr << L"createFirstServerInstance failed: " << error << L"\n";
        return 1;
    }

    std::wcout << L"Listening on " << pipesec::pipePath(name) << L"\n";
    std::wcout << L"SDDL: " << options.sddl << L"\n";

    while (true) {
        if (!pipesec::waitForClient(pipe.get(), &error)) {
            std::wcerr << error << L"\n";
            return 2;
        }

        {
            // Impersonation is used for client authorization/access checks.
            // The object reverts automatically.
            pipesec::ClientImpersonation impersonation(pipe.get());
            if (impersonation.ok()) {
                std::wcout << L"Client: "
                           << impersonation.identity().accountName
                           << L" (" << impersonation.identity().sid << L")\n";
            } else {
                std::wcout << L"ImpersonateNamedPipeClient failed\n";
            }
        }

        char buffer[4096] = {};
        DWORD bytesRead = 0;
        if (::ReadFile(pipe.get(), buffer, sizeof(buffer) - 1, &bytesRead, nullptr)
            && bytesRead > 0) {
            std::cout << "Received " << bytesRead << " bytes: "
                      << std::string(buffer, bytesRead) << "\n";
            static constexpr char reply[] = "OK\n";
            DWORD written = 0;
            ::WriteFile(pipe.get(), reply, sizeof(reply) - 1, &written, nullptr);
        }

        ::FlushFileBuffers(pipe.get());
        ::DisconnectNamedPipe(pipe.get());
    }
}
