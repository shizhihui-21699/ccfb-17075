#pragma once

#include <optional>
#include <string>

namespace pipesec {

struct HardenResult {
    bool success = false;
    bool dryRun = true;
    std::wstring pipeName;
    std::wstring oldSddl;
    std::wstring requestedSddl;
    std::wstring appliedSddl;
    std::wstring message;
    std::optional<int> healthCheckExitCode;
    bool rolledBack = false;
};

std::wstring hardeningPresetSddl(const std::string& preset);
HardenResult hardenPipe(const std::wstring& pipeName,
                        const std::wstring& sddl,
                        bool apply,
                        const std::wstring& healthCheckCommand = L"");

}  // namespace pipesec
