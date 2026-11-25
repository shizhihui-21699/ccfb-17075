#include "Harden.h"

#include "SecurityInspector.h"
#include "Util.h"

#include <aclapi.h>
#include <sddl.h>

namespace pipesec {

namespace {

bool applySddlString(const std::wstring& path, const std::wstring& sddl,
                     std::wstring& error) {
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!::ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.c_str(), SDDL_REVISION_1, &sd, nullptr) || !sd) {
        error = L"SDDL conversion failed: " + util::formatWindowsError();
        return false;
    }

    BOOL daclPresent = FALSE, daclDefaulted = FALSE;
    PACL dacl = nullptr;
    BOOL saclPresent = FALSE, saclDefaulted = FALSE;
    PACL sacl = nullptr;
    PSID owner = nullptr;
    PSID group = nullptr;
    BOOL ownerDefaulted = FALSE;
    BOOL groupDefaulted = FALSE;
    ::GetSecurityDescriptorDacl(sd, &daclPresent, &dacl, &daclDefaulted);
    ::GetSecurityDescriptorSacl(sd, &saclPresent, &sacl, &saclDefaulted);
    ::GetSecurityDescriptorOwner(sd, &owner, &ownerDefaulted);
    ::GetSecurityDescriptorGroup(sd, &group, &groupDefaulted);

    SECURITY_INFORMATION flags = 0;
    if (owner) flags |= OWNER_SECURITY_INFORMATION;
    if (group) flags |= GROUP_SECURITY_INFORMATION;
    if (daclPresent) flags |= DACL_SECURITY_INFORMATION;
    if (saclPresent) flags |= SACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION;

    SECURITY_DESCRIPTOR_CONTROL control = 0;
    DWORD revision = 0;
    if (::GetSecurityDescriptorControl(sd, &control, &revision)) {
        if (control & SE_DACL_PROTECTED) flags |= PROTECTED_DACL_SECURITY_INFORMATION;
        if (control & SE_SACL_PROTECTED) flags |= PROTECTED_SACL_SECURITY_INFORMATION;
    }

    DWORD rc = ERROR_INVALID_PARAMETER;
    const SE_OBJECT_TYPE objectTypes[] = {SE_KERNEL_OBJECT, SE_FILE_OBJECT};
    for (SE_OBJECT_TYPE objectType : objectTypes) {
        rc = ::SetNamedSecurityInfoW(
            const_cast<LPWSTR>(path.c_str()), objectType, flags,
            owner, group, daclPresent ? dacl : nullptr,
            saclPresent ? sacl : nullptr);
        if (rc == ERROR_SUCCESS) break;
    }
    ::LocalFree(sd);

    if (rc != ERROR_SUCCESS) {
        error = util::formatWindowsError(rc);
        return false;
    }
    return true;
}

std::optional<int> runHealthCheck(const std::wstring& commandLine) {
    if (commandLine.empty()) return std::nullopt;
    std::vector<wchar_t> mutableCommand(commandLine.begin(), commandLine.end());
    mutableCommand.push_back(L'\0');

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (!::CreateProcessW(nullptr, mutableCommand.data(), nullptr, nullptr, FALSE,
                          0, nullptr, nullptr, &si, &pi)) {
        return std::nullopt;
    }

    DWORD wait = ::WaitForSingleObject(pi.hProcess, 60000);
    std::optional<int> exitCode;
    if (wait == WAIT_OBJECT_0) {
        DWORD code = 1;
        if (::GetExitCodeProcess(pi.hProcess, &code)) exitCode = static_cast<int>(code);
    } else {
        ::TerminateProcess(pi.hProcess, 1);
        ::WaitForSingleObject(pi.hProcess, 5000);
        exitCode = 124;
    }
    ::CloseHandle(pi.hThread);
    ::CloseHandle(pi.hProcess);
    return exitCode;
}

}  // namespace

std::wstring hardeningPresetSddl(const std::string& preset) {
    std::string p = util::lowerAscii(preset);
    if (p == "system-admins" || p == "strict") {
        return L"D:P(A;;GA;;;SY)(A;;GA;;;BA)";
    }
    if (p == "high-integrity" || p == "hi") {
        return L"D:P(A;;GA;;;SY)(A;;GA;;;BA)S:(ML;;NW;;;HI)";
    }
    if (p == "users-compat" || p == "users") {
        return L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;BU)";
    }
    if (p == "interactive-compat" || p == "interactive") {
        return L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;BU)(A;;GRGW;;;IU)";
    }
    return {};
}

HardenResult hardenPipe(const std::wstring& pipeName,
                        const std::wstring& sddl,
                        bool apply,
                        const std::wstring& healthCheckCommand) {
    HardenResult result;
    result.pipeName = pipeName;
    result.requestedSddl = sddl;
    result.dryRun = !apply;

    std::wstring path = L"\\\\.\\pipe\\" + pipeName;
    SecurityInfo before = readPipeSecurity(pipeName);
    result.oldSddl = before.sddl;
    if (!before.available) {
        result.success = false;
        result.message = L"无法读取现有管道 SD，为避免覆盖未知配置已停止。";
        return result;
    }
    if (sddl.empty()) {
        result.message = L"空 SDDL；未执行操作。";
        return result;
    }

    if (!apply) {
        result.success = true;
        result.message = L"Dry-run：已备份旧 SDDL，未调用 SetNamedSecurityInfo。";
        return result;
    }

    util::enablePrivilege(SE_SECURITY_NAME);
    std::wstring error;
    if (!applySddlString(path, sddl, error)) {
        result.success = false;
        result.message = L"设置 SDDL 失败: " + error;
        return result;
    }

    result.healthCheckExitCode = runHealthCheck(healthCheckCommand);
    if (result.healthCheckExitCode.has_value() && *result.healthCheckExitCode != 0) {
        std::wstring rollbackError;
        if (!result.oldSddl.empty()
            && applySddlString(path, result.oldSddl, rollbackError)) {
            result.rolledBack = true;
            result.message = L"健康检查失败，已回滚到旧 SDDL。";
        } else {
            result.message = L"健康检查失败且回滚失败: " + rollbackError;
        }
        result.success = false;
        return result;
    }

    SecurityInfo after = readPipeSecurity(pipeName);
    result.appliedSddl = after.sddl;
    result.success = after.available;
    result.message = result.success ? L"SDDL 已应用并重新读取验证。"
                                    : L"SDDL 调用成功，但重新读取验证失败。";
    return result;
}

}  // namespace pipesec
