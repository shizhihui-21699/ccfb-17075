#include "SecurityInspector.h"

#include "Util.h"

#include <aclapi.h>
#include <sddl.h>

#include <array>

namespace pipesec {

std::string aceTypeName(unsigned char type) {
    switch (type) {
        case ACCESS_ALLOWED_ACE_TYPE: return "access-allowed";
        case ACCESS_DENIED_ACE_TYPE: return "access-denied";
        case SYSTEM_AUDIT_ACE_TYPE: return "system-audit";
        case SYSTEM_ALARM_ACE_TYPE: return "system-alarm";
        case ACCESS_ALLOWED_COMPOUND_ACE_TYPE: return "access-allowed-compound";
        case ACCESS_ALLOWED_OBJECT_ACE_TYPE: return "access-allowed-object";
        case ACCESS_DENIED_OBJECT_ACE_TYPE: return "access-denied-object";
        case SYSTEM_AUDIT_OBJECT_ACE_TYPE: return "system-audit-object";
        case ACCESS_ALLOWED_CALLBACK_ACE_TYPE: return "access-allowed-callback";
        case ACCESS_DENIED_CALLBACK_ACE_TYPE: return "access-denied-callback";
        case ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE: return "access-allowed-callback-object";
        case ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE: return "access-denied-callback-object";
        case SYSTEM_MANDATORY_LABEL_ACE_TYPE: return "mandatory-label";
        case SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE: return "resource-attribute";
        case SYSTEM_SCOPED_POLICY_ID_ACE_TYPE: return "scoped-policy-id";
        default: return "unknown-" + std::to_string(type);
    }
}

std::string describeAccessMask(uint32_t mask) {
    std::vector<std::string> rights;
    struct Bit { uint32_t bit; const char* name; };
    static const Bit bits[] = {
        {0x00000001u, "ReadData"},
        {0x00000002u, "WriteData"},
        {0x00000004u, "CreatePipeInstance"},
        {0x00000008u, "ReadEa"},
        {0x00000010u, "WriteEa"},
        {0x00000020u, "Execute/Traverse"},
        {0x00000040u, "DeleteChild"},
        {0x00000080u, "ReadAttributes"},
        {0x00000100u, "WriteAttributes"},
        {DELETE, "Delete"},
        {READ_CONTROL, "ReadControl"},
        {WRITE_DAC, "WriteDac"},
        {WRITE_OWNER, "WriteOwner"},
        {SYNCHRONIZE, "Synchronize"},
        {ACCESS_SYSTEM_SECURITY, "AccessSystemSecurity"},
        {GENERIC_READ, "GenericRead"},
        {GENERIC_WRITE, "GenericWrite"},
        {GENERIC_EXECUTE, "GenericExecute"},
        {GENERIC_ALL, "GenericAll"},
    };
    for (const auto& bit : bits) {
        if ((mask & bit.bit) == bit.bit) rights.emplace_back(bit.name);
    }
    std::string result;
    for (size_t i = 0; i < rights.size(); ++i) {
        if (i) result += "|";
        result += rights[i];
    }
    char hex[16];
    std::snprintf(hex, sizeof(hex), "0x%08lX", static_cast<unsigned long>(mask));
    if (result.empty()) return hex;
    return result + " (" + hex + ")";
}

namespace {

PSID aceSid(PACE_HEADER header) {
    switch (header->AceType) {
        case ACCESS_ALLOWED_ACE_TYPE:
        case ACCESS_DENIED_ACE_TYPE:
        case SYSTEM_AUDIT_ACE_TYPE:
        case SYSTEM_ALARM_ACE_TYPE:
        case ACCESS_ALLOWED_CALLBACK_ACE_TYPE:
        case ACCESS_DENIED_CALLBACK_ACE_TYPE: {
            auto* ace = reinterpret_cast<ACCESS_ALLOWED_ACE*>(header);
            return reinterpret_cast<PSID>(&ace->SidStart);
        }
        case ACCESS_ALLOWED_OBJECT_ACE_TYPE:
        case ACCESS_DENIED_OBJECT_ACE_TYPE:
        case SYSTEM_AUDIT_OBJECT_ACE_TYPE:
#ifdef ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE
        case ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE:
#endif
#ifdef ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE
        case ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE:
#endif
#ifdef SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE
        case SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE:
#endif
        {
            auto* ace = reinterpret_cast<ACCESS_ALLOWED_OBJECT_ACE*>(header);
            return reinterpret_cast<PSID>(&ace->SidStart);
        }
        case SYSTEM_MANDATORY_LABEL_ACE_TYPE: {
            auto* ace = reinterpret_cast<SYSTEM_MANDATORY_LABEL_ACE*>(header);
            return reinterpret_cast<PSID>(&ace->SidStart);
        }
        default:
            return nullptr;
    }
}

void parseSecurityDescriptor(PSECURITY_DESCRIPTOR sd, SecurityInfo& info) {
    LPWSTR sddl = nullptr;
    if (::ConvertSecurityDescriptorToStringSecurityDescriptorW(
            sd, SDDL_REVISION_1,
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION
                | DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION
                | LABEL_SECURITY_INFORMATION,
            &sddl, nullptr)
        && sddl) {
        info.sddl = sddl;
        ::LocalFree(sddl);
    }

    PSID owner = nullptr;
    BOOL ownerDefaulted = FALSE;
    if (::GetSecurityDescriptorOwner(sd, &owner, &ownerDefaulted) && owner) {
        info.ownerSid = util::sidToString(owner);
        SidInfo sidInfo = util::lookupSid(owner);
        info.ownerName = sidInfo.displayName;
    }

    PSID group = nullptr;
    BOOL groupDefaulted = FALSE;
    if (::GetSecurityDescriptorGroup(sd, &group, &groupDefaulted) && group) {
        info.groupSid = util::sidToString(group);
        info.groupName = util::lookupSid(group).displayName;
    }

    BOOL daclPresent = FALSE;
    BOOL daclDefaulted = FALSE;
    PACL dacl = nullptr;
    if (::GetSecurityDescriptorDacl(sd, &daclPresent, &dacl, &daclDefaulted)) {
        info.daclPresent = daclPresent != FALSE;
        info.nullDacl = !daclPresent || dacl == nullptr;
        if (daclPresent && dacl) {
            ACL_SIZE_INFORMATION aclSize{};
            if (::GetAclInformation(dacl, &aclSize, sizeof(aclSize), AclSizeInformation)) {
                info.emptyDacl = aclSize.AceCount == 0;
                for (DWORD i = 0; i < aclSize.AceCount; ++i) {
                    LPVOID ace = nullptr;
                    if (!::GetAce(dacl, i, &ace) || !ace) continue;
                    auto* header = static_cast<ACE_HEADER*>(ace);
                    AceInfo out;
                    out.type = header->AceType;
                    out.typeName = aceTypeName(header->AceType);
                    out.flags = header->AceFlags;

                    PSID sid = aceSid(header);
                    if (sid) out.trustee = util::lookupSid(sid);

                    if (header->AceType == SYSTEM_MANDATORY_LABEL_ACE_TYPE) {
                        auto* labelAce = reinterpret_cast<SYSTEM_MANDATORY_LABEL_ACE*>(header);
                        out.mask = labelAce->Mask;
                        if (sid && ::IsValidSid(sid)) {
                            PUCHAR count = ::GetSidSubAuthorityCount(sid);
                            PDWORD rid = ::GetSidSubAuthority(sid, count ? *count - 1 : 0);
                            if (rid) info.integrityRid = *rid;
                            info.integritySid = util::sidToString(sid);
                            info.integrityName = out.trustee.displayName;
                        }
                    } else if (header->AceType == ACCESS_ALLOWED_OBJECT_ACE_TYPE
                               || header->AceType == ACCESS_DENIED_OBJECT_ACE_TYPE
                               || header->AceType == SYSTEM_AUDIT_OBJECT_ACE_TYPE) {
                        auto* objectAce = reinterpret_cast<ACCESS_ALLOWED_OBJECT_ACE*>(header);
                        out.mask = objectAce->Mask;
                    } else {
                        auto* accessAce = reinterpret_cast<ACCESS_ALLOWED_ACE*>(header);
                        out.mask = accessAce->Mask;
                    }
                    out.accessText = describeAccessMask(out.mask);
                    info.aces.push_back(std::move(out));
                }
            }
        }
    }

    BOOL saclPresent = FALSE;
    BOOL saclDefaulted = FALSE;
    PACL sacl = nullptr;
    if (::GetSecurityDescriptorSacl(sd, &saclPresent, &sacl, &saclDefaulted)
        && saclPresent && sacl) {
        ACL_SIZE_INFORMATION aclSize{};
        if (::GetAclInformation(sacl, &aclSize, sizeof(aclSize), AclSizeInformation)) {
            for (DWORD i = 0; i < aclSize.AceCount; ++i) {
                LPVOID ace = nullptr;
                if (!::GetAce(sacl, i, &ace) || !ace) continue;
                auto* header = static_cast<ACE_HEADER*>(ace);
                if (header->AceType != SYSTEM_MANDATORY_LABEL_ACE_TYPE) continue;
                PSID sid = aceSid(header);
                if (!sid || !::IsValidSid(sid)) continue;
                PUCHAR count = ::GetSidSubAuthorityCount(sid);
                PDWORD rid = count ? ::GetSidSubAuthority(sid, *count - 1) : nullptr;
                if (rid) info.integrityRid = *rid;
                info.integritySid = util::sidToString(sid);
                info.integrityName = util::lookupSid(sid).displayName;
            }
        }
    }
}

}  // namespace

SecurityInfo readPipeSecurity(const std::wstring& pipeName) {
    SecurityInfo result;
    std::wstring path = pipeName;
    if (!util::startsWithIgnoreCase(path, L"\\\\.\\pipe\\")
        && !util::startsWithIgnoreCase(path, L"\\\\?\\pipe\\")) {
        path = L"\\\\.\\pipe\\" + pipeName;
    }

    SECURITY_INFORMATION allInfo = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION
                                   | DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION
                                   | LABEL_SECURITY_INFORMATION;
    const SE_OBJECT_TYPE objectTypes[] = {SE_KERNEL_OBJECT, SE_FILE_OBJECT};

    PSECURITY_DESCRIPTOR sd = nullptr;
    DWORD rc = ERROR_INVALID_PARAMETER;
    for (SE_OBJECT_TYPE objectType : objectTypes) {
        rc = ::GetNamedSecurityInfoW(path.c_str(), objectType, allInfo,
                                     nullptr, nullptr, nullptr, nullptr, &sd);
        if (rc == ERROR_SUCCESS && sd) {
            result.available = true;
            parseSecurityDescriptor(sd, result);
            ::LocalFree(sd);
            return result;
        }
        result.errors.push_back(L"full security query type="
                                + std::to_wstring(static_cast<int>(objectType)) + L": "
                                + util::formatWindowsError(rc));
        if (sd) {
            ::LocalFree(sd);
            sd = nullptr;
        }
    }

    SECURITY_INFORMATION daclOwnerInfo = OWNER_SECURITY_INFORMATION
                                          | GROUP_SECURITY_INFORMATION
                                          | DACL_SECURITY_INFORMATION;
    for (SE_OBJECT_TYPE objectType : objectTypes) {
        rc = ::GetNamedSecurityInfoW(path.c_str(), objectType, daclOwnerInfo,
                                     nullptr, nullptr, nullptr, nullptr, &sd);
        if (rc == ERROR_SUCCESS && sd) {
            result.available = true;
            parseSecurityDescriptor(sd, result);
            ::LocalFree(sd);
            return result;
        }
        result.errors.push_back(L"DACL/owner query type="
                                + std::to_wstring(static_cast<int>(objectType)) + L": "
                                + util::formatWindowsError(rc));
        if (sd) {
            ::LocalFree(sd);
            sd = nullptr;
        }
    }

    return result;
}

}  // namespace pipesec
