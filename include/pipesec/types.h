#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace pipesec {

enum class Severity {
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4
};

const char* severityName(Severity severity) noexcept;
std::optional<Severity> parseSeverity(const std::string& text) noexcept;

struct SidInfo {
    std::wstring sid;
    std::wstring domain;
    std::wstring name;
    std::wstring displayName;
    std::vector<std::string> tags;
    bool broadUntrusted = false;
    bool privileged = false;
};

struct AceInfo {
    unsigned char type = 0;
    std::string typeName;
    unsigned char flags = 0;
    uint32_t mask = 0;
    std::string accessText;
    SidInfo trustee;
};

struct SecurityInfo {
    bool available = false;
    std::wstring sddl;
    std::wstring ownerSid;
    std::wstring ownerName;
    std::wstring groupSid;
    std::wstring groupName;
    bool nullDacl = false;
    bool emptyDacl = false;
    bool daclPresent = false;
    std::vector<AceInfo> aces;
    std::optional<uint32_t> integrityRid;
    std::wstring integritySid;
    std::wstring integrityName;
    std::vector<std::wstring> errors;
};

struct HandleOwner {
    uint32_t processId = 0;
    uint64_t handleValue = 0;
    uint32_t grantedAccess = 0;
    uint16_t objectTypeIndex = 0;
};

struct ProcessInfo {
    uint32_t pid = 0;
    uint32_t parentPid = 0;
    std::wstring name;
    std::wstring imagePath;
    std::wstring accountName;
    std::wstring accountSid;
    std::wstring domain;
    bool elevated = false;
    bool system = false;
    bool localService = false;
    bool networkService = false;
    uint64_t creationTime100ns = 0;
    std::string creationTimeUtc;
    std::vector<std::wstring> services;
    std::vector<std::wstring> errors;
};

struct Finding {
    Severity severity = Severity::Info;
    std::string code;
    std::string title;
    std::string detail;
    std::string remediation;
};

struct PipeInfo {
    std::wstring name;
    std::wstring path;
    SecurityInfo security;
    std::vector<HandleOwner> handles;
    std::map<uint32_t, ProcessInfo> processes;
    uint64_t objectCreationTime100ns = 0;
    std::string objectCreationTimeUtc;
    uint32_t pipeFlags = 0;
    uint32_t maxInstances = 0;
    bool remoteClientsRejected = false;
    std::string firstSeenUtc;
    std::vector<Finding> findings;
    std::vector<std::wstring> errors;
};

struct ServicePipeReference {
    std::wstring pipeName;
    std::wstring normalizedName;
    std::wstring serviceName;
    std::wstring serviceDisplayName;
    std::wstring binaryPath;
    std::wstring scannedFile;
    uint32_t servicePid = 0;
    uint32_t startType = 0;
    std::wstring startAccount;
    bool runningAsSystem = false;
    bool impersonateApiHint = false;
    bool formatTemplate = false;
};

struct ServiceInfo {
    std::wstring name;
    std::wstring displayName;
    uint32_t pid = 0;
    uint32_t state = 0;
    uint32_t startType = 0;
    std::wstring binaryPath;
    std::wstring startAccount;
    bool systemAccount = false;
};

struct AuditReport {
    std::string schemaVersion = "1.0";
    std::string generatedAtUtc;
    std::wstring hostName;
    bool elevated = false;
    uint32_t processId = 0;
    std::vector<std::string> warnings;
    std::vector<Finding> findings;
    std::vector<PipeInfo> pipes;
    std::vector<ServiceInfo> services;
    std::vector<ServicePipeReference> references;
};

struct AuditOptions {
    bool scanHandles = true;
    bool enrichProcesses = true;
    bool scanServices = true;
    bool scanServiceBinaries = true;
    size_t maxBinaryBytes = 64u * 1024u * 1024u;
};

}  // namespace pipesec
