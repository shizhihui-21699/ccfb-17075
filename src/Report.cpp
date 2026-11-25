#include "Report.h"

#include "Util.h"

#include <algorithm>
#include <cctype>
#include <sstream>

namespace pipesec {

namespace {

using util::toJson;

std::string jsonFinding(const Finding& f, int indent) {
    std::string pad1(indent, ' ');
    std::string pad2(indent + 2, ' ');
    std::ostringstream out;
    out << pad1 << "{\n";
    out << pad2 << "\"severity\": " << toJson(severityName(f.severity)) << ",\n";
    out << pad2 << "\"code\": " << toJson(f.code) << ",\n";
    out << pad2 << "\"title\": " << toJson(f.title) << ",\n";
    out << pad2 << "\"detail\": " << toJson(f.detail) << ",\n";
    out << pad2 << "\"remediation\": " << toJson(f.remediation) << "\n";
    out << pad1 << "}";
    return out.str();
}

std::string jsonSid(const SidInfo& sid, int indent) {
    std::string pad2(indent + 2, ' ');
    std::ostringstream out;
    out << "{\n";
    out << pad2 << "\"sid\": " << toJson(sid.sid) << ",\n";
    out << pad2 << "\"name\": " << toJson(sid.displayName) << ",\n";
    out << pad2 << "\"broadUntrusted\": " << (sid.broadUntrusted ? "true" : "false") << ",\n";
    out << pad2 << "\"privileged\": " << (sid.privileged ? "true" : "false") << ",\n";
    out << pad2 << "\"tags\": [";
    for (size_t i = 0; i < sid.tags.size(); ++i) {
        if (i) out << ", ";
        out << toJson(sid.tags[i]);
    }
    out << "]\n" << std::string(indent, ' ') << "}";
    return out.str();
}

Severity maxPipeSeverity(const PipeInfo& pipe) {
    Severity max = Severity::Info;
    for (const Finding& f : pipe.findings) max = std::max(max, f.severity);
    return max;
}

std::string severityLabel(Severity severity) {
    std::string s = severityName(severity);
    for (char& c : s) c = static_cast<char>(::toupper(static_cast<unsigned char>(c)));
    return s;
}

}  // namespace

std::string reportToJson(const AuditReport& report) {
    size_t critical = 0, high = 0, medium = 0, low = 0, info = 0;
    auto count = [&](Severity s) {
        switch (s) {
            case Severity::Critical: ++critical; break;
            case Severity::High: ++high; break;
            case Severity::Medium: ++medium; break;
            case Severity::Low: ++low; break;
            case Severity::Info: ++info; break;
        }
    };
    for (const Finding& f : report.findings) count(f.severity);
    for (const PipeInfo& p : report.pipes) for (const Finding& f : p.findings) count(f.severity);

    std::ostringstream out;
    out << "{\n";
    out << "  \"schemaVersion\": " << toJson(report.schemaVersion) << ",\n";
    out << "  \"generatedAtUtc\": " << toJson(report.generatedAtUtc) << ",\n";
    out << "  \"hostName\": " << toJson(report.hostName) << ",\n";
    out << "  \"elevated\": " << (report.elevated ? "true" : "false") << ",\n";
    out << "  \"processId\": " << report.processId << ",\n";
    out << "  \"summary\": {\n";
    out << "    \"pipeCount\": " << report.pipes.size() << ",\n";
    out << "    \"serviceCount\": " << report.services.size() << ",\n";
    out << "    \"servicePipeReferenceCount\": " << report.references.size() << ",\n";
    out << "    \"critical\": " << critical << ",\n";
    out << "    \"high\": " << high << ",\n";
    out << "    \"medium\": " << medium << ",\n";
    out << "    \"low\": " << low << ",\n";
    out << "    \"info\": " << info << "\n";
    out << "  },\n";

    out << "  \"warnings\": [";
    for (size_t i = 0; i < report.warnings.size(); ++i) {
        if (i) out << ", ";
        out << toJson(report.warnings[i]);
    }
    out << "],\n";

    out << "  \"findings\": [\n";
    for (size_t i = 0; i < report.findings.size(); ++i) {
        out << "    " << jsonFinding(report.findings[i], 4);
        if (i + 1 != report.findings.size()) out << ",";
        out << "\n";
    }
    out << "  ],\n";

    out << "  \"pipes\": [\n";
    for (size_t pipeIndex = 0; pipeIndex < report.pipes.size(); ++pipeIndex) {
        const PipeInfo& p = report.pipes[pipeIndex];
        out << "    {\n";
        out << "      \"name\": " << toJson(p.name) << ",\n";
        out << "      \"path\": " << toJson(p.path) << ",\n";
        out << "      \"maxSeverity\": " << toJson(severityName(maxPipeSeverity(p))) << ",\n";
        out << "      \"firstSeenUtc\": " << toJson(p.firstSeenUtc) << ",\n";
        out << "      \"objectCreationTimeUtc\": " << toJson(p.objectCreationTimeUtc) << ",\n";
        out << "      \"maxInstances\": " << p.maxInstances << ",\n";
        out << "      \"pipeFlags\": " << p.pipeFlags << ",\n";
        out << "      \"remoteClientsRejected\": "
            << (p.remoteClientsRejected ? "true" : "false") << ",\n";

        out << "      \"security\": {\n";
        out << "        \"available\": " << (p.security.available ? "true" : "false") << ",\n";
        out << "        \"sddl\": " << toJson(p.security.sddl) << ",\n";
        out << "        \"ownerSid\": " << toJson(p.security.ownerSid) << ",\n";
        out << "        \"ownerName\": " << toJson(p.security.ownerName) << ",\n";
        out << "        \"groupSid\": " << toJson(p.security.groupSid) << ",\n";
        out << "        \"groupName\": " << toJson(p.security.groupName) << ",\n";
        out << "        \"nullDacl\": " << (p.security.nullDacl ? "true" : "false") << ",\n";
        out << "        \"emptyDacl\": " << (p.security.emptyDacl ? "true" : "false") << ",\n";
        out << "        \"integrityRid\": ";
        if (p.security.integrityRid) out << *p.security.integrityRid;
        else out << "null";
        out << ",\n";
        out << "        \"integrityName\": " << toJson(p.security.integrityName) << ",\n";
        out << "        \"aces\": [\n";
        for (size_t i = 0; i < p.security.aces.size(); ++i) {
            const AceInfo& ace = p.security.aces[i];
            out << "          {\n";
            out << "            \"type\": " << toJson(ace.typeName) << ",\n";
            out << "            \"flags\": " << static_cast<int>(ace.flags) << ",\n";
            out << "            \"mask\": " << ace.mask << ",\n";
            out << "            \"access\": " << toJson(ace.accessText) << ",\n";
            out << "            \"trustee\": " << jsonSid(ace.trustee, 12) << "\n";
            out << "          }";
            if (i + 1 != p.security.aces.size()) out << ",";
            out << "\n";
        }
        out << "        ],\n";
        out << "        \"errors\": [";
        for (size_t i = 0; i < p.security.errors.size(); ++i) {
            if (i) out << ", ";
            out << toJson(p.security.errors[i]);
        }
        out << "]\n";
        out << "      },\n";

        out << "      \"handles\": [\n";
        for (size_t i = 0; i < p.handles.size(); ++i) {
            const HandleOwner& h = p.handles[i];
            out << "        {\"pid\": " << h.processId
                << ", \"handle\": " << h.handleValue
                << ", \"grantedAccess\": " << h.grantedAccess
                << ", \"objectTypeIndex\": " << h.objectTypeIndex << "}";
            if (i + 1 != p.handles.size()) out << ",";
            out << "\n";
        }
        out << "      ],\n";

        out << "      \"processes\": [\n";
        size_t processIndex = 0;
        for (const auto& [pid, proc] : p.processes) {
            out << "        {\"pid\": " << pid
                << ", \"parentPid\": " << proc.parentPid
                << ", \"name\": " << toJson(proc.name)
                << ", \"imagePath\": " << toJson(proc.imagePath)
                << ", \"account\": " << toJson(proc.accountName)
                << ", \"accountSid\": " << toJson(proc.accountSid)
                << ", \"elevated\": " << (proc.elevated ? "true" : "false")
                << ", \"system\": " << (proc.system ? "true" : "false")
                << ", \"creationTimeUtc\": " << toJson(proc.creationTimeUtc)
                << ", \"services\": [";
            for (size_t j = 0; j < proc.services.size(); ++j) {
                if (j) out << ", ";
                out << toJson(proc.services[j]);
            }
            out << "], \"errors\": [";
            for (size_t j = 0; j < proc.errors.size(); ++j) {
                if (j) out << ", ";
                out << toJson(proc.errors[j]);
            }
            out << "]}";
            if (++processIndex != p.processes.size()) out << ",";
            out << "\n";
        }
        out << "      ],\n";

        out << "      \"findings\": [\n";
        for (size_t i = 0; i < p.findings.size(); ++i) {
            out << "    " << jsonFinding(p.findings[i], 8);
            if (i + 1 != p.findings.size()) out << ",";
            out << "\n";
        }
        out << "      ]\n";
        out << "    }";
        if (pipeIndex + 1 != report.pipes.size()) out << ",";
        out << "\n";
    }
    out << "  ],\n";

    out << "  \"services\": [\n";
    for (size_t i = 0; i < report.services.size(); ++i) {
        const ServiceInfo& s = report.services[i];
        out << "    {\"name\": " << toJson(s.name)
            << ", \"displayName\": " << toJson(s.displayName)
            << ", \"pid\": " << s.pid
            << ", \"state\": " << s.state
            << ", \"startType\": " << s.startType
            << ", \"systemAccount\": " << (s.systemAccount ? "true" : "false")
            << ", \"startAccount\": " << toJson(s.startAccount)
            << ", \"binaryPath\": " << toJson(s.binaryPath) << "}";
        if (i + 1 != report.services.size()) out << ",";
        out << "\n";
    }
    out << "  ],\n";

    out << "  \"servicePipeReferences\": [\n";
    for (size_t i = 0; i < report.references.size(); ++i) {
        const ServicePipeReference& r = report.references[i];
        out << "    {\"pipeName\": " << toJson(r.pipeName)
            << ", \"serviceName\": " << toJson(r.serviceName)
            << ", \"servicePid\": " << r.servicePid
            << ", \"startType\": " << r.startType
            << ", \"startAccount\": " << toJson(r.startAccount)
            << ", \"runningAsSystem\": " << (r.runningAsSystem ? "true" : "false")
            << ", \"impersonateApiHint\": " << (r.impersonateApiHint ? "true" : "false")
            << ", \"formatTemplate\": " << (r.formatTemplate ? "true" : "false")
            << ", \"scannedFile\": " << toJson(r.scannedFile) << "}";
        if (i + 1 != report.references.size()) out << ",";
        out << "\n";
    }
    out << "  ]\n";
    out << "}\n";
    return out.str();
}

std::string reportToText(const AuditReport& report, Severity minimumSeverity, bool showAllPipes) {
    std::ostringstream out;
    out << "PipeSec 命名管道审计\n";
    out << "生成时间(UTC): " << report.generatedAtUtc
        << " 主机: " << util::wideToUtf8(report.hostName)
        << " 提升: " << (report.elevated ? "是" : "否") << "\n";
    out << "管道数: " << report.pipes.size()
        << " 服务数: " << report.services.size()
        << " 服务管道字符串引用: " << report.references.size() << "\n\n";

    if (!report.warnings.empty()) {
        out << "警告:\n";
        for (const auto& w : report.warnings) out << "  - " << w << "\n";
        out << "\n";
    }

    if (showAllPipes) {
        out << "管道清单:\n";
        for (const PipeInfo& p : report.pipes) {
            Severity sev = maxPipeSeverity(p);
            std::string owners;
            for (const auto& [pid, proc] : p.processes) {
                if (!owners.empty()) owners += ",";
                owners += std::to_string(pid);
            }
            out << "  [" << severityLabel(sev) << "] "
                << util::wideToUtf8(p.name)
                << " | owner=" << util::wideToUtf8(p.security.ownerName.empty()
                                                       ? p.security.ownerSid
                                                       : p.security.ownerName)
                << " | pids=" << (owners.empty() ? "-" : owners)
                << " | " << (p.security.sddl.empty() ? "<SD unavailable>"
                                                     : util::wideToUtf8(p.security.sddl))
                << "\n";
        }
        out << "\n";
    }

    auto printFinding = [&](const Finding& f, const std::string& context) {
        if (static_cast<int>(f.severity) < static_cast<int>(minimumSeverity)) return;
        out << "[" << severityLabel(f.severity) << "] " << f.code;
        if (!context.empty()) out << " " << context;
        out << "\n  " << f.title << "\n  " << f.detail << "\n  建议: " << f.remediation << "\n\n";
    };

    if (!report.findings.empty()) {
        out << "全局/启动时序发现:\n";
        for (const Finding& f : report.findings) printFinding(f, "");
    }

    out << "管道详细发现:\n";
    bool any = false;
    for (const PipeInfo& p : report.pipes) {
        for (const Finding& f : p.findings) {
            if (static_cast<int>(f.severity) < static_cast<int>(minimumSeverity)) continue;
            any = true;
            printFinding(f, util::wideToUtf8(p.name));
        }
    }
    if (!any) out << "  没有达到最低严重级别的发现。\n";
    return out.str();
}

}  // namespace pipesec
