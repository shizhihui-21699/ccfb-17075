#include "Auditor.h"

#include "HandleScanner.h"
#include "PipeEnumerator.h"
#include "ProcessInspector.h"
#include "RiskAnalyzer.h"
#include "SecurityInspector.h"
#include "ServiceHunter.h"
#include "Util.h"

namespace pipesec {

AuditReport runAudit(const AuditOptions& options) {
    AuditReport report;
    report.generatedAtUtc = util::nowUtcString();
    report.hostName = util::currentHostName();
    report.elevated = util::isElevated();
    report.processId = ::GetCurrentProcessId();

    // Best effort. Failure is non-fatal; protected processes may remain unavailable.
    util::enablePrivilege(SE_DEBUG_NAME);
    util::enablePrivilege(SE_SECURITY_NAME);
    util::enablePrivilege(SE_BACKUP_NAME);

    if (options.scanServices) {
        report.services = enumerateServices();
        if (options.scanServiceBinaries) {
            report.references = findServicePipeReferences(report.services, options);
        }
    }

    HandleScanResult handles;
    if (options.scanHandles) {
        handles = scanSystemHandlesForPipes();
        for (const std::string& warning : handles.warnings) report.warnings.push_back(warning);
    }

    ProcessResolver processes;
    processes.setServices(report.services);

    std::vector<std::wstring> names = enumeratePipeNames();
    for (std::wstring name : names) {
        PipeInfo pipe;
        pipe.name = std::move(name);
        pipe.path = L"\\\\.\\pipe\\" + pipe.name;
        pipe.firstSeenUtc = report.generatedAtUtc;
        pipe.security = readPipeSecurity(pipe.name);

        std::wstring key = util::lowerWide(pipe.name);
        if (auto found = handles.owners.find(key); found != handles.owners.end()) {
            pipe.handles = found->second;
        }
        if (auto found = handles.creationTimes.find(key); found != handles.creationTimes.end()) {
            pipe.objectCreationTime100ns = found->second;
            pipe.objectCreationTimeUtc = util::fileTimeToUtcString(found->second);
        }
        if (auto found = handles.pipeFlags.find(key); found != handles.pipeFlags.end()) {
            pipe.pipeFlags = found->second;
            pipe.remoteClientsRejected = (pipe.pipeFlags & PIPE_REJECT_REMOTE_CLIENTS) != 0;
        }
        if (auto found = handles.maxInstances.find(key); found != handles.maxInstances.end()) {
            pipe.maxInstances = found->second;
        }

        if (options.enrichProcesses) {
            for (const HandleOwner& owner : pipe.handles) {
                if (pipe.processes.count(owner.processId)) continue;
                pipe.processes.emplace(owner.processId, processes.get(owner.processId));
            }
        }

        report.pipes.push_back(std::move(pipe));
    }

    if (!options.scanHandles) {
        report.warnings.push_back("Handle/process ownership scan disabled by options.");
    } else if (!report.elevated) {
        report.warnings.push_back(
            "Not elevated: many process paths, tokens and handles will be unavailable.");
    }

    analyzeReport(report);
    return report;
}

}  // namespace pipesec
