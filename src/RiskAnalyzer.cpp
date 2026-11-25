#include "RiskAnalyzer.h"

#include "Util.h"

#include <algorithm>
#include <unordered_map>
#include <unordered_set>

namespace pipesec {

namespace {

constexpr uint32_t kCreatePipeInstance = 0x00000004u;
constexpr uint32_t kReadData = 0x00000001u;
constexpr uint32_t kWriteData = 0x00000002u;

bool allowedAceType(unsigned char type) {
    return type == ACCESS_ALLOWED_ACE_TYPE
        || type == ACCESS_ALLOWED_OBJECT_ACE_TYPE
        || type == ACCESS_ALLOWED_CALLBACK_ACE_TYPE
        || type == ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE;
}

bool deniedAceType(unsigned char type) {
    return type == ACCESS_DENIED_ACE_TYPE
        || type == ACCESS_DENIED_OBJECT_ACE_TYPE
        || type == ACCESS_DENIED_CALLBACK_ACE_TYPE
        || type == ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE;
}

bool hasAny(uint32_t mask, uint32_t bits) {
    return (mask & bits) != 0;
}

std::string pipeLabel(const PipeInfo& pipe) {
    return util::wideToUtf8(pipe.name);
}

bool pipeTouchesPrivilegedProcess(const PipeInfo& pipe) {
    for (const auto& [pid, process] : pipe.processes) {
        if (process.system || process.elevated) return true;
    }
    return false;
}

std::string processSummary(const PipeInfo& pipe) {
    std::string out;
    for (const auto& [pid, p] : pipe.processes) {
        if (!out.empty()) out += "; ";
        out += "pid=" + std::to_string(pid);
        if (!p.name.empty()) out += " " + util::wideToUtf8(p.name);
        if (!p.accountName.empty()) out += " [" + util::wideToUtf8(p.accountName) + "]";
        if (p.system) out += " SYSTEM";
        else if (p.elevated) out += " elevated";
    }
    return out.empty() ? "no process handles could be duplicated" : out;
}

void analyzeSecurity(PipeInfo& pipe, bool privilegedServiceRef) {
    const SecurityInfo& sd = pipe.security;
    const std::string name = pipeLabel(pipe);
    const bool privilegedEndpoint = privilegedServiceRef || pipeTouchesPrivilegedProcess(pipe);

    if (!sd.available) {
        pipe.findings.push_back({
            Severity::Medium,
            "ACL_UNREADABLE",
            "无法读取管道安全描述符",
            "检查需要管理员权限或 READ_CONTROL/ACCESS_SYSTEM_SECURITY。无法确认访问控制并不代表安全。",
            "以提升后的管理员身份运行审计；修复服务时在 CreateNamedPipe 的 SECURITY_ATTRIBUTES 中显式指定严格 SD。"
        });
        return;
    }

    if (sd.nullDacl) {
        std::string detail =
            "任何低完整性/低权限进程都可能连接、创建同名实例或篡改安全描述符。";
        if (privilegedEndpoint) {
            detail += " 该管道还关联 SYSTEM/高权限进程，风险可直接转化为令牌冒用。";
        }
        pipe.findings.push_back({
            Severity::Critical,
            "NULL_DACL",
            "管道具有 NULL/缺失 DACL，通常等于允许所有主体完全访问",
            std::move(detail),
            "使用受保护 SDDL，例如 D:P(A;;GA;;;SY)(A;;GA;;;BA)，并按最小权限加入指定服务/用户组；"
            "创建时加 FILE_FLAG_FIRST_PIPE_INSTANCE。"
        });
    } else if (sd.emptyDacl) {
        pipe.findings.push_back({
            Severity::Info,
            "EMPTY_DACL",
            "管道 DACL 为空（拒绝所有访问）",
            "这是安全但可能影响可用性的配置；合法客户端也会被拒绝。",
            "确认所有预期客户端使用独立主体并被显式 Allow。"
        });
    }

    for (const AceInfo& ace : sd.aces) {
        if (!allowedAceType(ace.type) || !ace.trustee.broadUntrusted) continue;

        const std::string trustee = util::wideToUtf8(
            ace.trustee.displayName.empty() ? ace.trustee.sid : ace.trustee.displayName);
        const bool takesControl = hasAny(ace.mask, WRITE_DAC | WRITE_OWNER | GENERIC_ALL);
        const bool canCreateInstance =
            hasAny(ace.mask, kCreatePipeInstance | GENERIC_ALL);
        const bool canWrite = hasAny(ace.mask, kWriteData | GENERIC_WRITE | GENERIC_ALL);
        const bool canRead = hasAny(ace.mask, kReadData | GENERIC_READ | GENERIC_ALL);

        if (takesControl) {
            pipe.findings.push_back({
                Severity::Critical,
                "BROAD_WRITE_OWNERSHIP",
                "宽泛主体可修改管道 DACL/所有者: " + trustee,
                trustee + " 拥有 " + ace.accessText + "。攻击者可先放开 ACL，再创建实例或劫持通信。",
                "从 DACL 删除 " + trustee + " 的 WriteDac/WriteOwner/GenericAll；仅保留 SYSTEM、Administrators 和明确的服务/客户端 SID。"
            });
        }

        if (canCreateInstance) {
            pipe.findings.push_back({
                Severity::Critical,
                "BROAD_CREATE_PIPE_INSTANCE",
                "宽泛主体可创建同名管道实例: " + trustee,
                trustee + " 拥有 " + ace.accessText
                    + "。即使首个实例由高权限服务创建，低权限进程也可能加入额外实例并截获客户端连接。",
                "拒绝普通用户/Everyone/Anonymous/Authenticated Users/Users 的 FILE_CREATE_PIPE_INSTANCE；"
                "服务创建首个实例时使用 FILE_FLAG_FIRST_PIPE_INSTANCE。"
            });
        }

        if (canWrite) {
            Severity severity = privilegedEndpoint ? Severity::Critical : Severity::High;
            pipe.findings.push_back({
                severity,
                "BROAD_WRITE_ACCESS",
                "宽泛低信任主体可向管道写入/连接: " + trustee,
                trustee + " 的权限为 " + ace.accessText + "。"
                    + (privilegedEndpoint
                           ? "管道关联高权限服务或客户端；若对端调用 ImpersonateNamedPipeClient 且授权检查缺失，可能形成 SYSTEM 权限链路。"
                           : "可能导致数据注入、协议攻击或连接劫持。"),
                "将读写权限限制到指定服务 SID 与客户端安全组；不要使用 Everyone、Anonymous、Authenticated Users、BUILTIN\\Users 作为可写主体。"
            });
        } else if (canRead) {
            pipe.findings.push_back({
                Severity::Medium,
                "BROAD_READ_ACCESS",
                "宽泛主体可读取管道: " + trustee,
                trustee + " 的权限为 " + ace.accessText + "，可能泄露 IPC 数据或协议信息。",
                "按最小权限移除 " + trustee + " 的 ReadData/GenericRead。"
            });
        }
    }

    if (!sd.integrityRid.has_value()) {
        pipe.findings.push_back({
            Severity::Info,
            "NO_INTEGRITY_LABEL",
            "未能读取强制完整性标签",
            "未显式指定标签时通常采用默认中等完整性策略；低完整性/AppContainer 客户端的可达性需要结合 DACL 判断。",
            "如果客户端均为提升进程或 SYSTEM，使用 S:(ML;;NW;;;HI)；若必须服务普通中完整性用户，则用 DACL 和专用用户组限制。"
        });
    } else if (*sd.integrityRid <= SECURITY_MANDATORY_LOW_RID) {
        pipe.findings.push_back({
            Severity::High,
            "LOW_INTEGRITY_LABEL",
            "管道完整性标签为 Low 或更低",
            "低完整性进程通常可向该对象写入，扩大了本机攻击面。",
            "除非明确需要低完整性客户端，否则使用 Medium 或 High 标签并保留 NoWriteUp 策略。"
        });
    }

    bool broadDenied = false;
    for (const AceInfo& ace : sd.aces) {
        if (deniedAceType(ace.type) && ace.trustee.broadUntrusted) broadDenied = true;
    }
    if (broadDenied) {
        pipe.findings.push_back({
            Severity::Info,
            "DENY_ACE_PRESENT",
            "DACL 中存在针对宽泛主体的 Deny ACE",
            "Deny ACE 可降低风险，但仍应验证 ACE 顺序、登录 SID/组 SID 是否覆盖所有低权限令牌。",
            "优先使用最小 Allow 白名单，避免依赖复杂 Deny 规则。"
        });
    }
}

void analyzeOwnership(PipeInfo& pipe,
                      bool reportElevated,
                      const std::unordered_map<std::wstring, const ServiceInfo*>& serviceByName,
                      const std::vector<const ServicePipeReference*>& refs) {
    if (!pipe.security.ownerSid.empty()) {
        const std::wstring& ownerSid = pipe.security.ownerSid;
        bool systemOrAdminOwner = ownerSid == L"S-1-5-18"
                                  || ownerSid == L"S-1-5-32-544"
                                  || ownerSid == L"S-1-5-80"  // prefix handled below only
                                  || ownerSid.rfind(L"S-1-5-80-", 0) == 0
                                  || ownerSid == L"S-1-5-19"
                                  || ownerSid == L"S-1-5-20";
        SidInfo owner = util::lookupSidString(ownerSid);
        if (owner.broadUntrusted) {
            pipe.findings.push_back({
                Severity::Critical,
                "BROAD_OWNER",
                "管道所有者是宽泛低信任主体: " + util::wideToUtf8(owner.displayName),
                "对象所有者通常可重置 DACL，即使当前 DACL 看起来严格也不能视为安全。",
                "将所有者设置为 SYSTEM 或 BUILTIN\\Administrators，并使用受保护 DACL。"
            });
        } else if (!systemOrAdminOwner) {
            bool nonElevatedOwnerProcess = false;
            for (const auto& [pid, process] : pipe.processes) {
                if (process.accountSid == ownerSid && !process.elevated && !process.system
                    && !process.localService && !process.networkService) {
                    nonElevatedOwnerProcess = true;
                }
            }
            if (nonElevatedOwnerProcess) {
                pipe.findings.push_back({
                    Severity::High,
                    "NON_ELEVATED_OWNER_PROCESS",
                    "管道所有者进程未提升且不是系统/服务账户",
                    "低/中完整性进程若能创建该名称，可能在高权限客户端启动前实施名称抢占。 "
                        + processSummary(pipe),
                    "让高权限服务在启动早期以 FILE_FLAG_FIRST_PIPE_INSTANCE 和严格 SD 创建管道；"
                    "客户端连接前校验 GetNamedPipeServerProcessId 对应进程。"
                });
            } else {
                pipe.findings.push_back({
                    Severity::Low,
                    "CONFIRM_OWNER",
                    "请确认管道所有者符合服务身份: " + util::wideToUtf8(owner.displayName),
                    "非 SYSTEM/Administrators 所有者不一定有问题，例如虚拟服务账户或特定安装账户。",
                    "将所有者固定为服务 SID、SYSTEM 或 Administrators，并纳入基线检查。"
                });
            }
        }
    }

    for (const auto* ref : refs) {
        if (!ref || ref->servicePid == 0) continue;
        bool servicePidHasHandle = pipe.processes.count(ref->servicePid) != 0;
        if (!servicePidHasHandle && !pipe.processes.empty()) {
            std::string serviceName = util::wideToUtf8(ref->serviceName);
            pipe.findings.push_back({
                reportElevated ? Severity::Critical : Severity::High,
                "SERVICE_PID_MISMATCH",
                "当前管道句柄不属于引用该名称的服务 PID: " + serviceName,
                "服务 PID=" + std::to_string(ref->servicePid)
                    + "，但可复制句柄的所有者为: " + processSummary(pipe)
                    + (reportElevated
                           ? "。这可能表示同名管道已被其他进程/抢占者创建；也可能是字符串来自未加载的二进制或服务当前未运行。"
                           : "。当前未完整提权，受保护进程的句柄可能无法复制，因此该判断存在权限缺口。"),
                "以管理员/SYSTEM 复核句柄进程路径和签名；客户端应拒绝非预期 PID/镜像/服务 SID，并告警。"
            });
        }
    }

    if (!pipe.processes.empty() && !pipe.objectCreationTimeUtc.empty()) {
        // Timing data is retained in JSON; do not cry wolf solely on a short delay.
    }
}

}  // namespace

void analyzeReport(AuditReport& report) {
    std::unordered_map<std::wstring, const ServiceInfo*> serviceByName;
    for (const ServiceInfo& service : report.services) {
        serviceByName[util::lowerWide(service.name)] = &service;
    }

    std::unordered_map<std::wstring, std::vector<const ServicePipeReference*>> refsByName;
    for (const ServicePipeReference& ref : report.references) {
        if (!ref.formatTemplate) refsByName[ref.normalizedName].push_back(&ref);
    }

    std::unordered_set<std::wstring> absentReported;

    for (PipeInfo& pipe : report.pipes) {
        std::wstring key = util::lowerWide(pipe.name);
        auto refsIt = refsByName.find(key);
        std::vector<const ServicePipeReference*> refs;
        bool privilegedServiceRef = false;
        if (refsIt != refsByName.end()) {
            refs = refsIt->second;
            for (const auto* ref : refs) {
                if (ref->runningAsSystem) privilegedServiceRef = true;
            }
        }

        analyzeSecurity(pipe, privilegedServiceRef);
        analyzeOwnership(pipe, report.elevated, serviceByName, refs);

        bool impersonationHint = false;
        for (const auto* ref : refs) {
            if (ref && ref->impersonateApiHint) impersonationHint = true;
        }
        if (impersonationHint) {
            pipe.findings.push_back({
                Severity::Low,
                "IMPERSONATION_API_HINT",
                "关联服务二进制包含 ImpersonateNamedPipeClient 字符串/导入提示",
                "这本身不是漏洞；服务端必须在模拟后查询令牌并执行授权，且不能把高权限操作暴露给任意连接者。",
                "使用 pipesec::ClientImpersonation RAII，在模拟上下文中做组成员/AccessCheck；"
                "客户端默认使用 SecurityIdentification 并校验服务端 PID/镜像/服务 SID。"
            });
        }

        if (!pipe.remoteClientsRejected && pipe.pipeFlags != 0) {
            pipe.findings.push_back({
                Severity::Low,
                "REMOTE_CLIENTS_NOT_EXPLICITLY_REJECTED",
                "未在查询到的管道句柄上看到 PIPE_REJECT_REMOTE_CLIENTS",
                "本地提权是主要风险，但允许远程客户端会扩大攻击面；该判断可能受复制到的是客户端/服务端句柄影响。",
                "服务端 CreateNamedPipe 的 dwPipeMode 中加入 PIPE_REJECT_REMOTE_CLIENTS，并通过防火墙/SMB 策略限制远程访问。"
            });
        }

        if (refs.empty() && pipeTouchesPrivilegedProcess(pipe)
            && std::any_of(pipe.security.aces.begin(), pipe.security.aces.end(),
                           [](const AceInfo& ace) { return ace.trustee.broadUntrusted; })) {
            pipe.findings.push_back({
                Severity::Medium,
                "UNKNOWN_PRODUCER_BROAD_ACL",
                "未在已扫描服务二进制中找到该管道名，但 ACL 包含宽泛主体且有高权限进程句柄",
                "可能来自第三方 DLL、按需启动组件或动态名称。需要结合进程镜像和模块/字符串进一步确认。",
                "联系组件厂商获取严格 SD 与 FIRST_PIPE_INSTANCE 支持；在修复前用学习模式生成兼容白名单 SDDL。"
            });
        }
    }

    // Predictable names referenced by SYSTEM service binaries but not currently present.
    for (const ServicePipeReference& ref : report.references) {
        if (ref.formatTemplate || !ref.runningAsSystem) continue;
        std::wstring key = ref.normalizedName;
        if (refsByName.count(key) == 0) continue;  // unreachable, kept for clarity
        bool currentlyExists = false;
        for (const PipeInfo& pipe : report.pipes) {
            if (util::lowerWide(pipe.name) == key) {
                currentlyExists = true;
                break;
            }
        }
        if (currentlyExists) continue;

        const ServiceInfo* service = nullptr;
        if (auto it = serviceByName.find(util::lowerWide(ref.serviceName));
            it != serviceByName.end()) {
            service = it->second;
        }
        if (service && service->startType == SERVICE_DISABLED) continue;

        std::wstring dedupeKey = key + L"|" + util::lowerWide(ref.serviceName);
        if (!absentReported.insert(dedupeKey).second) continue;

        bool autoStart = service && service->startType == SERVICE_AUTO_START;
        bool running = service && service->state == SERVICE_RUNNING;
        Severity severity = running ? Severity::Medium
                                    : (autoStart ? Severity::High : Severity::Medium);

        Finding finding;
        finding.severity = severity;
        finding.code = "PREDICTABLE_NAME_ABSENT";
        finding.title = "SYSTEM 服务引用的管道名当前不存在，存在启动前抢占窗口";
        finding.detail = "服务 " + util::wideToUtf8(ref.serviceName)
            + (autoStart ? "（自动启动）" : "（手动/触发启动）")
            + " 的镜像或 ServiceDll 包含管道 " + util::wideToUtf8(ref.pipeName)
            + "，但当前快照中不存在。若该名称可预测且服务尚未调用 CreateNamedPipe，低权限进程可能抢先创建服务端并等待高权限客户端连接。"
            + (running ? " 服务当前状态为 RUNNING：这也可能只是客户端字符串、动态后缀或已关闭的瞬时管道，需用 watch 模式复核。" : "")
            + " 文件: " + util::wideToUtf8(ref.scannedFile);
        finding.remediation = "服务启动最早期使用严格 SDDL 和 FILE_FLAG_FIRST_PIPE_INSTANCE 创建管道；"
                              "客户端以 SECURITY_IDENTIFICATION 首连并校验 GetNamedPipeServerProcessId/服务 SID/镜像签名；"
                              "使用 watch 与 Sysmon Event 17/18 捕获创建时序。";
        report.findings.push_back(std::move(finding));
    }
}

}  // namespace pipesec
