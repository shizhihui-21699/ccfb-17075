#include "Auditor.h"
#include "Harden.h"
#include "Monitor.h"
#include "Report.h"
#include "Util.h"

#include <windows.h>

#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <filesystem>
#include <iostream>
#include <unordered_map>
#include <unordered_set>

namespace {

struct CommonArgs {
    std::string command = "audit";
    std::string format = "text";
    std::string out;
    std::string minSeverity = "low";
    std::string nameFilter;
    std::string failOn;
    bool handles = true;
    bool processes = true;
    bool services = true;
    bool binaryScan = true;
    uint32_t maxBinaryMb = 64;

    uint32_t intervalMs = 1000;
    int durationSec = 0;
    bool jsonl = false;
    bool emitExisting = false;
    std::string stateFile;

    std::wstring pipeName;
    std::wstring sddl;
    std::string preset;
    bool apply = false;
    std::wstring healthCheck;
    std::string backupFile;
};

void printHelp() {
    std::cout <<
R"(PipeSec - Windows 命名管道枚举、风险分析、监视与安全加固

用法:
  pipe-audit [audit] [选项]
  pipe-audit watch [选项]
  pipe-audit learn --name <管道名> [--duration-sec 30] [--interval-ms 500] [--out candidate.sddl]
  pipe-audit harden --name <管道名> (--preset <名称> | --sddl <SDDL>) [--apply]
  pipe-audit presets
  pipe-audit help

audit 选项:
  --format text|json         输出格式，默认 text
  --json                     等价于 --format json
  --out <文件>               将完整报告写入文件
  --min-severity <level>     text 详细发现最低级别: info/low/medium/high/critical
  --name <文本>              仅保留名称包含该文本的管道
  --fail-on <level>          存在该级别及以上发现时退出码=2
  --no-handles               不枚举系统句柄表（更快，但没有 PID 归属）
  --no-processes             不查询进程账户/提升状态
  --no-services              不枚举 Windows 服务
  --no-binary-scan           不扫描服务镜像/ServiceDll 中的管道字符串
  --max-binary-mb <MB>       单个二进制扫描上限，默认 64

watch 选项:
  --interval-ms <ms>         轮询间隔，默认 1000
  --duration-sec <秒>        持续时间，0 表示一直运行
  --jsonl                    输出 JSON Lines 事件
  --state <文件>             持久化 first-seen 时间
  --emit-existing            首轮也输出所有现存管道
  以及 audit 中的 --no-handles/--no-services 等降噪选项

harden 选项:
  --name <管道名>            不带 \\.\pipe\ 前缀的名称
  --preset <名称>            strict | high-integrity | users | interactive
  --sddl <SDDL>              自定义 SDDL，覆盖 --preset
  --apply                    真正生效；默认只 dry-run
  --health-check <命令行>    应用后执行；非 0 退出则回滚旧 SDDL
  --backup <文件>            将旧 SDDL 备份到文件

说明:
  枚举和句柄复制是只读操作。建议以管理员身份运行以获得完整 PID/ACL 信息。
  外部修改第三方管道 DACL 可能破坏通信；请先 dry-run、备份并使用健康检查。
)";
}

bool parseArgs(int argc, wchar_t** argv, CommonArgs& args) {
    std::vector<std::wstring> wideArgs;
    for (int i = 1; i < argc; ++i) wideArgs.emplace_back(argv[i]);

    size_t i = 0;
    if (i < wideArgs.size() && !wideArgs[i].empty() && wideArgs[i][0] != L'-') {
        args.command = pipesec::util::wideToUtf8(wideArgs[i]);
        ++i;
    }

    auto needValue = [&](const char* option) -> std::wstring {
        if (i + 1 >= wideArgs.size()) {
            std::cerr << "选项 " << option << " 缺少值\n";
            return {};
        }
        ++i;
        return wideArgs[i];
    };

    for (; i < wideArgs.size(); ++i) {
        std::string a = pipesec::util::wideToUtf8(wideArgs[i]);
        if (a == "--json") args.format = "json";
        else if (a == "--apply") args.apply = true;
        else if (a == "--no-handles") args.handles = false;
        else if (a == "--no-processes") args.processes = false;
        else if (a == "--no-services") args.services = false;
        else if (a == "--no-binary-scan") args.binaryScan = false;
        else if (a == "--jsonl") args.jsonl = true;
        else if (a == "--emit-existing") args.emitExisting = true;
        else if (a == "--format") args.format = pipesec::util::wideToUtf8(needValue("--format"));
        else if (a == "--out") args.out = pipesec::util::wideToUtf8(needValue("--out"));
        else if (a == "--min-severity") args.minSeverity = pipesec::util::wideToUtf8(needValue("--min-severity"));
        else if (a == "--name") args.nameFilter = pipesec::util::wideToUtf8(needValue("--name"));
        else if (a == "--fail-on") args.failOn = pipesec::util::wideToUtf8(needValue("--fail-on"));
        else if (a == "--state") args.stateFile = pipesec::util::wideToUtf8(needValue("--state"));
        else if (a == "--backup") args.backupFile = pipesec::util::wideToUtf8(needValue("--backup"));
        else if (a == "--preset") args.preset = pipesec::util::wideToUtf8(needValue("--preset"));
        else if (a == "--interval-ms") args.intervalMs = static_cast<uint32_t>(_wtoi(needValue(a.c_str()).c_str()));
        else if (a == "--duration-sec") args.durationSec = _wtoi(needValue(a.c_str()).c_str());
        else if (a == "--max-binary-mb") args.maxBinaryMb = static_cast<uint32_t>(_wtoi(needValue(a.c_str()).c_str()));
        else if (a == "--pipe-name" || a == "--name") args.pipeName = needValue("--name");
        else if (a == "--sddl") args.sddl = needValue("--sddl");
        else if (a == "--health-check") args.healthCheck = needValue("--health-check");
        else if (a == "help" || a == "--help" || a == "-h") args.command = "help";
        else {
            std::cerr << "未知参数: " << a << "\n";
            return false;
        }
    }

    // --name is shared between filtering and harden/learn. In those modes it is the pipe name.
    if ((args.command == "harden" || args.command == "learn")
        && args.pipeName.empty() && !args.nameFilter.empty()) {
        args.pipeName = pipesec::util::utf8ToWide(args.nameFilter);
    }
    return true;
}

pipesec::AuditOptions makeAuditOptions(const CommonArgs& args) {
    pipesec::AuditOptions options;
    options.scanHandles = args.handles;
    options.enrichProcesses = args.processes;
    options.scanServices = args.services;
    options.scanServiceBinaries = args.binaryScan;
    options.maxBinaryBytes = static_cast<size_t>(args.maxBinaryMb) * 1024u * 1024u;
    return options;
}

int runAuditCommand(const CommonArgs& args) {
    auto minSeverity = pipesec::parseSeverity(args.minSeverity);
    if (!minSeverity) {
        std::cerr << "无效 --min-severity: " << args.minSeverity << "\n";
        return 1;
    }

    pipesec::AuditReport report = pipesec::runAudit(makeAuditOptions(args));
    if (!args.nameFilter.empty()) {
        std::wstring needle = pipesec::util::utf8ToWide(args.nameFilter);
        report.pipes.erase(std::remove_if(report.pipes.begin(), report.pipes.end(),
            [&](const pipesec::PipeInfo& p) {
                return !pipesec::util::containsIgnoreCase(p.name, needle);
            }), report.pipes.end());
    }

    std::string output;
    if (args.format == "json") {
        output = pipesec::reportToJson(report);
    } else if (args.format == "text") {
        output = pipesec::reportToText(report, *minSeverity, true);
    } else {
        std::cerr << "无效 --format: " << args.format << "\n";
        return 1;
    }

    if (!args.out.empty()) {
        std::ofstream file(std::filesystem::u8path(args.out), std::ios::binary | std::ios::trunc);
        if (!file) {
            std::cerr << "无法写入 --out: " << args.out << "\n";
            return 1;
        }
        file << output;
        std::cout << "报告已写入 " << args.out << " (" << output.size() << " bytes)\n";
    } else {
        std::cout << output;
    }

    if (!args.failOn.empty()) {
        auto threshold = pipesec::parseSeverity(args.failOn);
        if (!threshold) {
            std::cerr << "无效 --fail-on: " << args.failOn << "\n";
            return 1;
        }
        for (const auto& f : report.findings) {
            if (f.severity >= *threshold) return 2;
        }
        for (const auto& p : report.pipes) {
            for (const auto& f : p.findings) {
                if (f.severity >= *threshold) return 2;
            }
        }
    }
    return 0;
}

int runWatchCommand(const CommonArgs& args) {
    pipesec::WatchOptions watch;
    watch.intervalMs = args.intervalMs == 0 ? 1000 : args.intervalMs;
    watch.durationSec = args.durationSec;
    watch.jsonl = args.jsonl || args.format == "json";
    watch.emitExisting = args.emitExisting;
    watch.stateFile = args.stateFile;
    watch.auditOptions = makeAuditOptions(args);
    if (watch.jsonl && args.out.empty()) return pipesec::runWatch(watch, std::cout);

    std::ofstream file;
    if (!args.out.empty()) {
        file.open(std::filesystem::u8path(args.out), std::ios::binary | std::ios::trunc);
        if (!file) {
            std::cerr << "无法写入 --out: " << args.out << "\n";
            return 1;
        }
        return pipesec::runWatch(watch, file);
    }
    return pipesec::runWatch(watch, std::cout);
}

int runLearnCommand(const CommonArgs& args) {
    if (args.pipeName.empty()) {
        std::cerr << "learn 需要 --name <管道名>\n";
        return 1;
    }

    int duration = args.durationSec > 0 ? args.durationSec : 30;
    uint32_t interval = args.intervalMs == 0 ? 500 : args.intervalMs;
    pipesec::AuditOptions options = makeAuditOptions(args);
    options.scanServices = true;
    options.scanServiceBinaries = false;

    std::unordered_set<std::wstring> serverSids;
    std::unordered_set<std::wstring> clientSids;
    std::unordered_map<std::wstring, std::wstring> sidNames;
    std::unordered_set<uint32_t> observedPids;

    std::wcout << L"学习管道 " << args.pipeName << L"，持续 " << duration
               << L" 秒；请在此期间运行业务客户端和健康检查。\n";

    int64_t start = pipesec::util::unixSecondsNow();
    while (pipesec::util::unixSecondsNow() - start < duration) {
        pipesec::AuditReport report = pipesec::runAudit(options);
        for (const pipesec::PipeInfo& pipe : report.pipes) {
            if (!pipesec::util::equalsIgnoreCase(pipe.name, args.pipeName)) continue;
            for (const auto& [pid, process] : pipe.processes) {
                observedPids.insert(pid);
                if (process.accountSid.empty()) continue;
                sidNames[process.accountSid] = process.accountName;
                bool isService = !process.services.empty() || process.system
                                  || process.localService || process.networkService;
                if (isService) serverSids.insert(process.accountSid);
                else clientSids.insert(process.accountSid);
            }
        }
        ::Sleep(interval);
    }

    std::wstring sddl = L"D:P(A;;GA;;;SY)(A;;GA;;;BA)";
    for (const std::wstring& sid : serverSids) {
        if (sid == L"S-1-5-18" || sid == L"S-1-5-32-544") continue;
        sddl += L"(A;;GA;;;" + sid + L")";
    }
    for (const std::wstring& sid : clientSids) {
        if (sid == L"S-1-5-18" || sid == L"S-1-5-32-544") continue;
        sddl += L"(A;;GRGW;;;" + sid + L")";
    }

    std::cout << "观察到 PID:";
    for (uint32_t pid : observedPids) std::cout << ' ' << pid;
    std::cout << "\n主体:\n";
    for (const auto& [sid, name] : sidNames) {
        std::wcout << L"  " << sid << L" " << name << L"\n";
    }
    std::wcout << L"候选 SDDL（必须由人工/预生产验证）:\n" << sddl << L"\n";
    std::cout << "下一步: pipe-audit harden --name "
              << pipesec::util::wideToUtf8(args.pipeName)
              << " --sddl '<候选 SDDL>' --health-check <业务健康检查> --apply --backup <文件>\n";

    if (!args.out.empty()) {
        std::ofstream out(std::filesystem::u8path(args.out), std::ios::binary | std::ios::trunc);
        out << pipesec::util::wideToUtf8(sddl) << "\n";
        std::cout << "候选 SDDL 已写入 " << args.out << "\n";
    }
    return 0;
}

int runHardenCommand(const CommonArgs& args) {
    if (args.pipeName.empty()) {
        std::cerr << "harden 需要 --name <管道名>\n";
        return 1;
    }

    std::wstring sddl = args.sddl;
    if (sddl.empty() && !args.preset.empty()) {
        sddl = pipesec::hardeningPresetSddl(args.preset);
        if (sddl.empty()) {
            std::cerr << "未知 --preset: " << args.preset << "\n";
            return 1;
        }
    }
    if (sddl.empty()) {
        std::cerr << "harden 需要 --sddl 或 --preset\n";
        return 1;
    }

    pipesec::HardenResult result = pipesec::hardenPipe(
        args.pipeName, sddl, args.apply, args.healthCheck);

    std::cout << "管道: " << pipesec::util::wideToUtf8(result.pipeName) << "\n";
    std::cout << "模式: " << (result.dryRun ? "dry-run" : "APPLY") << "\n";
    std::cout << "旧 SDDL: " << pipesec::util::wideToUtf8(result.oldSddl) << "\n";
    std::cout << "目标 SDDL: " << pipesec::util::wideToUtf8(result.requestedSddl) << "\n";
    if (!result.appliedSddl.empty()) {
        std::cout << "当前 SDDL: " << pipesec::util::wideToUtf8(result.appliedSddl) << "\n";
    }
    if (result.healthCheckExitCode.has_value()) {
        std::cout << "健康检查退出码: " << *result.healthCheckExitCode << "\n";
    }
    std::cout << "回滚: " << (result.rolledBack ? "已执行" : "否") << "\n";
    std::cout << "结果: " << pipesec::util::wideToUtf8(result.message) << "\n";

    if (!args.backupFile.empty() && !result.oldSddl.empty()) {
        std::ofstream backup(std::filesystem::u8path(args.backupFile),
                             std::ios::binary | std::ios::trunc);
        backup << pipesec::util::wideToUtf8(result.oldSddl) << "\n";
        std::cout << "旧 SDDL 已备份: " << args.backupFile << "\n";
    }

    return result.success ? 0 : 1;
}

void printPresets() {
    std::cout << "strict/system-admins: "
              << pipesec::util::wideToUtf8(pipesec::hardeningPresetSddl("strict")) << "\n";
    std::cout << "high-integrity: "
              << pipesec::util::wideToUtf8(pipesec::hardeningPresetSddl("high-integrity")) << "\n";
    std::cout << "users: "
              << pipesec::util::wideToUtf8(pipesec::hardeningPresetSddl("users")) << "\n";
    std::cout << "interactive: "
              << pipesec::util::wideToUtf8(pipesec::hardeningPresetSddl("interactive")) << "\n";
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    ::SetConsoleOutputCP(CP_UTF8);
    ::SetConsoleCP(CP_UTF8);

    CommonArgs args;
    if (!parseArgs(argc, argv, args)) {
        printHelp();
        return 1;
    }

    if (args.command == "help" || args.command == "--help" || args.command == "-h") {
        printHelp();
        return 0;
    }
    if (args.command == "presets") {
        printPresets();
        return 0;
    }
    if (args.command == "audit") return runAuditCommand(args);
    if (args.command == "watch") return runWatchCommand(args);
    if (args.command == "learn") return runLearnCommand(args);
    if (args.command == "harden") return runHardenCommand(args);

    std::cerr << "未知命令: " << args.command << "\n\n";
    printHelp();
    return 1;
}
