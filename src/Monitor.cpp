#include "Monitor.h"

#include "Auditor.h"
#include "Util.h"

#include <windows.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

namespace pipesec {

namespace {

using util::toJson;

std::unordered_map<std::wstring, int64_t> loadState(const std::string& path) {
    std::unordered_map<std::wstring, int64_t> state;
    if (path.empty()) return state;
    std::ifstream in(std::filesystem::u8path(path));
    std::string line;
    while (std::getline(in, line)) {
        size_t tab = line.find('\t');
        if (tab == std::string::npos) continue;
        try {
            int64_t seconds = std::stoll(line.substr(0, tab));
            std::wstring key = util::utf8ToWide(line.substr(tab + 1));
            state[util::lowerWide(key)] = seconds;
        } catch (...) {
            // Ignore corrupt/partial line; state is only a convenience cache.
        }
    }
    return state;
}

void saveState(const std::string& path,
               const std::unordered_map<std::wstring, int64_t>& state) {
    if (path.empty()) return;
    std::ofstream out(std::filesystem::u8path(path), std::ios::trunc);
    for (const auto& [key, seconds] : state) {
        out << seconds << '\t' << util::wideToUtf8(key) << '\n';
    }
}

Severity maxSeverity(const PipeInfo& pipe) {
    Severity max = Severity::Info;
    for (const Finding& f : pipe.findings) max = std::max(max, f.severity);
    return max;
}

std::string createdEventJson(const PipeInfo& pipe, const std::string& firstSeen) {
    std::ostringstream out;
    out << "{\"event\":\"created\",\"timestampUtc\":" << toJson(util::nowUtcString())
        << ",\"firstSeenUtc\":" << toJson(firstSeen)
        << ",\"objectCreationTimeUtc\":" << toJson(pipe.objectCreationTimeUtc)
        << ",\"pipe\":{"
        << "\"name\":" << toJson(pipe.name)
        << ",\"sddl\":" << toJson(pipe.security.sddl)
        << ",\"owner\":" << toJson(pipe.security.ownerName.empty()
                                       ? pipe.security.ownerSid
                                       : pipe.security.ownerName)
        << ",\"nullDacl\":" << (pipe.security.nullDacl ? "true" : "false")
        << ",\"maxSeverity\":" << toJson(severityName(maxSeverity(pipe)))
        << ",\"pids\":[";
    bool first = true;
    for (const auto& [pid, proc] : pipe.processes) {
        if (!first) out << ",";
        first = false;
        out << pid;
    }
    out << "],\"findings\":[";
    for (size_t i = 0; i < pipe.findings.size(); ++i) {
        if (i) out << ",";
        out << toJson(pipe.findings[i].code);
    }
    out << "]}}\n";
    return out.str();
}

std::string removedEventJson(const std::wstring& name) {
    return "{\"event\":\"removed\",\"timestampUtc\":" + toJson(util::nowUtcString())
           + ",\"name\":" + toJson(name) + "}\n";
}

}  // namespace

int runWatch(const WatchOptions& options, std::ostream& out) {
    auto state = loadState(options.stateFile);
    std::unordered_set<std::wstring> previous;
    bool firstTick = true;
    int64_t start = util::unixSecondsNow();

    if (options.jsonl) {
        out << "{\"event\":\"started\",\"timestampUtc\":" << toJson(util::nowUtcString())
            << ",\"intervalMs\":" << options.intervalMs << "}\n";
    } else {
        out << "开始监视命名管道，间隔 " << options.intervalMs << " ms";
        if (options.durationSec > 0) out << "，持续 " << options.durationSec << " 秒";
        out << "。按 Ctrl+C 可停止。\n";
    }

    while (true) {
        AuditOptions tickOptions = options.auditOptions;
        if (!firstTick) {
            // Service binary string scanning is useful for the initial baseline but
            // far too expensive to repeat every poll.
            tickOptions.scanServices = false;
            tickOptions.scanServiceBinaries = false;
        }

        AuditReport report = runAudit(tickOptions);
        std::unordered_set<std::wstring> current;

        for (const PipeInfo& pipe : report.pipes) {
            std::wstring key = util::lowerWide(pipe.name);
            current.insert(key);
            int64_t seen = util::unixSecondsNow();
            auto stateIt = state.find(key);
            if (stateIt == state.end()) state[key] = seen;
            else seen = stateIt->second;
            std::string firstSeenUtc = util::unixSecondsToUtcString(seen);

            bool isNew = !firstTick && !previous.count(key);
            if (isNew || (firstTick && options.emitExisting)) {
                if (options.jsonl) {
                    out << createdEventJson(pipe, firstSeenUtc);
                } else {
                    out << "[CREATE] " << util::nowUtcString() << " "
                        << util::wideToUtf8(pipe.name)
                        << " firstSeen=" << firstSeenUtc
                        << " severity=" << severityName(maxSeverity(pipe))
                        << " sddl=" << util::wideToUtf8(pipe.security.sddl) << "\n";
                    for (const Finding& f : pipe.findings) {
                        out << "    - [" << severityName(f.severity) << "] "
                            << f.code << ": " << f.title << "\n";
                    }
                }
            }
        }

        if (!firstTick) {
            for (const std::wstring& oldKey : previous) {
                if (current.count(oldKey)) continue;
                if (options.jsonl) out << removedEventJson(oldKey);
                else out << "[REMOVE] " << util::nowUtcString() << " "
                         << util::wideToUtf8(oldKey) << "\n";
                state.erase(oldKey);
            }
        }

        previous = std::move(current);
        saveState(options.stateFile, state);
        firstTick = false;

        if (options.durationSec > 0
            && util::unixSecondsNow() - start >= options.durationSec) {
            break;
        }
        ::Sleep(options.intervalMs);
    }

    if (options.jsonl) {
        out << "{\"event\":\"stopped\",\"timestampUtc\":" << toJson(util::nowUtcString()) << "}\n";
    } else {
        out << "监视结束。\n";
    }
    return 0;
}

}  // namespace pipesec
