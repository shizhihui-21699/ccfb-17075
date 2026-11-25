#pragma once

#include "pipesec/types.h"

#include <iosfwd>
#include <string>

namespace pipesec {

struct WatchOptions {
    uint32_t intervalMs = 1000;
    int durationSec = 0;  // 0 means until interrupted.
    bool jsonl = false;
    bool emitExisting = false;
    std::string stateFile;
    AuditOptions auditOptions{};
};

int runWatch(const WatchOptions& options, std::ostream& out);

}  // namespace pipesec
