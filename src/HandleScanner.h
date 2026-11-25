#pragma once

#include "pipesec/types.h"

#include <map>
#include <string>
#include <vector>

namespace pipesec {

struct HandleScanResult {
    // Key is lower-cased pipe name without \\.\pipe\.
    std::map<std::wstring, std::vector<HandleOwner>> owners;
    std::map<std::wstring, uint64_t> creationTimes;
    std::map<std::wstring, uint32_t> pipeFlags;
    std::map<std::wstring, uint32_t> maxInstances;
    std::vector<std::string> warnings;
    uint64_t totalHandles = 0;
};

HandleScanResult scanSystemHandlesForPipes();

}  // namespace pipesec
