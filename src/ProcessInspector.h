#pragma once

#include "pipesec/types.h"

#include <unordered_map>

namespace pipesec {

class ProcessResolver {
public:
    void setServices(const std::vector<ServiceInfo>& services);
    ProcessInfo get(uint32_t pid);

private:
    void ensureParentMap();
    std::unordered_map<uint32_t, ProcessInfo> cache_;
    std::unordered_map<uint32_t, uint32_t> parents_;
    std::unordered_map<uint32_t, std::vector<std::wstring>> serviceNamesByPid_;
    bool parentsBuilt_ = false;
};

}  // namespace pipesec
