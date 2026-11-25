#pragma once

#include "pipesec/types.h"

#include <vector>

namespace pipesec {

std::vector<ServiceInfo> enumerateServices();

std::vector<ServicePipeReference> findServicePipeReferences(
    const std::vector<ServiceInfo>& services,
    const AuditOptions& options);

// Exposed for unit tests / one-off binary inspection.
std::vector<std::wstring> extractPipeNamesFromBytes(const std::vector<unsigned char>& bytes);
bool bytesContainImpersonationHint(const std::vector<unsigned char>& bytes);

}  // namespace pipesec
