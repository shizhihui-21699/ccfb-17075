#pragma once

#include "pipesec/types.h"

#include <string>

namespace pipesec {

SecurityInfo readPipeSecurity(const std::wstring& pipeName);
std::string describeAccessMask(uint32_t mask);
std::string aceTypeName(unsigned char type);

}  // namespace pipesec
