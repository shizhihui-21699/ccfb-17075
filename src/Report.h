#pragma once

#include "pipesec/types.h"

#include <string>

namespace pipesec {

std::string reportToJson(const AuditReport& report);
std::string reportToText(const AuditReport& report,
                         Severity minimumSeverity = Severity::Low,
                         bool showAllPipes = true);

}  // namespace pipesec
