#pragma once

#include "pipesec/types.h"

#include <windows.h>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace pipesec::util {

std::wstring utf8ToWide(const std::string& value);
std::string wideToUtf8(const std::wstring& value);
std::string wideToUtf8(PCWSTR value);

std::wstring lowerWide(std::wstring value);
std::string lowerAscii(std::string value);
bool startsWithIgnoreCase(std::wstring_view value, std::wstring_view prefix);
bool containsIgnoreCase(std::wstring_view value, std::wstring_view needle);
bool equalsIgnoreCase(std::wstring_view a, std::wstring_view b);

std::string jsonEscape(std::string_view value);
std::string toJson(const std::wstring& value);
std::string toJson(const std::string& value);

std::string fileTimeToUtcString(uint64_t fileTime100ns);
std::string nowUtcString();
int64_t unixSecondsNow();
std::string unixSecondsToUtcString(int64_t seconds);

std::wstring sidToString(PSID sid);
bool equalWellKnownSid(PSID sid, WELL_KNOWN_SID_TYPE type);
SidInfo lookupSid(PSID sid);
SidInfo lookupSidString(const std::wstring& sidString);

bool enablePrivilege(const wchar_t* privilegeName);
bool isElevated();
std::wstring currentHostName();

std::wstring formatWindowsError(DWORD error = ::GetLastError());

std::optional<std::vector<unsigned char>> readFileBytes(
    const std::wstring& path, size_t maxBytes);

std::wstring expandPath(const std::wstring& rawPath);
std::wstring extractImagePath(const std::wstring& binPath);

}  // namespace pipesec::util
