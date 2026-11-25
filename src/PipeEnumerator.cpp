#include "PipeEnumerator.h"

#include "Util.h"

#include <windows.h>

#include <algorithm>

namespace pipesec {

std::vector<std::wstring> enumeratePipeNames() {
    std::vector<std::wstring> names;
    constexpr wchar_t kPattern[] = L"\\\\.\\pipe\\*";

    WIN32_FIND_DATAW data{};
    HANDLE find = ::FindFirstFileW(kPattern, &data);
    if (find == INVALID_HANDLE_VALUE) return names;

    do {
        std::wstring name = data.cFileName;
        if (name.empty() || name == L"." || name == L"..") continue;
        names.push_back(std::move(name));
    } while (::FindNextFileW(find, &data));

    ::FindClose(find);
    std::sort(names.begin(), names.end(), [](const auto& a, const auto& b) {
        return util::lowerWide(a) < util::lowerWide(b);
    });
    names.erase(std::unique(names.begin(), names.end(), [](const auto& a, const auto& b) {
        return util::equalsIgnoreCase(a, b);
    }), names.end());
    return names;
}

}  // namespace pipesec
