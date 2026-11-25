#include "HandleScanner.h"

#include "Util.h"

#include <winternl.h>

#include <unordered_map>

namespace pipesec {

namespace {

using NtQuerySystemInformationFn = NTSTATUS(NTAPI*)(ULONG systemInformationClass,
                                                    PVOID systemInformation,
                                                    ULONG systemInformationLength,
                                                    PULONG returnLength);
using NtQueryObjectFn = NTSTATUS(NTAPI*)(HANDLE handle,
                                         ULONG objectInformationClass,
                                         PVOID objectInformation,
                                         ULONG objectInformationLength,
                                         PULONG returnLength);

constexpr ULONG kSystemExtendedHandleInformation = 0x40;
constexpr ULONG kObjectBasicInformation = 0;
constexpr ULONG kObjectNameInformation = 1;
constexpr ULONG kObjectTypeInformation = 2;
constexpr NTSTATUS kStatusSuccess = 0;

struct SystemExtendedHandleEntry {
    PVOID object;
    ULONG_PTR uniqueProcessId;
    ULONG_PTR handleValue;
    ULONG grantedAccess;
    USHORT creatorBackTraceIndex;
    USHORT objectTypeIndex;
    ULONG handleAttributes;
    ULONG reserved;
};

struct SystemExtendedHandleInformation {
    ULONG_PTR numberOfHandles;
    ULONG_PTR reserved;
    SystemExtendedHandleEntry handles[1];
};

struct NtUnicodeString {
    USHORT length;
    USHORT maximumLength;
    PWSTR Buffer;
};

struct ObjectNameInformationBuffer {
    NtUnicodeString name;
};

struct ObjectTypeInformationMin {
    NtUnicodeString typeName;
};

struct ObjectBasicInformationBuffer {
    ULONG attributes;
    ACCESS_MASK grantedAccess;
    ULONG handleCount;
    ULONG pointerCount;
    ULONG pagedPoolCharge;
    ULONG nonPagedPoolCharge;
    ULONG reserved[3];
    ULONG nameInfoSize;
    ULONG typeInfoSize;
    ULONG securityDescriptorSize;
    LARGE_INTEGER creationTime;
};

NtQuerySystemInformationFn querySystemInformationApi() {
    static auto fn = reinterpret_cast<NtQuerySystemInformationFn>(
        ::GetProcAddress(::GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation"));
    return fn;
}

NtQueryObjectFn queryObjectApi() {
    static auto fn = reinterpret_cast<NtQueryObjectFn>(
        ::GetProcAddress(::GetModuleHandleW(L"ntdll.dll"), "NtQueryObject"));
    return fn;
}

std::vector<unsigned char> querySystemHandles() {
    auto ntQuery = querySystemInformationApi();
    if (!ntQuery) return {};

    ULONG size = 1 << 20;
    for (int attempt = 0; attempt < 8; ++attempt) {
        std::vector<unsigned char> buffer(size);
        ULONG returned = 0;
        NTSTATUS status = ntQuery(kSystemExtendedHandleInformation, buffer.data(),
                                  static_cast<ULONG>(buffer.size()), &returned);
        if (status == kStatusSuccess) return buffer;
        if (static_cast<ULONG>(status) == 0xC0000004u) {
            if (returned > size) size = returned + 4096;
            else size *= 2;
            if (size > 256u * 1024u * 1024u) return {};
            continue;
        }
        return {};
    }
    return {};
}

HANDLE openProcessForDuplicate(DWORD pid,
                               std::unordered_map<DWORD, HANDLE>& cache) {
    auto found = cache.find(pid);
    if (found != cache.end()) return found->second;
    HANDLE process = ::OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid);
    cache.emplace(pid, process);  // May store nullptr; failures are cached.
    return process;
}

std::wstring queryObjectName(HANDLE duplicate, NtQueryObjectFn ntQueryObject) {
    ULONG size = 4096;
    for (int attempt = 0; attempt < 6; ++attempt) {
        std::vector<unsigned char> buffer(size);
        ULONG returned = 0;
        NTSTATUS status = ntQueryObject(duplicate, kObjectNameInformation, buffer.data(),
                                        static_cast<ULONG>(buffer.size()), &returned);
        if (status == kStatusSuccess) {
            auto* info = reinterpret_cast<ObjectNameInformationBuffer*>(buffer.data());
            if (info->name.Buffer && info->name.length > 0) {
                return std::wstring(info->name.Buffer, info->name.length / sizeof(wchar_t));
            }
            return {};
        }
        if (static_cast<ULONG>(status) == 0xC0000004u) {
            size = returned > size ? returned + 1024 : size * 2;
            continue;
        }
        break;
    }
    return {};
}

std::wstring queryObjectTypeName(USHORT typeIndex,
                                 const SystemExtendedHandleEntry* firstEntry,
                                 std::unordered_map<DWORD, HANDLE>& processCache,
                                 NtQueryObjectFn ntQueryObject) {
    if (!firstEntry || !ntQueryObject) return {};
    DWORD pid = static_cast<DWORD>(firstEntry->uniqueProcessId);
    HANDLE process = openProcessForDuplicate(pid, processCache);
    if (!process) return {};

    HANDLE duplicate = nullptr;
    if (!::DuplicateHandle(process, reinterpret_cast<HANDLE>(firstEntry->handleValue),
                           ::GetCurrentProcess(), &duplicate, 0, FALSE,
                           DUPLICATE_SAME_ACCESS)) {
        return {};
    }

    std::wstring typeName;
    std::vector<unsigned char> buffer(8192);
    NTSTATUS status = ntQueryObject(duplicate, kObjectTypeInformation, buffer.data(),
                                    static_cast<ULONG>(buffer.size()), nullptr);
    if (status == kStatusSuccess) {
        auto* info = reinterpret_cast<ObjectTypeInformationMin*>(buffer.data());
        if (info->typeName.Buffer && info->typeName.length) {
            typeName.assign(info->typeName.Buffer, info->typeName.length / sizeof(wchar_t));
        }
    }
    ::CloseHandle(duplicate);
    return typeName;
}

}  // namespace

HandleScanResult scanSystemHandlesForPipes() {
    HandleScanResult result;
    auto ntQueryObject = queryObjectApi();

    // Opening the pipe directory gives this process a known File handle. Its
    // ObjectTypeIndex lets us skip type-name queries for every other type.
    HANDLE fileTypeProbe = ::CreateFileW(
        L"\\\\.\\pipe\\", 0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);

    std::vector<unsigned char> buffer = querySystemHandles();
    if (buffer.empty()) {
        if (fileTypeProbe != INVALID_HANDLE_VALUE) ::CloseHandle(fileTypeProbe);
        result.warnings.push_back(
            "NtQuerySystemInformation(SystemExtendedHandleInformation) failed; "
            "run as Administrator for process ownership.");
        return result;
    }

    auto* info = reinterpret_cast<SystemExtendedHandleInformation*>(buffer.data());
    result.totalHandles = static_cast<uint64_t>(info->numberOfHandles);
    auto* entries = reinterpret_cast<SystemExtendedHandleEntry*>(&info->handles[0]);

    std::unordered_map<DWORD, HANDLE> processCache;
    std::vector<USHORT> fileTypeIndices;

    if (fileTypeProbe != INVALID_HANDLE_VALUE) {
        DWORD currentPid = ::GetCurrentProcessId();
        for (ULONG_PTR i = 0; i < info->numberOfHandles; ++i) {
            const auto& entry = entries[i];
            if (entry.uniqueProcessId == currentPid
                && reinterpret_cast<HANDLE>(entry.handleValue) == fileTypeProbe) {
                fileTypeIndices.push_back(entry.objectTypeIndex);
                break;
            }
        }
        ::CloseHandle(fileTypeProbe);
    }

    if (fileTypeIndices.empty()) {
        std::unordered_map<USHORT, const SystemExtendedHandleEntry*> firstByType;
        for (ULONG_PTR i = 0; i < info->numberOfHandles; ++i) {
            const auto& entry = entries[i];
            if (!firstByType.count(entry.objectTypeIndex)) {
                firstByType.emplace(entry.objectTypeIndex, &entry);
            }
        }
        for (const auto& [typeIndex, entry] : firstByType) {
            std::wstring typeName = queryObjectTypeName(
                typeIndex, entry, processCache, ntQueryObject);
            if (typeName == L"File") fileTypeIndices.push_back(typeIndex);
        }
    }

    // If type resolution failed globally, fall back to checking every handle.
    // It is slower but keeps ownership discovery possible in restricted tokens.
    bool inspectAllTypes = fileTypeIndices.empty();

    constexpr std::wstring_view kDevicePipePrefix = L"\\Device\\NamedPipe\\";

    for (ULONG_PTR i = 0; i < info->numberOfHandles; ++i) {
        const auto& entry = entries[i];
        if (!inspectAllTypes) {
            bool isFileType = false;
            for (USHORT index : fileTypeIndices) {
                if (entry.objectTypeIndex == index) {
                    isFileType = true;
                    break;
                }
            }
            if (!isFileType) continue;
        }
        if (entry.uniqueProcessId > UINT32_MAX) continue;

        DWORD pid = static_cast<DWORD>(entry.uniqueProcessId);
        HANDLE process = openProcessForDuplicate(pid, processCache);
        if (!process) continue;

        HANDLE duplicate = nullptr;
        if (!::DuplicateHandle(process, reinterpret_cast<HANDLE>(entry.handleValue),
                               ::GetCurrentProcess(), &duplicate, 0, FALSE,
                               DUPLICATE_SAME_ACCESS)) {
            continue;
        }

        std::wstring objectName = queryObjectName(duplicate, ntQueryObject);
        if (util::startsWithIgnoreCase(objectName, kDevicePipePrefix)) {
            std::wstring pipeName = objectName.substr(kDevicePipePrefix.size());
            std::wstring key = util::lowerWide(pipeName);

            HandleOwner owner;
            owner.processId = pid;
            owner.handleValue = static_cast<uint64_t>(entry.handleValue);
            owner.grantedAccess = entry.grantedAccess;
            owner.objectTypeIndex = entry.objectTypeIndex;
            result.owners[key].push_back(owner);

            if (!result.creationTimes.count(key) && ntQueryObject) {
                ObjectBasicInformationBuffer basic{};
                if (ntQueryObject(duplicate, kObjectBasicInformation, &basic,
                                  sizeof(basic), nullptr) == kStatusSuccess
                    && basic.creationTime.QuadPart > 0) {
                    result.creationTimes[key] =
                        static_cast<uint64_t>(basic.creationTime.QuadPart);
                }
            }

            if (!result.pipeFlags.count(key)) {
                DWORD flags = 0;
                DWORD maxInstances = 0;
                if (::GetNamedPipeInfo(duplicate, &flags, nullptr, nullptr, &maxInstances)) {
                    result.pipeFlags[key] = flags;
                    result.maxInstances[key] = maxInstances;
                }
            }
        }

        ::CloseHandle(duplicate);
    }

    for (auto& [pid, handle] : processCache) {
        if (handle) ::CloseHandle(handle);
    }
    return result;
}

}  // namespace pipesec
