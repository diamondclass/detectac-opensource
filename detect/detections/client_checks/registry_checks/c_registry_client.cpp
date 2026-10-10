#include "c_registry_client.h"
#include "../yara_scanner/rule_delivery.h"
#include "../yara_scanner/yara_compile_util.h"

static std::unordered_map<std::string, std::string> s_registryRuleNames;

std::string PERegistryScanner::FormatFileTimeLocal(const FILETIME& ft)
{
    try
    {
        if (ft.dwLowDateTime == 0 && ft.dwHighDateTime == 0)
            return xorstr_("N/A");

        SYSTEMTIME stUtc{};
        if (!FileTimeToSystemTime(&ft, &stUtc))
            return xorstr_("N/A");

        SYSTEMTIME stLocal{};
        if (!SystemTimeToTzSpecificLocalTime(nullptr, &stUtc, &stLocal))
            return xorstr_("N/A");

        char buf[32];
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            xorstr_("%04u-%02u-%02u %02u:%02u:%02u"),
            stLocal.wYear, stLocal.wMonth, stLocal.wDay,
            stLocal.wHour, stLocal.wMinute, stLocal.wSecond);
        return std::string(buf);
    }
    catch (...) { return xorstr_("N/A"); }
}

void PERegistryScanner::CheckAptitudeProductsKey()
{
    try
    {
        HKEY hKey = nullptr;
        LONG r = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            xorstr_(L"SOFTWARE\\WOW6432Node\\AptitudeProducts"),
            0,
            KEY_READ | KEY_WOW64_64KEY,
            &hKey);
        if (r != ERROR_SUCCESS || !hKey)
            return;

        FILETIME lastWrite{};
        RegQueryInfoKeyW(hKey, nullptr, nullptr, nullptr,
            nullptr, nullptr, nullptr,
            nullptr, nullptr, nullptr,
            nullptr, &lastWrite);
        RegCloseKey(hKey);

        LOG(WARNING, FormatFileTimeLocal(lastWrite))
            << xorstr_("Aptitude Product Cheat Trace Found In Registry");
    }
    catch (...) {}
}

int PERegistryScanner::RegistryYaraCallback(
    YR_SCAN_CONTEXT*,
    int message,
    void* message_data,
    void* user_data)
{
    try
    {
        if (message == CALLBACK_MSG_RULE_MATCHING)
        {
            auto* rule = static_cast<YR_RULE*>(message_data);
            auto* regPath = static_cast<const std::string*>(user_data);

            const auto& names = s_registryRuleNames;
            auto it = names.find(rule->identifier);

            if (it != names.end())
            {
                std::string detectionName = it->second;
                RuleDelivery::StripWarningPrefix(detectionName);
                LOG(WARNING, xorstr_("N/A")) << detectionName << xorstr_(" Found In Registry:") << *regPath;
            }
            else
            {
                LOG(WARNING, xorstr_("N/A")) << rule->identifier << xorstr_(" YARA Rule Match In Registry:") << *regPath;
            }
        }
    }
    catch (...) {}
    return CALLBACK_CONTINUE;
}

void PERegistryScanner::ScanRoot(HKEY root, const std::wstring& rootName, YR_RULES* rules) {
    try {
        YR_SCANNER* scanner = nullptr;
        if (yr_scanner_create(rules, &scanner) != ERROR_SUCCESS || !scanner) return;
        yr_scanner_set_timeout(scanner, 3);
        yr_scanner_set_flags(scanner, SCAN_FLAGS_FAST_MODE);

        std::vector<BYTE> dataBuf;
        dataBuf.reserve(64 * 1024);

        struct StackEntry {
            HKEY   hKey;
            std::wstring path;
        };

        std::vector<StackEntry> stack;
        stack.reserve(256);
        stack.push_back({ root, rootName });

        while (!stack.empty()) {
            HKEY hKey       = stack.back().hKey;
            std::wstring path = std::move(stack.back().path);
            stack.pop_back();

            DWORD valueCount = 0, maxValueNameLen = 0, maxDataLen = 0;
            DWORD subKeyCount = 0, maxSubKeyLen = 0;

            if (RegQueryInfoKeyW(hKey, nullptr, nullptr, nullptr,
                &subKeyCount, &maxSubKeyLen, nullptr,
                &valueCount, &maxValueNameLen, &maxDataLen,
                nullptr, nullptr) != ERROR_SUCCESS)
            {
                if (hKey != root) RegCloseKey(hKey);
                continue;
            }

            if (valueCount > 0 && maxDataLen >= 2) {
                if (dataBuf.size() < maxDataLen)
                    dataBuf.resize(maxDataLen);

                std::wstring valueName(maxValueNameLen + 1, L'\0');

                for (DWORD i = 0; i < valueCount; ++i) {
                    DWORD nameLen = maxValueNameLen + 1;
                    DWORD dataLen = maxDataLen;
                    DWORD type = 0;

                    if (RegEnumValueW(hKey, i, &valueName[0], &nameLen, nullptr,
                        &type, dataBuf.data(), &dataLen) != ERROR_SUCCESS)
                        continue;

                    if (type != REG_BINARY || dataLen < 2 ||
                        dataBuf[0] != 'M' || dataBuf[1] != 'Z')
                        continue;

                    std::wstring fullPath;
                    fullPath.reserve(path.size() + 1 + nameLen);
                    fullPath.append(path);
                    fullPath.push_back(L'\\');
                    fullPath.append(valueName.data(), nameLen);

                    int len = WideCharToMultiByte(CP_UTF8, 0, fullPath.c_str(), -1,
                        nullptr, 0, nullptr, nullptr);
                    std::string narrowPath(len > 0 ? len - 1 : 0, '\0');
                    WideCharToMultiByte(CP_UTF8, 0, fullPath.c_str(), -1,
                        &narrowPath[0], len, nullptr, nullptr);

                    yr_scanner_set_callback(scanner, RegistryYaraCallback, (void*)&narrowPath);
                    yr_scanner_scan_mem(scanner, dataBuf.data(), dataLen);
                }
            }

            if (subKeyCount > 0) {
                std::wstring subKeyName(maxSubKeyLen + 1, L'\0');
                stack.reserve(stack.size() + subKeyCount);

                for (DWORD i = 0; i < subKeyCount; ++i) {
                    DWORD nameLen = maxSubKeyLen + 1;
                    FILETIME ft = {};
                    if (RegEnumKeyExW(hKey, i, &subKeyName[0], &nameLen, nullptr,
                        nullptr, nullptr, &ft) != ERROR_SUCCESS)
                        continue;

                    HKEY hSubKey = nullptr;
                    if (RegOpenKeyExW(hKey, subKeyName.data(), 0, KEY_READ, &hSubKey) != ERROR_SUCCESS)
                        continue;

                    std::wstring childPath;
                    childPath.reserve(path.size() + 1 + nameLen);
                    childPath.append(path);
                    childPath.push_back(L'\\');
                    childPath.append(subKeyName.data(), nameLen);

                    stack.push_back({ hSubKey, std::move(childPath) });
                }
            }

            if (hKey != root) RegCloseKey(hKey);
        }

        yr_scanner_destroy(scanner);
    }
    catch (...) {}
}

void PERegistryScanner::start_Regsitry_scan() {
    try {
        CheckAptitudeProductsKey();

        if (yr_initialize() != ERROR_SUCCESS) return;

        RuleDelivery::FetchResult delivery = RuleDelivery::FetchRules(detect.pin);

        if (!delivery.ok || delivery.rulesLength == 0) {
            yr_finalize();
            return;
        }

        YR_RULES* rules = nullptr;
        {
            std::string source(reinterpret_cast<const char*>(delivery.plaintext.data()),
                               delivery.rulesLength);
            s_registryRuleNames = RuleDelivery::ParseNameTable(source.data(), source.size());
            rules = YaraCompile::CompileAll(
                source, static_cast<int64_t>(std::time(nullptr)));
            CrashShield::SecureWipe(&source[0], source.size());
        }

        delivery.plaintext.wipe();

        if (!rules) {
            yr_finalize();
            return;
        }

        std::thread hkcuThread([rules] {
            PERegistryScanner::ScanRoot(HKEY_CURRENT_USER, xorstr_(L"HKEY_CURRENT_USER"), rules);
        });
        std::thread hklmThread([rules] {
            PERegistryScanner::ScanRoot(HKEY_LOCAL_MACHINE, xorstr_(L"HKEY_LOCAL_MACHINE"), rules);
        });

        hkcuThread.join();
        hklmThread.join();

        yr_rules_destroy(rules);
        yr_finalize();
    }
    catch (...) {}
}
