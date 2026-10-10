#include "c_jvm_arg_scanner.h"

std::string JvmArgScanner::lower_copy(const std::string& s)
{
    try {
        std::string out = s;
        for (char& c : out) {
            const unsigned char uc = static_cast<unsigned char>(c);
            if (uc >= 'A' && uc <= 'Z') c = static_cast<char>(uc + ('a' - 'A'));
        }
        return out;
    } catch (...) {
        return {};
    }
}

std::string JvmArgScanner::wideToNarrow(const std::wstring& ws)
{
    try {
        if (ws.empty()) return {};
        int sz = WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), (int)ws.size(), nullptr, 0, nullptr, nullptr);
        if (sz <= 0) return {};
        std::string out(sz, '\0');
        WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), (int)ws.size(), &out[0], sz, nullptr, nullptr);
        return out;
    } catch (...) {
        return {};
    }
}

std::vector<std::string> JvmArgScanner::parseCommandLine(const std::string& cmdLine)
{
    try {
        std::vector<std::string> args;
        std::string current;
        bool inQuotes = false;
        bool hasToken = false;

        for (size_t i = 0; i < cmdLine.size(); ++i) {
            const char c = cmdLine[i];

            if (c == '\\' && i + 1 < cmdLine.size() && cmdLine[i + 1] == '"') {
                current += '"';
                hasToken = true;
                ++i;
                continue;
            }

            if (c == '"') {
                inQuotes = !inQuotes;
                hasToken = true;
                continue;
            }

            if ((c == ' ' || c == '\t') && !inQuotes) {
                if (hasToken) {
                    args.push_back(current);
                    current.clear();
                    hasToken = false;
                }
                continue;
            }

            current += c;
            hasToken = true;
        }

        if (hasToken) args.push_back(current);
        return args;
    } catch (...) {
        return {};
    }
}

std::vector<std::string> JvmArgScanner::extract_flag_values(const std::string& cmdLine, const std::string& flag)
{
    std::vector<std::string> values;
    try {
        if (cmdLine.empty() || flag.empty()) return values;

        const std::string lower_cmd = lower_copy(cmdLine);
        const std::string lower_flag = lower_copy(flag);

        size_t pos = 0;
        while ((pos = lower_cmd.find(lower_flag, pos)) != std::string::npos) {
            const bool at_boundary =
                (pos == 0) || cmdLine[pos - 1] == ' ' || cmdLine[pos - 1] == '\t' || cmdLine[pos - 1] == '"';

            if (!at_boundary) {
                pos += lower_flag.size();
                continue;
            }

            size_t value_start = pos + lower_flag.size();
            size_t value_end = cmdLine.size();

            for (size_t i = value_start; i + 1 < cmdLine.size(); ++i) {
                if ((cmdLine[i] == ' ' || cmdLine[i] == '\t') && cmdLine[i + 1] == '-') {
                    value_end = i;
                    break;
                }
            }

            std::string value = cmdLine.substr(value_start, value_end - value_start);

            while (!value.empty() && (value.front() == ' ' || value.front() == '"')) value.erase(value.begin());
            while (!value.empty() && (value.back() == ' ' || value.back() == '\t' || value.back() == '"')) value.pop_back();

            if (!value.empty()) values.push_back(value);
            pos = value_end;
        }
    } catch (...) {}
    return values;
}

std::vector<std::string> JvmArgScanner::split_classpath(const std::string& value)
{
    std::vector<std::string> entries;
    try {
        std::string current;
        for (char c : value) {
            if (c == ';') {
                if (!current.empty()) entries.push_back(current);
                current.clear();
            } else {
                current += c;
            }
        }
        if (!current.empty()) entries.push_back(current);
    } catch (...) {}
    return entries;
}

bool JvmArgScanner::is_launcher_temp_agent(const std::string& path_lower)
{
    try {
        if (path_lower.find(xorstr_("\\appdata\\local\\temp\\")) == std::string::npos &&
            path_lower.find(xorstr_("\\windows\\temp\\")) == std::string::npos) {
            return false;
        }

        static const std::vector<std::string> known = {
            xorstr_("\\theseus.jar")
        };

        for (const std::string& name : known) {
            const size_t at = path_lower.rfind(name);
            if (at == std::string::npos) continue;

            const size_t end = at + name.size();
            if (end == path_lower.size() || path_lower[end] == '=') return true;
        }
    } catch (...) {}
    return false;
}

bool JvmArgScanner::is_trusted_agent_path(const std::string& path_lower)
{
    try {
        if (is_launcher_temp_agent(path_lower)) return true;

        static const std::vector<std::string> trusted = {
            xorstr_(".lunarclient"), xorstr_("lunarclient"), xorstr_("badlion"),
            xorstr_("\\feather"), xorstr_(".feather"),
            xorstr_("\\program files\\"), xorstr_("\\program files (x86)\\"),
            xorstr_("\\jetbrains\\"), xorstr_("idea_rt.jar"),
            xorstr_("\\jre\\lib\\"), xorstr_("\\jdk\\lib\\")
        };

        for (const std::string& t : trusted) {
            if (path_lower.find(t) != std::string::npos) return true;
        }
    } catch (...) {}
    return false;
}

bool JvmArgScanner::is_staging_path(const std::string& path_lower)
{
    try {
        static const std::vector<std::string> staging = {
            xorstr_("\\downloads\\"), xorstr_("\\desktop\\"), xorstr_("$recycle.bin"),
            xorstr_("\\appdata\\local\\temp\\"), xorstr_("\\windows\\temp\\")
        };

        for (const std::string& s : staging) {
            if (path_lower.find(s) != std::string::npos) return true;
        }
    } catch (...) {}
    return false;
}

bool JvmArgScanner::has_launch_time_agent(const std::string& command_line)
{
    try {
        const std::string lower = lower_copy(command_line);
        return lower.find(xorstr_("-javaagent:")) != std::string::npos ||
               lower.find(xorstr_("-agentpath:")) != std::string::npos ||
               lower.find(xorstr_("-agentlib:"))  != std::string::npos ||
               lower.find(xorstr_("-xrun"))       != std::string::npos;
    } catch (...) {
        return false;
    }
}

bool JvmArgScanner::environment_agent_present()
{
    static std::atomic<int> cached{ -1 };

    try {
        const int seen = cached.load(std::memory_order_acquire);
        if (seen >= 0) return seen != 0;

        static const std::wstring vars[] = {
            xorstr_(L"JAVA_TOOL_OPTIONS"), xorstr_(L"_JAVA_OPTIONS"), xorstr_(L"JDK_JAVA_OPTIONS"), xorstr_(L"JAVA_OPTS")
        };

        bool found = false;
        for (const std::wstring& var : vars) {
            wchar_t buffer[4096]{};
            const DWORD len = GetEnvironmentVariableW(var.c_str(), buffer, ARRAYSIZE(buffer));
            if (len == 0 || len >= ARRAYSIZE(buffer)) continue;

            const std::string value = lower_copy(wideToNarrow(std::wstring(buffer, len)));
            if (value.find(xorstr_("-javaagent")) != std::string::npos ||
                value.find(xorstr_("-agentpath")) != std::string::npos ||
                value.find(xorstr_("-agentlib"))  != std::string::npos) {
                found = true;
            }
        }

        cached.store(found ? 1 : 0, std::memory_order_release);
        return found;
    } catch (...) {
        return false;
    }
}

bool JvmArgScanner::looks_like_jvm(const jvm_process_info& proc)
{
    try {
        const std::string name = lower_copy(proc.name);
        if (name == xorstr_("javaw.exe") || name == xorstr_("java.exe")) return true;

        const std::string cmd = lower_copy(proc.command_line);
        if (cmd.find(xorstr_("-javaagent:")) != std::string::npos) return true;
        if (cmd.find(xorstr_("-agentpath:")) != std::string::npos) return true;
        if (cmd.find(xorstr_("-xbootclasspath")) != std::string::npos) return true;
        if (cmd.find(xorstr_("net.minecraft.client")) != std::string::npos) return true;
    } catch (...) {}
    return false;
}

std::vector<jvm_process_info> JvmArgScanner::collect_jvm_processes()
{
    std::vector<jvm_process_info> processes;

    IWbemLocator*           pLocator = nullptr;
    IWbemServices*          pServices = nullptr;
    IEnumWbemClassObject*   pEnum = nullptr;
    bool                    com_initialized = false;

    try {
        HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        if (hr == RPC_E_CHANGED_MODE) hr = S_OK;
        else if (SUCCEEDED(hr)) com_initialized = true;
        if (FAILED(hr)) return processes;

        hr = CoInitializeSecurity(
            nullptr, -1, nullptr, nullptr,
            RPC_C_AUTHN_LEVEL_DEFAULT,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            nullptr, EOAC_NONE, nullptr);
        if (FAILED(hr) && hr != RPC_E_TOO_LATE) {
            if (com_initialized) CoUninitialize();
            return processes;
        }

        hr = CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
            IID_IWbemLocator, reinterpret_cast<LPVOID*>(&pLocator));
        if (FAILED(hr) || !pLocator) {
            if (com_initialized) CoUninitialize();
            return processes;
        }

        hr = pLocator->ConnectServer(
            _bstr_t(xorstr_(L"ROOT\\CIMV2")), nullptr, nullptr, nullptr,
            0, nullptr, nullptr, &pServices);
        if (FAILED(hr) || !pServices) {
            pLocator->Release();
            if (com_initialized) CoUninitialize();
            return processes;
        }

        CoSetProxyBlanket(pServices,
            RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
            RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
            nullptr, EOAC_NONE);

        hr = pServices->ExecQuery(
            _bstr_t(xorstr_(L"WQL")),
            _bstr_t(xorstr_(L"SELECT ProcessId, Name, ExecutablePath, CommandLine FROM Win32_Process")),
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            nullptr, &pEnum);
        if (FAILED(hr) || !pEnum) {
            pServices->Release();
            pLocator->Release();
            if (com_initialized) CoUninitialize();
            return processes;
        }

        ULONG returned = 0;
        IWbemClassObject* pObj = nullptr;

        while (pEnum->Next(WBEM_INFINITE, 1, &pObj, &returned) == S_OK && returned > 0) {
            try {
                jvm_process_info info;

                VARIANT vtPid;   VariantInit(&vtPid);
                VARIANT vtName;  VariantInit(&vtName);
                VARIANT vtPath;  VariantInit(&vtPath);
                VARIANT vtCmd;   VariantInit(&vtCmd);

                pObj->Get(xorstr_(L"ProcessId"), 0, &vtPid, nullptr, nullptr);
                pObj->Get(xorstr_(L"Name"), 0, &vtName, nullptr, nullptr);
                pObj->Get(xorstr_(L"ExecutablePath"), 0, &vtPath, nullptr, nullptr);
                pObj->Get(xorstr_(L"CommandLine"), 0, &vtCmd, nullptr, nullptr);

                if (vtPid.vt == VT_I4)  info.pid = static_cast<DWORD>(vtPid.lVal);
                if (vtPid.vt == VT_UI4) info.pid = vtPid.ulVal;
                if (vtName.vt == VT_BSTR && vtName.bstrVal) info.name = wideToNarrow(vtName.bstrVal);
                if (vtPath.vt == VT_BSTR && vtPath.bstrVal) info.image_path = wideToNarrow(vtPath.bstrVal);
                if (vtCmd.vt  == VT_BSTR && vtCmd.bstrVal)  info.command_line = wideToNarrow(vtCmd.bstrVal);

                VariantClear(&vtCmd);
                VariantClear(&vtPath);
                VariantClear(&vtName);
                VariantClear(&vtPid);

                if (info.pid != 0 && looks_like_jvm(info)) processes.push_back(info);

                pObj->Release();
                pObj = nullptr;
            } catch (...) {
                if (pObj) { pObj->Release(); pObj = nullptr; }
            }
        }

        pEnum->Release();
        pServices->Release();
        pLocator->Release();
        if (com_initialized) CoUninitialize();
    } catch (...) {
        if (pEnum)     pEnum->Release();
        if (pServices) pServices->Release();
        if (pLocator)  pLocator->Release();
        if (com_initialized) CoUninitialize();
    }

    return processes;
}

void JvmArgScanner::inspect_agent_args(const jvm_process_info& proc)
{
    try {
        struct agent_flag { std::string flag; std::string label; };
        static const std::vector<agent_flag> flags = {
            { xorstr_("-javaagent:"), xorstr_("Java Agent") },
            { xorstr_("-agentpath:"), xorstr_("Java Agent") },
            { xorstr_("-agentlib:"),  xorstr_("Extra Code File") }
        };

        for (const agent_flag& f : flags) {
            for (const std::string& value : extract_flag_values(proc.command_line, f.flag)) {
                const std::string lower = lower_copy(value);

                if (lower.find(xorstr_("weave")) != std::string::npos) {
                    LOG(WARNING, xorstr_("N/A"))
                        << xorstr_("Weave Cheat Loader Was Loaded Into Minecraft. Weave loads cheat jars into Minecraft while the game is running: ")
                        << value;
                    continue;
                }

                if (lower.find(xorstr_("jdwp")) != std::string::npos) {
                    LOG(WARNING, xorstr_("N/A"))
                        << xorstr_("Minecraft Was Started With Remote Debugging Turned On. This lets another program connect to Minecraft and run its own code inside the game: ")
                        << value;
                    continue;
                }

                if (is_trusted_agent_path(lower)) continue;

                if (is_staging_path(lower)) {
                    LOG(WARNING, xorstr_("N/A"))
                        << xorstr_("Unknown ") << f.label
                        << xorstr_(" Loaded Into Minecraft: ")
                        << value;
                    continue;
                }

                LOG(WARNING, xorstr_("N/A"))
                    << xorstr_("Unknown ") << f.label
                    << xorstr_(" Loaded Into Minecraft. Files loaded like this can change how the game works: ") << value;
            }
        }
    } catch (...) {}
}

void JvmArgScanner::inspect_debug_args(const jvm_process_info& proc)
{
    try {
        const std::string lower = lower_copy(proc.command_line);

        if (lower.find(xorstr_("-xrunjdwp")) != std::string::npos || lower.find(xorstr_("-xdebug")) != std::string::npos) {
            LOG(WARNING, xorstr_("N/A"))
                << xorstr_("Minecraft Was Started With Remote Debugging Turned On. This lets another program connect to Minecraft and run its own code inside the game.");
        }

        for (const std::string& value : extract_flag_values(proc.command_line, xorstr_("-Xbootclasspath/a:"))) {
            LOG(WARNING, xorstr_("N/A"))
                << xorstr_("Extra Files Added To Minecraft's Startup. Files added here can replace parts of the game before it loads: ")
                << value;
        }

        for (const std::string& value : extract_flag_values(proc.command_line, xorstr_("-Xbootclasspath/p:"))) {
            LOG(WARNING, xorstr_("N/A"))
                << xorstr_("Extra Files Added To Minecraft's Startup. Files added here can replace parts of the game before it loads: ")
                << value;
        }
    } catch (...) {}
}

void JvmArgScanner::inspect_attach_policy_args(const jvm_process_info& proc)
{
    try {
        const std::string lower = lower_copy(proc.command_line);

        if (lower.find(xorstr_("-xx:-disableattachmechanism")) != std::string::npos) {
            LOG(WARNING, xorstr_("N/A"))
                << xorstr_("Minecraft Was Started With Injection Protection Turned Off. This setting is only enabled so another program can inject into the game while it runs.");
        }

        if (lower.find(xorstr_("-djdk.attach.allowattachself=true")) != std::string::npos) {
            LOG(WARNING, xorstr_("N/A"))
                << xorstr_("Minecraft Was Started Allowing It To Inject Into Itself. This lets code already inside the game load more code into the game.");
        }

        if (lower.find(xorstr_("-xx:+enabledynamicagentloading")) != std::string::npos) {
            LOG(WARNING, xorstr_("N/A"))
                << xorstr_("Minecraft Was Started With Injection Warnings Turned Off. This hides the warning Java normally shows when something injects into the game.");
        }
    } catch (...) {}
}

void JvmArgScanner::inspect_classpath_args(const jvm_process_info& proc)
{
    try {
        std::vector<std::string> values = extract_flag_values(proc.command_line, xorstr_("-classpath "));
        for (const std::string& v : extract_flag_values(proc.command_line, xorstr_("-cp "))) values.push_back(v);

        for (const std::string& value : values) {
            for (const std::string& entry : split_classpath(value)) {
                const std::string lower = lower_copy(entry);
                if (!is_staging_path(lower)) continue;
                if (is_trusted_agent_path(lower)) continue;

                LOG(WARNING, xorstr_("N/A"))
                    << xorstr_("Minecraft Is Loading A Suspicious File: ") << entry;
            }
        }
    } catch (...) {}
}

void JvmArgScanner::inspect_environment_overrides()
{
    try {
        static const std::wstring vars[] = {
            xorstr_(L"JAVA_TOOL_OPTIONS"), xorstr_(L"_JAVA_OPTIONS"), xorstr_(L"JDK_JAVA_OPTIONS"), xorstr_(L"JAVA_OPTS")
        };

        for (const std::wstring& var : vars) {
            wchar_t buffer[4096]{};
            const DWORD len = GetEnvironmentVariableW(var.c_str(), buffer, ARRAYSIZE(buffer));
            if (len == 0 || len >= ARRAYSIZE(buffer)) continue;

            const std::string value = wideToNarrow(std::wstring(buffer, len));
            const std::string lower = lower_copy(value);

            if (lower.find(xorstr_("-javaagent")) == std::string::npos &&
                lower.find(xorstr_("-agentpath")) == std::string::npos &&
                lower.find(xorstr_("-agentlib"))  == std::string::npos &&
                lower.find(xorstr_("-xbootclasspath")) == std::string::npos) {
                continue;
            }

            LOG(WARNING, xorstr_("N/A"))
                << xorstr_("Java Agent Forced Into Every Java Program:") << wideToNarrow(var)
                << xorstr_("This Forced Java Agent Will Inject Without Showing In Any Launcher Settings")
                << value;
        }
    } catch (...) {}
}

void JvmArgScanner::start_jvm_arg_scan()
{
    try {
        inspect_environment_overrides();

        const std::vector<jvm_process_info> processes = collect_jvm_processes();

        for (const jvm_process_info& proc : processes) {
            if (proc.command_line.empty()) continue;

            inspect_agent_args(proc);
            inspect_debug_args(proc);
            inspect_attach_policy_args(proc);
            inspect_classpath_args(proc);
        }
    } catch (...) {
        return;
    }
}
