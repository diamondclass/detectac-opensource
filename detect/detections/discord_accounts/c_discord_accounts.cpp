#include "c_discord_accounts.h"

bool DiscordScanner::IsPrintableChar(char c) {
    try{
    unsigned char uc = static_cast<unsigned char>(c);
    return (uc >= 32 && uc <= 126) || uc >= 128;
    }
    catch (...) {}
}

std::vector<DiscordScanner::Account> DiscordScanner::ExtractAccounts(const std::string& jsonString) {
    try {
        std::vector<Account> accounts;
        const std::string idTarget = xorstr_("\"id\":\"");
        const std::string usernameTarget = xorstr_("\"username\":\"");
        size_t pos = 0;

        while ((pos = jsonString.find(idTarget, pos)) != std::string::npos) {
            size_t idStart = pos + idTarget.length();
            size_t idEnd = jsonString.find(xorstr_("\""), idStart);
            if (idEnd == std::string::npos) break;

            std::string id = jsonString.substr(idStart, idEnd - idStart);

            bool numericId = !id.empty() && id.size() <= 32;
            for (char c : id) {
                if (c < '0' || c > '9') { numericId = false; break; }
            }

            if (!numericId) {
                pos = idEnd;
                continue;
            }

            size_t userPos = jsonString.find(usernameTarget, idEnd);
            if (userPos == std::string::npos) break;

            size_t nextIdPos = jsonString.find(idTarget, idEnd);
            if (nextIdPos != std::string::npos && nextIdPos < userPos) {
                pos = idEnd;
                continue;
            }

            size_t userStart = userPos + usernameTarget.length();
            size_t userEnd = jsonString.find(xorstr_("\""), userStart);
            if (userEnd == std::string::npos) break;

            Account acc;
            acc.id = std::move(id);
            acc.username = jsonString.substr(userStart, userEnd - userStart);
            accounts.push_back(std::move(acc));

            pos = userEnd;
        }

        return accounts;
    }
    catch (...) { return {}; }
}

std::vector<DiscordScanner::ProcessInfo> DiscordScanner::GetDiscordProcesses() {
    try{
    std::vector<ProcessInfo> processes;
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return processes;
    }

    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (_stricmp(pe32.szExeFile, xorstr_("discord.exe")) == 0) {
                ProcessInfo info;
                info.pid = pe32.th32ProcessID;
                info.processName = pe32.szExeFile;
                info.hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);

                if (info.hProcess != NULL) {
                    processes.push_back(info);
                }
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return processes;
    }
    catch (...) {}
    return {};
}

bool DiscordScanner::SearchForTargetStringInProcess(HANDLE hProcess) {
    try{
    MEMORY_BASIC_INFORMATION mbi;
    LPVOID address = 0;

    const std::string target = xorstr_("{\"_state\":{\"users\":");
    const std::string audioTarget = xorstr_("AudioContextSettingsMigrated:");

    bool found_state_users = false;
    std::vector<Account> all_accounts;
    std::unordered_set<std::string> audio_ids;

    while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi))) {
        if ((mbi.State == MEM_COMMIT)) {
            bool isReadable = (mbi.Protect == PAGE_READONLY ||
                mbi.Protect == PAGE_READWRITE ||
                mbi.Protect == PAGE_EXECUTE_READ ||
                mbi.Protect == PAGE_EXECUTE_READWRITE ||
                mbi.Protect == PAGE_WRITECOPY ||
                mbi.Protect == PAGE_EXECUTE_WRITECOPY);

            bool isGuardPage = (mbi.Protect & PAGE_GUARD);

            if (isReadable && !isGuardPage && mbi.RegionSize > 0) {
                std::vector<BYTE> buffer(mbi.RegionSize);
                SIZE_T bytesRead = 0;

                if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer.data(), mbi.RegionSize, &bytesRead) && bytesRead > 0) {

                    if (!found_state_users && bytesRead >= target.length()) {
                        for (SIZE_T i = 0; i + target.length() <= bytesRead; i++) {
                            bool found = true;
                            for (size_t j = 0; j < target.length(); j++) {
                                char c1 = std::toupper(static_cast<char>(buffer[i + j]));
                                char c2 = std::toupper(target[j]);
                                if (c1 != c2) {
                                    found = false;
                                    break;
                                }
                            }

                            if (found) {
                                int startPos = static_cast<int>(i);
                                int endPos = static_cast<int>(i) + static_cast<int>(target.length());

                                while (startPos > 0 && IsPrintableChar(static_cast<char>(buffer[startPos - 1]))) {
                                    startPos--;
                                    if (i - startPos > 4096) break;
                                }

                                while (endPos < static_cast<int>(bytesRead) &&
                                    IsPrintableChar(static_cast<char>(buffer[endPos]))) {
                                    endPos++;
                                    if (endPos - i > 4096) break;
                                }

                                std::string fullString;
                                for (int pos = startPos; pos < endPos && pos < static_cast<int>(bytesRead); pos++) {
                                    fullString += static_cast<char>(buffer[pos]);
                                }

                                std::vector<Account> accounts = ExtractAccounts(fullString);
                                for (auto& acc : accounts) all_accounts.push_back(std::move(acc));

                                found_state_users = true;
                                break;
                            }
                        }
                    }

                    if (bytesRead >= audioTarget.length()) {
                        for (SIZE_T i = 0; i + audioTarget.length() <= bytesRead; i++) {
                            bool match = true;
                            for (size_t j = 0; j < audioTarget.length(); j++) {
                                if (static_cast<char>(buffer[i + j]) != audioTarget[j]) {
                                    match = false;
                                    break;
                                }
                            }

                            if (!match) continue;

                            SIZE_T idPos = i + audioTarget.length();

                            SIZE_T skipCount = 0;
                            while (idPos < bytesRead && skipCount < 8) {
                                char c = static_cast<char>(buffer[idPos]);
                                if (c >= '0' && c <= '9') break;
                                idPos++;
                                skipCount++;
                            }

                            std::string id;
                            while (idPos < bytesRead && id.size() < 32) {
                                char c = static_cast<char>(buffer[idPos]);
                                if (c < '0' || c > '9') break;
                                id += c;
                                idPos++;
                            }

                            if (id.size() >= 17 && id.size() <= 20) {
                                audio_ids.insert(id);
                            }

                            i = idPos;
                        }
                    }
                }
            }
        }

        address = (LPBYTE)mbi.BaseAddress + mbi.RegionSize;

        if (address < mbi.BaseAddress) {
            break;
        }
    }

    std::unordered_set<std::string> known_ids;
    for (const auto& acc : all_accounts) {
        LOG ( WARNING , xorstr_("N/A")) << xorstr_("Discord Account:Username: ") << acc.username << xorstr_(" ID: ") << acc.id;
        known_ids.insert(acc.id);
    }

    for (const auto& id : audio_ids) {
        if (known_ids.find(id) == known_ids.end()) {
            LOG ( WARNING , xorstr_("N/A")) << xorstr_("Discord Account:ID:") << id;
        }
    }

    return found_state_users || !audio_ids.empty();
    }
    catch (...) {}
    return false;
}

bool DiscordScanner::ScanForDiscordUsernames() {
    try{
    std::vector<ProcessInfo> processes = GetDiscordProcesses();

    if (processes.empty()) {
        return false;
    }

    bool found = false;
    for (const auto& proc : processes) {
        found = SearchForTargetStringInProcess(proc.hProcess);
        CloseHandle(proc.hProcess);

        if (found) {
            break;
        }
    }

    return found;
    }
    catch (...) {}
    return false;
}