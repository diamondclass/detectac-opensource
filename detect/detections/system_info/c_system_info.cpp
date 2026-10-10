#include "c_system_info.h"

inline std::string SystemInfo::trim(const std::string& s) {
    try {
        size_t start = s.find_first_not_of(xorstr_(" \t\r\n"));
        if (start == std::string::npos) return "";
        size_t end = s.find_last_not_of(xorstr_(" \t\r\n"));
        return s.substr(start, end - start + 1);
    }
    catch (...) {
        return xorstr_("");
    }
}

std::string SystemInfo::sanitize_text(const std::string& input) {
    try {
        std::string output;
        output.reserve(input.size());
        for (unsigned char c : input) {
            if (c >= 32 && c <= 126) output.push_back((char)c);
        }
        return trim(output);
    }
    catch (...) {
        return xorstr_("");
    }
}

std::string SystemInfo::exec_command(const std::string& cmd) {
    try {
        SECURITY_ATTRIBUTES sa;
        sa.nLength = sizeof(SECURITY_ATTRIBUTES);
        sa.bInheritHandle = TRUE;
        sa.lpSecurityDescriptor = NULL;

        HANDLE hRead, hWrite;
        if (!CreatePipe(&hRead, &hWrite, &sa, 0))
            return "";

        STARTUPINFOA si = { 0 };
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        si.hStdOutput = hWrite;
        si.hStdError = hWrite;
        si.hStdInput = NULL;

        PROCESS_INFORMATION pi = { 0 };
        std::string command = xorstr_("cmd /C ") + cmd;

        if (!CreateProcessA(NULL, const_cast<char*>(command.c_str()), NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
            CloseHandle(hRead);
            CloseHandle(hWrite);
            return "";
        }

        CloseHandle(hWrite);

        std::string result;
        char buffer[128];
        DWORD bytesRead;
        while (ReadFile(hRead, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0) {
            buffer[bytesRead] = '\0';
            result += buffer;
        }

        CloseHandle(hRead);
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        return result;
    }
    catch (...) {
        return xorstr_("");
    }
}

std::string SystemInfo::get_serial_number() {
    try {
        std::string output = exec_command(xorstr_("wmic bios get serialnumber"));
        if (output.empty()) return "";

        std::istringstream stream(output);
        std::string line;

        while (std::getline(stream, line)) {
            std::string serial = trim(line);

            if (serial.find(xorstr_("SerialNumber")) != std::string::npos)
                continue;

            if (serial.empty())
                continue;

            serial = sanitize_text(serial);

            if (serial == xorstr_("To Be Filled By O.E.M.") ||
                serial == xorstr_("Default string") ||
                serial == xorstr_("System Serial Number"))
                continue;

            if (serial.length() < 5)
                continue;

            bool valid = true;
            for (unsigned char c : serial) {
                if (!std::isalnum(c) && c != '-') {
                    valid = false;
                    break;
                }
            }

            if (!valid)
                continue;

            return serial;
        }

        return xorstr_("");
    }
    catch (...) {
        return xorstr_("");
    }
}


void SystemInfo::start_systeminfo_scan() {
    try {
        std::string serial = SystemInfo::get_serial_number();
        if (!serial.empty()) {
            LOG(INFO, xorstr_("N/A")) << xorstr_("Serial Number:") << serial;
        }
    }
    catch (...) {}
}
