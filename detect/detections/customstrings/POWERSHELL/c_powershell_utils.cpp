#include "c_powershell_utils.h"

void cpowershellmaster::start_powershell()
{
    try
    {
        STARTUPINFOW si = { 0 };
        PROCESS_INFORMATION pi = { 0 };

        si.cb = sizeof(STARTUPINFOW);
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;

        if (CreateProcessW(
            xorstr_(L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
            NULL,
            NULL,
            NULL,
            FALSE,
            CREATE_NO_WINDOW,
            NULL,
            NULL,
            &si,
            &pi)) {
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }

        return;
    }
    catch ( ... ) { };
}

void cpowershellmaster::start_powershell_scans() 
{

	try
	{

        cpowershellmaster::start_powershell();

        Sleep(1000);

		cpowershellscan::start_cpowershell_scan();

	}
	catch ( ... ) { };
}