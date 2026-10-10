#include "c_pe_injection.h"


const std::vector<std::pair<std::wstring, std::wstring>> fileFilters = {

    { xorstr_(L"notepad.exe"), xorstr_(L"PE Injection Out Of Instance: User Has Previously PE Injected Cheats Into Notepad.exe") },
    { xorstr_(L"snippingtool.exe"), xorstr_(L"PE Injection Out Of Instance: User Has Previously PE Injected Cheats Into Snippingtool.exe") },
    { xorstr_(L"osk.exe"), xorstr_(L"PE Injection Out Of Instance: User Has Previously PE Injected Cheats Into Osk.exe") },
    { xorstr_(L"mspaint.exe"), xorstr_(L"PE Injection Out Of Instance: User Has Previously PE Injected Cheats Into Mspaint.exe") },
    { xorstr_(L"calc.exe"), xorstr_(L"PE Injection Out Of Instance: User Has Previously PE Injected Cheats Into Calc.exe") },
    { xorstr_(L"calculatorapp.exe"), xorstr_(L"PE Injection Out Of Instance: User Has Previously PE Injected Cheats Into Calculatorapp.exe") },
    { xorstr_(L"ctfmon.exe"), xorstr_(L"PE Injection Out Of Instance: User Has Previously PE Injected Cheats Into Ctfmon.exe") },
    { xorstr_(L"curl.exe"), xorstr_(L"PE Injection Out Of Instance: User Has Previously PE Injected Cheats Into Curl.exe") },
    { xorstr_(L"powershell.exe"), xorstr_(L"PE Injection Out Of Instance: User Has Previously PE Injected Cheats Into PowerShell.exe") },
    { xorstr_(L"powershell_ise.exe"), xorstr_(L"PE Injection Out Of Instance: User Has Previously PE Injected Cheats Into PowerShell ISE.exe") },
    { xorstr_(L"cmd.exe"), xorstr_(L"PE Injection Out Of Instance: User Has Previously PE Injected Cheats Into Cmd.exe") },
    { xorstr_(L"conhost.exe"), xorstr_(L"PE Injection Out Of Instance: User Has Previously PE Injected Cheats Into Conhost.exe") },

};

std::wstring peinjectionscan::ToLower(const std::wstring& str) {
    try{
    std::wstring lowerStr = str;
    std::transform(lowerStr.begin(), lowerStr.end(), lowerStr.begin(), towlower);
    return lowerStr;
    }
    catch (...) {}
    return {};
}

std::wstring peinjectionscan::GetCustomMessage(const std::wstring& path) {
    try{
    std::wstring lowerPath = ToLower(path);

    for (const auto& filter : fileFilters) {
        if (lowerPath.find(ToLower(filter.first)) != std::wstring::npos) {
            return filter.second;
        }
    }
    return xorstr_(L"");
    }
    catch (...) {}
    return {};
}

void peinjectionscan::start_pe_scan() {
    try{
    HRESULT hr;
    INetFwPolicy2* pNetFwPolicy2 = nullptr;
    INetFwRules* pFwRules = nullptr;

    std::unordered_set<std::wstring> printedMessages;

    hr = CoInitializeEx(0, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) {
        return;
    }

    hr = CoCreateInstance(__uuidof(NetFwPolicy2), nullptr, CLSCTX_INPROC_SERVER, __uuidof(INetFwPolicy2), (void**)&pNetFwPolicy2);
    if (FAILED(hr)) {
        CoUninitialize();
        return;
    }

    hr = pNetFwPolicy2->get_Rules(&pFwRules);
    if (FAILED(hr)) {
        pNetFwPolicy2->Release();
        CoUninitialize();
        return;
    }

    IUnknown* pEnumerator;
    IEnumVARIANT* pVariantEnum;
    hr = pFwRules->get__NewEnum(&pEnumerator);
    if (SUCCEEDED(hr)) {
        hr = pEnumerator->QueryInterface(__uuidof(IEnumVARIANT), (void**)&pVariantEnum);
        if (SUCCEEDED(hr)) {
            VARIANT var;
            VariantInit(&var);

            while (pVariantEnum->Next(1, &var, NULL) == S_OK) {
                INetFwRule* pFwRule;
                hr = V_DISPATCH(&var)->QueryInterface(__uuidof(INetFwRule), (void**)&pFwRule);
                if (SUCCEEDED(hr)) {
                    BSTR bstrFilePath;
                    hr = pFwRule->get_ApplicationName(&bstrFilePath);
                    if (SUCCEEDED(hr) && bstrFilePath != nullptr) {
                        std::wstring appPath(bstrFilePath, SysStringLen(bstrFilePath));
                        SysFreeString(bstrFilePath);

                        std::wstring message = GetCustomMessage(appPath);
                        if (!message.empty() && printedMessages.find(message) == printedMessages.end()) {
                            LOG ( WARNING, xorstr_("N/A")) << message;
                            printedMessages.insert(message);
                        }
                    }
                    pFwRule->Release();
                }
                VariantClear(&var);
            }
            pVariantEnum->Release();
        }
        pEnumerator->Release();
    }

    pFwRules->Release();
    pNetFwPolicy2->Release();
    CoUninitialize();
    }
    catch (...) {}
}