#include "c_wmi.h"

std::string wmiscanner::GetProp(IWbemClassObject* pObj, const wchar_t* prop)
{
    try {
        if (!pObj || !prop) return "";
        VARIANT vt;
        VariantInit(&vt);
        std::string result;
        if (SUCCEEDED(pObj->Get(prop, 0, &vt, 0, 0)) && vt.vt == VT_BSTR && vt.bstrVal) {
            _bstr_t val(vt.bstrVal);
            if ((const char*)val)
                result = (const char*)val;
        }
        VariantClear(&vt);
        return result;
    }
    catch (...) { return ""; }
}

void wmiscanner::ScanNamespace(IWbemLocator* pLoc, const wchar_t* ns, std::vector<std::string>& results)
{
    IWbemServices* pSvc = NULL;
    try {
        if (!pLoc) return;
        if (FAILED(pLoc->ConnectServer(_bstr_t(ns), NULL, NULL, 0, NULL, 0, 0, &pSvc)) || !pSvc)
            return;

        CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
            RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);

        std::vector<std::string> filterNames;
        std::vector<std::string> filterQueries;
        std::vector<std::string> bindConsumer;
        std::vector<std::string> bindFilter;

        try {
            IEnumWbemClassObject* pEnum = NULL;
            if (SUCCEEDED(pSvc->ExecQuery(_bstr_t(xorstr_("WQL")),
                _bstr_t(xorstr_("SELECT * FROM __EventFilter")),
                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                NULL, &pEnum)) && pEnum)
            {
                IWbemClassObject* pObj = NULL;
                ULONG uReturn = 0;
                while (pEnum->Next(WBEM_INFINITE, 1, &pObj, &uReturn) == S_OK && uReturn && pObj) {
                    filterNames.push_back(GetProp(pObj, xorstr_(L"Name")));
                    filterQueries.push_back(GetProp(pObj, xorstr_(L"Query")));
                    pObj->Release();
                    pObj = NULL;
                }
                pEnum->Release();
            }
        }
        catch (...) {}

        try {
            IEnumWbemClassObject* pEnum = NULL;
            if (SUCCEEDED(pSvc->ExecQuery(_bstr_t(xorstr_("WQL")),
                _bstr_t(xorstr_("SELECT * FROM __FilterToConsumerBinding")),
                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                NULL, &pEnum)) && pEnum)
            {
                IWbemClassObject* pObj = NULL;
                ULONG uReturn = 0;
                while (pEnum->Next(WBEM_INFINITE, 1, &pObj, &uReturn) == S_OK && uReturn && pObj) {
                    bindConsumer.push_back(GetProp(pObj, xorstr_(L"Consumer")));
                    bindFilter.push_back(GetProp(pObj, xorstr_(L"Filter")));
                    pObj->Release();
                    pObj = NULL;
                }
                pEnum->Release();
            }
        }
        catch (...) {}

        std::string queries[] = {
            xorstr_("SELECT * FROM CommandLineEventConsumer"),
            xorstr_("SELECT * FROM ActiveScriptEventConsumer")
        };

        for (int q = 0; q < 2; q++) {
            IEnumWbemClassObject* pEnum = NULL;
            try {
                if (FAILED(pSvc->ExecQuery(_bstr_t(xorstr_("WQL")),
                    _bstr_t(queries[q].c_str()),
                    WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                    NULL, &pEnum)) || !pEnum)
                    continue;

                IWbemClassObject* pObj = NULL;
                ULONG uReturn = 0;

                while (pEnum->Next(WBEM_INFINITE, 1, &pObj, &uReturn) == S_OK && uReturn && pObj) {
                    try {
                        std::string name = GetProp(pObj, xorstr_(L"Name"));
                        std::string command;
                        std::string cmd = GetProp(pObj, xorstr_(L"CommandLineTemplate"));
                        std::string exe = GetProp(pObj, xorstr_(L"ExecutablePath"));
                        std::string sFile = GetProp(pObj, xorstr_(L"ScriptFileName"));
                        std::string sText = GetProp(pObj, xorstr_(L"ScriptText"));

                        if (!cmd.empty())        command = cmd;
                        else if (!exe.empty())   command = exe;
                        else if (!sFile.empty()) command = sFile;
                        else if (!sText.empty()) command = sText;
                        else                     command = name;

                        std::string trigger;
                        for (size_t i = 0; i < bindConsumer.size(); i++) {
                            if (bindConsumer[i].find(name) != std::string::npos) {
                                for (size_t j = 0; j < filterNames.size(); j++) {
                                    if (bindFilter[i].find(filterNames[j]) != std::string::npos) {
                                        trigger = filterQueries[j];
                                        break;
                                    }
                                }
                                break;
                            }
                        }

                        results.push_back(std::string(xorstr_("Suspicious WMI Instruction Found:")) + command + xorstr_("   |   ") + trigger);
                    }
                    catch (...) {}
                    pObj->Release();
                    pObj = NULL;
                }
                pEnum->Release();
                pEnum = NULL;
            }
            catch (...) {
                if (pEnum) { try { pEnum->Release(); } catch (...) {} }
            }
        }
    }
    catch (...) {}

    if (pSvc) { try { pSvc->Release(); } catch (...) {} }
}

std::vector<std::string> wmiscanner::ScanWMIBypasses()
{
    std::vector<std::string> results;
    bool comInitialized = false;
    IWbemLocator* pLoc = NULL;

    try {
        HRESULT hr = CoInitializeEx(0, COINIT_MULTITHREADED);
        if (hr == RPC_E_CHANGED_MODE)
            hr = CoInitializeEx(0, COINIT_APARTMENTTHREADED);
        if (FAILED(hr) && hr != S_FALSE)
            return results;
        comInitialized = true;

        hr = CoInitializeSecurity(NULL, -1, NULL, NULL,
            RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
            NULL, EOAC_NONE, NULL);
        if (FAILED(hr) && hr != RPC_E_TOO_LATE) {
            CoUninitialize();
            return results;
        }

        hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
            IID_IWbemLocator, (LPVOID*)&pLoc);
        if (FAILED(hr) || !pLoc) {
            CoUninitialize();
            return results;
        }

        ScanNamespace(pLoc, xorstr_(L"ROOT\\subscription"), results);
        ScanNamespace(pLoc, xorstr_(L"ROOT\\default"), results);
    }
    catch (...) {}

    if (pLoc) { try { pLoc->Release(); } catch (...) {} }
    if (comInitialized) { try { CoUninitialize(); } catch (...) {} }

    return results;
}

void wmiscanner::start_wmi()
{
    try {
        std::vector<std::string> results = wmiscanner::ScanWMIBypasses();
        for (size_t i = 0; i < results.size(); i++)
            LOG ( WARNING , xorstr_("N/A")) << results[i];
    }
    catch (...) {}
    return;
}