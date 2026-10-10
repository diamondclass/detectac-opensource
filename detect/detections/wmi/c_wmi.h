#pragma once

#include "../../pch.h"

class wmiscanner {

public:

	static std::string GetProp(IWbemClassObject* pObj, const wchar_t* prop);
	static void ScanNamespace(IWbemLocator* pLoc, const wchar_t* ns, std::vector<std::string>& results);
	static std::vector<std::string> ScanWMIBypasses();
	static void start_wmi();

};

inline auto c_wmi = std::make_unique<wmiscanner>();