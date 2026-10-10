#pragma once

#include "../../../pch.h"

class dma_pads_scan {

public:

	static std::string Narrow(const std::wstring& w);
	static std::wstring WideUpper(std::wstring s);
	static bool IsGuidAllFF(const GUID& g);
	static std::string ParseHexField(const std::wstring& hwId, const wchar_t* prefix);
	static std::wstring ReadStr(HDEVINFO di, PSP_DEVINFO_DATA dd, const DEVPROPKEY* k);
	static bool ReadGuid(HDEVINFO di, PSP_DEVINFO_DATA dd, const DEVPROPKEY* k, GUID& v);
	static bool CheckInstanceFF(const std::wstring& id);
	static bool CheckSubsysFF(const std::wstring& hwId);
	static bool CheckRevFF(const std::wstring& hwId);

	static void start_dma_pads();

};

inline auto c_dma_pads = std::make_unique<dma_pads_scan>();