#pragma once

#include "../../pch.h"

class c_opensavepidlmru
{
public:
	static void PrintAsciiValue(const BYTE* data, DWORD dataSize, const std::string& timestamp = "");
	static void start_opensavemidlmru_scan();
};

inline auto c_injdll = std::make_unique<c_opensavepidlmru>();