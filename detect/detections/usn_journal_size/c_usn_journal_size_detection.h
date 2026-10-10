#pragma once

#include "../../pch.h"

class c_usn_journal_size_detection
{
public:
	static void start_usn_journal_size_detection ( );
};

inline auto c_usn_journal_size = std::make_unique<c_usn_journal_size_detection> ( );

