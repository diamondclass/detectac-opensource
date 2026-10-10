#pragma once

#include "../../../../pch.h"
#include "../../../browser_detections/sqlite/sqlite3.h"

class windows_db_parser {
public:
    static void parse_db(const std::string& db_path);
    static void start_windb_urls();
};

inline auto c_dbu = std::make_unique<windows_db_parser>();