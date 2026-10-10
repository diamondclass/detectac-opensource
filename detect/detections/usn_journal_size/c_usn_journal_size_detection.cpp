#include "c_usn_journal_size_detection.h"

void c_usn_journal_size_detection::start_usn_journal_size_detection ( )
{
    try{
    std::string command_output = utils->exec_command (xorstr_("fsutil usn queryjournal C:") );
    std::regex max_size_regex (xorstr_(R"(Maximum Size\s*:\s*0x[\da-fA-F]+\s*\(([\d\.]+)\s*MB\))") );
    std::smatch match;

    if ( std::regex_search ( command_output , match , max_size_regex ) && match.size ( ) > 1 )
    {
        double max_size = std::stod ( match.str ( 1 ) );
        if ( max_size != 32.0 )
            LOG ( WARNING , xorstr_("N/A") ) << xorstr_("USN Journal Size Modified: ") << max_size;
    }
    }
    catch (...) {}
}