#pragma once

#include <curl/curl.h>

namespace CryptoInit {

inline void EnsureInitialized() noexcept
{
    static const bool done = []() {
        curl_global_init(CURL_GLOBAL_DEFAULT);
        return true;
    }();
    (void)done;
}

}
