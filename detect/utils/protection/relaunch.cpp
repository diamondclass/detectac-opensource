#include <Windows.h>
#include <string>
#include <random>

#include "relaunch.h"
#include "../crypt/xorstr.h"

namespace protection {
namespace relaunch {

std::wstring MakeRandomAlnum(int minLen, int maxLen) noexcept {
    try {
        static const std::wstring kAlphabet = xorstr_(L"abcdefghijklmnopqrstuvwxyz0123456789");
        const int alphaCount = static_cast<int>(kAlphabet.size());
        std::mt19937_64 rng{
            static_cast<unsigned long long>(GetTickCount64())
            ^ (static_cast<unsigned long long>(GetCurrentProcessId()) << 17)
            ^ static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(&rng))
        };
        if (minLen < 1) minLen = 1;
        if (maxLen < minLen) maxLen = minLen;
        std::uniform_int_distribution<int> lenDist{ minLen, maxLen };
        std::uniform_int_distribution<int> alphaDist{ 0, alphaCount - 1 };
        int len = lenDist(rng);
        std::wstring out;
        out.reserve(static_cast<size_t>(len));
        for (int i = 0; i < len; ++i) out.push_back(kAlphabet[alphaDist(rng)]);
        return out;
    } catch (...) { return std::wstring(xorstr_(L"runtime")); }
}

} // namespace relaunch
} // namespace protection
