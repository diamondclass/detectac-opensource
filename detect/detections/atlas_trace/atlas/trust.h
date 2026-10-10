#pragma once
#include "common.h"
#include "target.h"

namespace atlas {

struct SigInfo {
    bool        valid  = false;
    bool        present = false;
    std::string subject;
    std::string status;
};

SigInfo VerifyFile(const std::wstring& path);

Trust ClassifyModule(const std::wstring& path, std::string* signerOut);

bool IsTrustedPublisher(const std::string& subject);

bool IsExpectedUnsignedNative(const std::wstring& path);

bool IsLauncherOwnedPath(const std::wstring& path);

bool IsKnownTempExtractedNative(const std::wstring& path);

void ClearTrustCache();

}
