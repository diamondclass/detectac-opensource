#pragma once

#include "../../pch.h"


class club_checker {
public:
    static bool IsTargetCertificate(PCCERT_CONTEXT pCertContext);

    static void start_club44_check();
};

inline auto c_club = std::make_unique<club_checker>();