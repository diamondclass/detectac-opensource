#include "c_club44.h"

bool club_checker::IsTargetCertificate(PCCERT_CONTEXT pCertContext) {
    try{
    DWORD cbData = 0;

    cbData = CertGetNameStringA(
        pCertContext,
        CERT_NAME_SIMPLE_DISPLAY_TYPE,
        0,
        NULL,
        NULL,
        0
    );

    if (cbData <= 1) return false;

    std::vector<char> subjectName(cbData);
    CertGetNameStringA(
        pCertContext,
        CERT_NAME_SIMPLE_DISPLAY_TYPE,
        0,
        NULL,
        &subjectName[0],
        cbData
    );

    std::string name(&subjectName[0]);
    return name.find(xorstr_("Microsoft Root Certificate Authority 2010")) != std::string::npos;
    }
    catch (...) {}
}

void club_checker::start_club44_check() {
    try{
    HCERTSTORE hStore = NULL;
    PCCERT_CONTEXT pCertContext = NULL;
    int certificateCount = 0;

    hStore = CertOpenStore(
        CERT_STORE_PROV_SYSTEM_A,
        0,
        0,
        CERT_SYSTEM_STORE_LOCAL_MACHINE,
        xorstr_("ROOT")
    );

    if (!hStore) {
        return;
    }

    pCertContext = CertEnumCertificatesInStore(hStore, NULL);

    while (pCertContext != NULL) {
        if (IsTargetCertificate(pCertContext)) {
            certificateCount++;
        }
        pCertContext = CertEnumCertificatesInStore(hStore, pCertContext);
    }

    std::vector<std::string> otherStores = { xorstr_("MY"), xorstr_("CA"), xorstr_("AuthRoot") };

    for (const auto& storeName : otherStores) {
        HCERTSTORE hOtherStore = CertOpenStore(
            CERT_STORE_PROV_SYSTEM_A,
            0,
            0,
            CERT_SYSTEM_STORE_LOCAL_MACHINE,
            storeName.c_str()
        );

        if (hOtherStore) {
            PCCERT_CONTEXT pOtherCert = CertEnumCertificatesInStore(hOtherStore, NULL);

            while (pOtherCert != NULL) {
                if (IsTargetCertificate(pOtherCert)) {
                    certificateCount++;
                }
                pOtherCert = CertEnumCertificatesInStore(hOtherStore, pOtherCert);
            }

            CertCloseStore(hOtherStore, 0);
        }
    }

    if (hStore) {
        CertCloseStore(hStore, 0);
    }

    if (certificateCount >= 2) {
        LOG ( WARNING , xorstr_("N/A")) << xorstr_("Previous Version Of Club44 Bypass Detected:Trace Of Previous Club44 Bypass Certificate Found");

    }

    return;
    }
    catch (...) {}
}