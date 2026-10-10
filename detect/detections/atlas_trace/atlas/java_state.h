#pragma once
#include "common.h"
#include "target.h"

namespace atlas {

struct JvmCounters {
    bool ok = false;
    std::string error;
    std::wstring path;
    std::map<std::string, std::string> values;

    const std::string* Find(const char* key) const {
        std::map<std::string, std::string>::const_iterator it = values.find(key);
        return it == values.end() ? nullptr : &it->second;
    }
    long long Num(const char* key, long long dflt = -1) const {
        const std::string* v = Find(key);
        if (!v) return dflt;
        return _strtoi64(v->c_str(), nullptr, 10);
    }
};

JvmCounters ReadJvmCounters(const Target& t);

struct MetaspaceNames {
    std::set<std::string> names;
    size_t bytesScanned = 0;
    bool   truncated = false;
};

MetaspaceNames ScanMetaspaceClassNames(const Target& t, size_t maxNames = 200000);

struct NamedObject {
    std::string  type;
    std::wstring name;
};

std::vector<NamedObject> EnumNamedObjects(const Target& t);

bool ReadClasspathClassNames(const Target& t, std::set<std::string>* out,
                             int* jarsRead, int* jarsMissing);

}
