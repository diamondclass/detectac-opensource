#pragma once

#include "../../../pch.h"

#include <string>
#include <yara.h>

namespace YaraCompile {

inline bool InitCompiler(YR_COMPILER*& comp, int64_t scanEpoch)
{
    if (yr_compiler_create(&comp) != ERROR_SUCCESS || !comp) return false;
    yr_compiler_define_string_variable(comp, xorstr_("filename"), "");
    yr_compiler_define_integer_variable(comp, xorstr_("current_time"), scanEpoch);
    yr_compiler_define_boolean_variable(comp, xorstr_("is_hidden"), 0);
    yr_compiler_set_callback(comp,
        [](int, const char*, int, const YR_RULE*, const char*, void*) {},
        nullptr);
    return true;
}

inline YR_RULES* CompileAll(const std::string& source, int64_t scanEpoch)
{
    YR_COMPILER* comp = nullptr;
    if (!InitCompiler(comp, scanEpoch)) return nullptr;

    if (yr_compiler_add_string(comp, source.c_str(), nullptr) != 0) {
        yr_compiler_destroy(comp);
        return nullptr;
    }

    YR_RULES* rules = nullptr;
    if (yr_compiler_get_rules(comp, &rules) != ERROR_SUCCESS || !rules) {
        yr_compiler_destroy(comp);
        return nullptr;
    }

    yr_compiler_destroy(comp);
    return rules;
}

}
