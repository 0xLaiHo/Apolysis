/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef APOLYSIS_INTENT_H
#define APOLYSIS_INTENT_H
#include "apolysis_observer.h"
#define APOLYSIS_INTENT_HEADER_LEN (sizeof("# APOLYSIS_INTENT_ID=") - 1 + APOLYSIS_INTENT_ID_LEN + 1)
#define APOLYSIS_SHELL_OPTION_LEN 16
/* UNKNOWN means a header might have been truncated or malformed. */
enum apolysis_intent_capture { APOLYSIS_INTENT_UNKNOWN, APOLYSIS_INTENT_ABSENT, APOLYSIS_INTENT_PRESENT };
enum apolysis_intent_update { APOLYSIS_INTENT_CLEAR, APOLYSIS_INTENT_KEEP, APOLYSIS_INTENT_REPLACE };
enum apolysis_shell_opt {
    APOLYSIS_SHELL_OPT_UNKNOWN = 0,
    APOLYSIS_SHELL_OPT_SCRIPT = 1,
    APOLYSIS_SHELL_OPT_END = 2,
    APOLYSIS_SHELL_OPT_FLAG = 3,
    APOLYSIS_SHELL_OPT_COMMAND = 4,
    APOLYSIS_SHELL_OPT_TAKES_ARG = 5,
};

static __inline __attribute__((always_inline)) int
apolysis_is_shell_short_flag(char ch)
{
    switch (ch) {
    case 'a':
    case 'b':
    case 'C':
    case 'e':
    case 'f':
    case 'h':
    case 'i':
    case 'k':
    case 'l':
    case 'm':
    case 'n':
    case 'p':
    case 'r':
    case 's':
    case 't':
    case 'u':
    case 'v':
    case 'x':
    case 'B':
    case 'E':
    case 'H':
    case 'P':
    case 'T':
        return 1;
    default:
        return 0;
    }
}

static __inline __attribute__((always_inline)) int
apolysis_opt_eq(const char *option, unsigned int length, const char *expected, unsigned int expected_len)
{
    unsigned int i;

    if (length != expected_len)
        return 0;
#pragma unroll
    for (i = 0; i < expected_len; i++) {
        if (option[i] != expected[i])
            return 0;
    }
    return 1;
}

static __inline __attribute__((always_inline)) int
apolysis_classify_shell_option(const char *option, unsigned int length)
{
    int has_c = 0;
    int i;

    if (length == 0)
        return APOLYSIS_SHELL_OPT_UNKNOWN;
    if (option[0] != '-' && option[0] != '+')
        return APOLYSIS_SHELL_OPT_SCRIPT;
    if (length >= APOLYSIS_SHELL_OPTION_LEN - 1)
        return APOLYSIS_SHELL_OPT_UNKNOWN;
    if (length == 1)
        return option[0] == '-' ? APOLYSIS_SHELL_OPT_SCRIPT : APOLYSIS_SHELL_OPT_UNKNOWN;

    if (option[0] == '-' && option[1] == '-') {
        if (length == 2)
            return APOLYSIS_SHELL_OPT_END;
        if (apolysis_opt_eq(option, length, "--login", 7) ||
            apolysis_opt_eq(option, length, "--norc", 6) ||
            apolysis_opt_eq(option, length, "--noprofile", 11) ||
            apolysis_opt_eq(option, length, "--posix", 7) ||
            apolysis_opt_eq(option, length, "--noediting", 11))
            return APOLYSIS_SHELL_OPT_FLAG;
        return APOLYSIS_SHELL_OPT_UNKNOWN;
    }

    if (length == 2 && (option[1] == 'o' || option[1] == 'O'))
        return APOLYSIS_SHELL_OPT_TAKES_ARG;

    if (length > 6)
        return APOLYSIS_SHELL_OPT_UNKNOWN;

#pragma unroll
    for (i = 1; i < 6; i++) {
        if ((unsigned int)i < length) {
            if (option[0] == '-' && option[i] == 'c') {
                has_c = 1;
            } else if (!apolysis_is_shell_short_flag(option[i])) {
                return APOLYSIS_SHELL_OPT_UNKNOWN;
            }
        }
    }
    return has_c ? APOLYSIS_SHELL_OPT_COMMAND : APOLYSIS_SHELL_OPT_FLAG;
}

/* length is the complete path length returned by probe_read_user_str, minus
 * its NUL. Fixed tail checks avoid a path-scanning loop's verifier state
 * explosion while requiring an exact basename, not just a shell-like suffix. */
static __inline __attribute__((always_inline)) int
apolysis_executable_is_shell(const char *path, unsigned int length)
{
    if (length < 2 || length >= APOLYSIS_RESOURCE_LEN)
        return 0;
    if (path[length - 1] != 'h' || path[length - 2] != 's')
        return 0;
    if (length == 2 || path[length - 3] == '/')
        return 1;
    if (length < 3)
        return 0;
    if ((length == 3 || path[length - 4] == '/') &&
        (path[length - 3] == 'z' || path[length - 3] == 'k' || path[length - 3] == 'a'))
        return 1;
    if (length < 4 || (length != 4 && path[length - 5] != '/'))
        return 0;
    return ((path[length - 4] == 'b' || path[length - 4] == 'd') && path[length - 3] == 'a') ||
           (path[length - 4] == 'f' && path[length - 3] == 'i');
}

static __inline __attribute__((always_inline)) int
apolysis_parse_intent_header(const char *header, unsigned int length, char *intent_id)
{
    const char prefix[] = "# APOLYSIS_INTENT_ID=";
    int i;
#pragma unroll
    for (i = 0; i < sizeof(prefix) - 1; i++) {
        if (i >= length)
            return APOLYSIS_INTENT_UNKNOWN;
        if (header[i] != prefix[i])
            return APOLYSIS_INTENT_ABSENT;
    }
    if (length < APOLYSIS_INTENT_HEADER_LEN)
        return APOLYSIS_INTENT_UNKNOWN;
#pragma unroll
    for (i = 0; i < APOLYSIS_INTENT_ID_LEN; i++) {
        char ch = header[sizeof(prefix) - 1 + i];
        if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')))
            return APOLYSIS_INTENT_UNKNOWN;
    }
    if (header[APOLYSIS_INTENT_HEADER_LEN - 1] != '\n')
        return APOLYSIS_INTENT_UNKNOWN;
    __builtin_memcpy(intent_id, header + sizeof(prefix) - 1, APOLYSIS_INTENT_ID_LEN);
    return APOLYSIS_INTENT_PRESENT;
}

static __inline __attribute__((always_inline)) int
apolysis_intent_update_for_capture(int present, int complete, int has_token)
{
    if (!present || !complete)
        return APOLYSIS_INTENT_CLEAR;
    return has_token ? APOLYSIS_INTENT_REPLACE : APOLYSIS_INTENT_KEEP;
}
#endif
