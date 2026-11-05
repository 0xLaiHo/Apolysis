/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef APOLYSIS_INTENT_H
#define APOLYSIS_INTENT_H
#include "apolysis_observer.h"
#define APOLYSIS_INTENT_HEADER_LEN (sizeof("# APOLYSIS_INTENT_ID=") - 1 + APOLYSIS_INTENT_ID_LEN + 1)
/* UNKNOWN means a header might have been truncated or malformed. */
enum apolysis_intent_capture { APOLYSIS_INTENT_UNKNOWN, APOLYSIS_INTENT_ABSENT, APOLYSIS_INTENT_PRESENT };
enum apolysis_intent_update { APOLYSIS_INTENT_CLEAR, APOLYSIS_INTENT_KEEP, APOLYSIS_INTENT_REPLACE };

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
