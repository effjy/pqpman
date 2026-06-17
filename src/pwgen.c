/*
 * pwgen.c - Password generation and entropy estimation (see pwgen.h).
 */
#include "pwgen.h"

#include <sodium.h>
#include <math.h>
#include <string.h>

static const char *LOWER   = "abcdefghijklmnopqrstuvwxyz";
static const char *UPPER   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
static const char *DIGITS  = "0123456789";
/* A widely-accepted printable symbol set (no space, no quotes/backslash that
 * tend to break shells and CSV imports). */
static const char *SYMBOLS = "!#$%&()*+,-./:;<=>?@[]^_{|}~";

/* Build the combined pool into buf (caller supplies a buffer >= 95 bytes).
 * Returns the pool length. */
static size_t build_pool(unsigned classes, char *buf) {
    size_t n = 0;
    if (classes & PWGEN_LOWER)   { memcpy(buf + n, LOWER,   strlen(LOWER));   n += strlen(LOWER); }
    if (classes & PWGEN_UPPER)   { memcpy(buf + n, UPPER,   strlen(UPPER));   n += strlen(UPPER); }
    if (classes & PWGEN_DIGITS)  { memcpy(buf + n, DIGITS,  strlen(DIGITS));  n += strlen(DIGITS); }
    if (classes & PWGEN_SYMBOLS) { memcpy(buf + n, SYMBOLS, strlen(SYMBOLS)); n += strlen(SYMBOLS); }
    return n;
}

size_t pwgen_pool_size(unsigned classes) {
    char pool[128];
    return build_pool(classes, pool);
}

int pwgen_generate(char *out, size_t length, unsigned classes) {
    char pool[128];
    size_t pool_len = build_pool(classes, pool);
    if (pool_len == 0) return -1;
    if (length < PWGEN_MIN_LEN || length > PWGEN_MAX_LEN) return -1;

    /* Each selected class as its own sub-pool, so we can guarantee at least one
     * character from every class the user asked for (many sites enforce this). */
    struct { unsigned flag; const char *set; } cls[] = {
        { PWGEN_LOWER, LOWER }, { PWGEN_UPPER, UPPER },
        { PWGEN_DIGITS, DIGITS }, { PWGEN_SYMBOLS, SYMBOLS },
    };

    size_t i = 0;
    /* Seed one character from each selected class. PWGEN_MIN_LEN (4) is >= the
     * number of classes, so this never overflows out for a valid length. */
    for (size_t c = 0; c < sizeof(cls) / sizeof(cls[0]); c++) {
        if (!(classes & cls[c].flag)) continue;
        size_t set_len = strlen(cls[c].set);
        out[i++] = cls[c].set[randombytes_uniform((uint32_t)set_len)];
    }
    /* Fill the remainder from the combined pool. */
    for (; i < length; i++)
        out[i] = pool[randombytes_uniform((uint32_t)pool_len)];

    /* Fisher-Yates shuffle so the guaranteed characters are not stuck at the
     * front (unbiased: randombytes_uniform has no modulo bias). */
    for (size_t k = length; k > 1; k--) {
        size_t j = randombytes_uniform((uint32_t)k);
        char t = out[k - 1]; out[k - 1] = out[j]; out[j] = t;
    }

    out[length] = '\0';
    return 0;
}

double pwgen_naive_entropy(size_t length, unsigned classes) {
    size_t pool = pwgen_pool_size(classes);
    if (pool < 2 || length == 0) return 0.0;
    return (double)length * log2((double)pool);
}

double pwgen_shannon_entropy(const char *s) {
    if (!s || !*s) return 0.0;
    unsigned counts[256] = { 0 };
    size_t len = 0;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        counts[*p]++;
        len++;
    }
    double h = 0.0;   /* bits per character */
    for (int i = 0; i < 256; i++) {
        if (!counts[i]) continue;
        double pi = (double)counts[i] / (double)len;
        h -= pi * log2(pi);
    }
    return h * (double)len;
}

const char *pwgen_strength_label(double bits) {
    if (bits < 28)  return "Very weak";
    if (bits < 36)  return "Weak";
    if (bits < 60)  return "Reasonable";
    if (bits < 90)  return "Strong";
    if (bits < 128) return "Very strong";
    return "Excellent";
}
