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

    for (size_t i = 0; i < length; i++)
        out[i] = pool[randombytes_uniform((uint32_t)pool_len)];
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
