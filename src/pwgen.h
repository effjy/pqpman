/*
 * pwgen.h - Password generation and entropy estimation for PQPMan.
 *
 * Generation uses libsodium's unbiased randombytes_uniform, so every
 * character is drawn uniformly from the selected pool with no modulo bias.
 *
 * Two entropy figures are reported because they answer different questions:
 *
 *   - "naive" / search-space entropy: log2(pool_size ^ length) =
 *     length * log2(pool_size). This is the correct measure for a password
 *     drawn uniformly at random from a known alphabet (it tells an attacker
 *     how many guesses a brute-force search of that space costs). It is the
 *     headline strength for a *generated* password.
 *
 *   - "real" / Shannon entropy of the actual string: the per-character
 *     Shannon entropy H = -sum p_i*log2(p_i) over the characters that
 *     actually appear, times the length. For a short string this is a sample
 *     estimate and is usually *lower* than the search-space value (a 12-char
 *     password can't exhibit its full alphabet), so it is a useful sanity
 *     check / lower bound rather than the headline number.
 */
#ifndef PQPMAN_PWGEN_H
#define PQPMAN_PWGEN_H

#include <stddef.h>

/* Character classes, OR-combined into an options mask. */
typedef enum {
    PWGEN_LOWER   = 1 << 0,   /* a-z */
    PWGEN_UPPER   = 1 << 1,   /* A-Z */
    PWGEN_DIGITS  = 1 << 2,   /* 0-9 */
    PWGEN_SYMBOLS = 1 << 3,   /* punctuation */
} pwgen_class_t;

#define PWGEN_MIN_LEN 4
#define PWGEN_MAX_LEN 256

/* Generate a password of `length` characters using the character classes in
 * `classes` (a bitwise OR of pwgen_class_t). Writes a NUL-terminated string
 * into out (which must hold length+1 bytes). Returns 0 on success, -1 if no
 * class is selected or length is out of range. */
int pwgen_generate(char *out, size_t length, unsigned classes);

/* Size of the character pool implied by the selected classes. */
size_t pwgen_pool_size(unsigned classes);

/* Search-space ("naive") entropy in bits for a length-char password drawn
 * uniformly from the given classes: length * log2(pool_size). */
double pwgen_naive_entropy(size_t length, unsigned classes);

/* Shannon ("real") entropy in bits of the actual string s: the per-character
 * Shannon entropy of its observed symbol distribution, times its length. */
double pwgen_shannon_entropy(const char *s);

/* A short human label for an entropy figure (in bits): "Very weak" ..
 * "Excellent". */
const char *pwgen_strength_label(double bits);

#endif /* PQPMAN_PWGEN_H */
