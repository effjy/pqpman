/*
 * vault.h - PQPMan password vault model and on-disk encryption.
 *
 * A vault is an in-memory list of credential entries. It is persisted to a
 * single encrypted file. The serialized vault is encrypted as one AEAD blob
 * with AES-256-GCM or XChaCha20-Poly1305; the AEAD key is protected by the
 * master password through Argon2id, and (optionally) wrapped in a
 * post-quantum hybrid KEM layer (Kyber-1024 + X448) exactly as in Ciphers:
 * the file's KEM secret key is wrapped with the password-derived master key,
 * and the KEM shared secret is the AEAD key. A single master password unlocks
 * everything, and the vault stays secure against a quantum adversary.
 *
 * Nothing decrypted is ever written to disk: serialization and encryption
 * happen entirely in (locked) memory.
 */
#ifndef PQPMAN_VAULT_H
#define PQPMAN_VAULT_H

#include <stddef.h>
#include <stdint.h>

/* AEAD ciphers offered for the vault (subset of the Ciphers registry). */
typedef enum {
    VAULT_CIPHER_AES_256_GCM        = 1,
    VAULT_CIPHER_XCHACHA20_POLY1305 = 2,
} vault_cipher_t;

/* Argon2id strength presets (master-key derivation). */
typedef enum {
    VAULT_KDF_BASIC  = 0,   /* 256 MiB */
    VAULT_KDF_MEDIUM = 1,   /* 1 GiB, parallel - recommended minimum */
    VAULT_KDF_STRONG = 2,   /* 4 GiB, parallel */
} vault_kdf_t;

/* One credential entry. All strings are owned, NUL-terminated UTF-8 and are
 * zeroed before being freed. Any field may be an empty string but never NULL
 * once the entry is in a vault. */
typedef struct {
    char *title;      /* what this password is for (e.g. "GitHub")   */
    char *url;        /* location / website it is used at (optional) */
    char *username;   /* account / login name (optional)            */
    char *password;   /* the secret                                  */
    char *notes;      /* free-form notes (optional)                  */
} vault_entry_t;

typedef struct vault vault_t;

/* Initialise libsodium and process hardening (no core dumps, etc.).
 * Returns 0 on success. Call once at startup. */
int vault_init(void);

/* Create a new, empty in-memory vault with the given protection settings. */
vault_t *vault_new(vault_cipher_t cipher, vault_kdf_t kdf, int hybrid);

/* Free a vault and securely wipe every secret it holds. */
void vault_free(vault_t *v);

/* Protection settings (as chosen at creation or read from the file). */
vault_cipher_t vault_cipher(const vault_t *v);
vault_kdf_t    vault_kdf(const vault_t *v);
int            vault_is_hybrid(const vault_t *v);

/* Entry access. */
size_t               vault_count(const vault_t *v);
const vault_entry_t *vault_get(const vault_t *v, size_t index);

/* Add a new entry (fields are copied; NULL is treated as ""). Entries are kept
 * sorted by title (case-insensitive), so the entry is inserted at its sorted
 * position. Returns the index of the new entry, or (size_t)-1 on allocation
 * failure. */
size_t vault_add(vault_t *v, const char *title, const char *url,
                 const char *username, const char *password, const char *notes);

/* Replace the fields of an existing entry. Because a changed title can alter
 * the sort order, the entry may be moved; returns the entry's new index, or
 * (size_t)-1 on failure (bad index or allocation failure). */
size_t vault_update(vault_t *v, size_t index, const char *title, const char *url,
                    const char *username, const char *password, const char *notes);

/* Remove the entry at index, wiping its secrets. Returns 0 on success. */
int vault_remove(vault_t *v, size_t index);

/* Encrypt and write the vault to path using master password. The vault's
 * cipher/kdf/hybrid settings are used. Writes via a temp file + rename so a
 * failure never corrupts an existing vault. Returns 0 on success; on failure
 * fills err (size errlen). */
int vault_save(vault_t *v, const char *path, const char *password,
               char *err, size_t errlen);

/* Decrypt path with master password into a fresh vault (*out). The cipher,
 * KDF parameters and hybrid flag are read from the file header. Returns 0 on
 * success; non-zero on failure (wrong password, corruption, ...) with err
 * filled. */
int vault_load(const char *path, const char *password, vault_t **out,
               char *err, size_t errlen);

#endif /* PQPMAN_VAULT_H */
