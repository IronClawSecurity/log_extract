#ifndef HASH_H
#define HASH_H

#include <stddef.h>

/*
 * Compute SHA-256 hash of a file.
 * path:   file to hash
 * hex_out: buffer to receive 64-char hex string + null terminator (min 65 bytes)
 *
 * Returns 0 on success, nonzero on failure.
 */
int hash_sha256_file(const char *path, char *hex_out, size_t bufsz);

/*
 * Write a .sha256 sidecar file next to the archive.
 * archive_path: the file that was hashed
 * hex:          the 64-char hex hash string
 *
 * Returns 0 on success, nonzero on failure.
 */
int hash_write_sidecar(const char *archive_path, const char *hex);

#endif /* HASH_H */
