#ifndef MANIFEST_H
#define MANIFEST_H

#include <time.h>
#include "collector.h"

/*
 * Write a forensic collection manifest into output_dir.
 *
 * Produces two files inside output_dir, so they are captured by the outer
 * archive (and thus covered by the archive's own SHA-256):
 *   - hashes.txt     : sha256sum-compatible ("<hex>  <relpath>\n")
 *   - manifest.json  : tool/host metadata + per-file hash, size, mtime
 *
 * collect_start_utc / collect_end_utc bracket the collector run (time(NULL)).
 *
 * Returns 0 on success, nonzero on failure.
 */
int manifest_write(const char *output_dir, const collector_registry_t *reg,
                   time_t collect_start_utc, time_t collect_end_utc);

#endif /* MANIFEST_H */
