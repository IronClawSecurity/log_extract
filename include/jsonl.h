#ifndef JSONL_H
#define JSONL_H

#include <stdio.h>
#include <time.h>

/* Newline-delimited JSON event emitter for collectors.
 *
 * Globally enabled by --jsonl. Each line-oriented collector should:
 *   1. Open a sibling .jsonl file alongside its raw text output via jsonl_open.
 *   2. Call jsonl_emit(...) for every line that passes filtering.
 *   3. Close the file with jsonl_close at the end.
 * If g_jsonl_enabled is 0, jsonl_open returns NULL and other calls are no-ops.
 */

extern int g_jsonl_enabled;

/* Returns a FILE* for the .jsonl sidecar, or NULL if disabled / can't open. */
FILE *jsonl_open(const char *out_dir, const char *base_name);

/* Emit one event. Any of source/severity/user may be NULL/empty.
 * If ts == 0, no timestamp field is included. message is required. */
void  jsonl_emit(FILE *f, const char *source, time_t ts,
                 int severity, const char *user, const char *message);

void  jsonl_close(FILE *f);

#endif /* JSONL_H */
