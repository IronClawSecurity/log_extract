#ifndef MANIFEST_H
#define MANIFEST_H

#include "collector.h"
#include "cli.h"

/*
 * Write a JSON manifest describing the collection: tool version, hostname,
 * command line, per-collector status, and a SHA-256 of every collected file.
 *
 * Written into <output_dir>/manifest.json BEFORE the directory is archived,
 * so the manifest itself is captured inside the archive.
 *
 * Returns 0 on success, nonzero on failure.
 */
int manifest_write(const char *output_dir,
                   const collector_registry_t *reg,
                   const cli_options_t *opts,
                   int argc, char *argv[]);

#endif /* MANIFEST_H */
