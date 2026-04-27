#ifndef REMOTE_H
#define REMOTE_H

#include "cli.h"

/*
 * Remote-target mode: copy this binary to a remote host via scp, exec it via
 * ssh with the same arguments (minus --target), then copy the resulting
 * archive(s) back to the local output directory. Returns the program exit
 * code that main() should use.
 *
 * argv[0] is taken to be the path to the local binary to deploy.
 * Requires `ssh` and `scp` on PATH on the local machine.
 */
int remote_run(const cli_options_t *opts, int argc, char *argv[]);

#endif /* REMOTE_H */
