#ifndef COLLECTOR_FILEMON_H
#define COLLECTOR_FILEMON_H

#include "collector.h"

/* Live fs_usage capture duration on macOS (seconds). 0 = disabled.
 * Set from CLI in main.c before collectors run. */
extern int g_fs_usage_secs;

int  collect_filemon_init(collector_t *self, const filter_config_t *filter,
                          const char *output_dir);
int  collect_filemon_run(collector_t *self);
void collect_filemon_cleanup(collector_t *self);

#endif /* COLLECTOR_FILEMON_H */
