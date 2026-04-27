#ifndef COLLECTOR_SNAPSHOT_H
#define COLLECTOR_SNAPSHOT_H

#include "collector.h"

int  collect_snapshot_init(collector_t *self, const filter_config_t *filter,
                           const char *output_dir);
int  collect_snapshot_run(collector_t *self);
void collect_snapshot_cleanup(collector_t *self);

#endif /* COLLECTOR_SNAPSHOT_H */
