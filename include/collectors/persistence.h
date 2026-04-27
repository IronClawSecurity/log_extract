#ifndef COLLECTOR_PERSISTENCE_H
#define COLLECTOR_PERSISTENCE_H

#include "collector.h"

int  collect_persistence_init(collector_t *self, const filter_config_t *filter,
                              const char *output_dir);
int  collect_persistence_run(collector_t *self);
void collect_persistence_cleanup(collector_t *self);

#endif /* COLLECTOR_PERSISTENCE_H */
