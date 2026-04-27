#ifndef COLLECTOR_FILEMON_H
#define COLLECTOR_FILEMON_H

#include "collector.h"

int  collect_filemon_init(collector_t *self, const filter_config_t *filter,
                          const char *output_dir);
int  collect_filemon_run(collector_t *self);
void collect_filemon_cleanup(collector_t *self);

#endif /* COLLECTOR_FILEMON_H */
