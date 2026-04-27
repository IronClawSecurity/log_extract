#ifndef COLLECTOR_EVENTLOG_H
#define COLLECTOR_EVENTLOG_H

#include "collector.h"

int  collect_eventlog_init(collector_t *self, const filter_config_t *filter,
                           const char *output_dir);
int  collect_eventlog_run(collector_t *self);
void collect_eventlog_cleanup(collector_t *self);

#endif /* COLLECTOR_EVENTLOG_H */
