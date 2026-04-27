#ifndef COLLECTOR_NETLOG_H
#define COLLECTOR_NETLOG_H

#include "collector.h"

int  collect_netlog_init(collector_t *self, const filter_config_t *filter,
                         const char *output_dir);
int  collect_netlog_run(collector_t *self);
void collect_netlog_cleanup(collector_t *self);

#endif /* COLLECTOR_NETLOG_H */
