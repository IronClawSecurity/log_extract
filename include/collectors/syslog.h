#ifndef COLLECTOR_SYSLOG_H
#define COLLECTOR_SYSLOG_H

#include "collector.h"

int  collect_syslog_init(collector_t *self, const filter_config_t *filter,
                         const char *output_dir);
int  collect_syslog_run(collector_t *self);
void collect_syslog_cleanup(collector_t *self);

#endif /* COLLECTOR_SYSLOG_H */
