#ifndef COLLECTOR_AUTH_H
#define COLLECTOR_AUTH_H

#include "collector.h"

int  collect_auth_init(collector_t *self, const filter_config_t *filter,
                       const char *output_dir);
int  collect_auth_run(collector_t *self);
void collect_auth_cleanup(collector_t *self);

#endif /* COLLECTOR_AUTH_H */
