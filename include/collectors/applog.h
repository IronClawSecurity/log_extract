#ifndef COLLECTOR_APPLOG_H
#define COLLECTOR_APPLOG_H

#include "collector.h"

/* App log collector needs access to user-supplied paths */
typedef struct {
    char *app_paths[32];
    int   app_path_count;
} applog_config_t;

extern applog_config_t g_applog_config;

int  collect_applog_init(collector_t *self, const filter_config_t *filter,
                         const char *output_dir);
int  collect_applog_run(collector_t *self);
void collect_applog_cleanup(collector_t *self);

#endif /* COLLECTOR_APPLOG_H */
