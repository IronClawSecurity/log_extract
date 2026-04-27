#ifndef COLLECTOR_H
#define COLLECTOR_H

#include "filter.h"

#define MAX_COLLECTORS 16

typedef struct collector collector_t;

typedef int  (*collector_init_fn)(collector_t *self, const filter_config_t *filter,
                                  const char *output_dir);
typedef int  (*collector_run_fn)(collector_t *self);
typedef void (*collector_cleanup_fn)(collector_t *self);

struct collector {
    const char           *name;
    const char           *description;
    const char           *subdir;
    int                   enabled;
    collector_init_fn     init;
    collector_run_fn      run;
    collector_cleanup_fn  cleanup;
    void                 *ctx;
    const filter_config_t *filter;
    char                  out_path[1024];
    long                  lines_collected;
    int                   status;  /* 0=ok, 1=warn/partial, 2=skip, 3=error */
    char                  status_msg[256];
};

typedef struct {
    collector_t items[MAX_COLLECTORS];
    int         count;
} collector_registry_t;

/* Registry management */
void collector_registry_init(collector_registry_t *reg);
void collector_register(collector_registry_t *reg, const char *name,
                        const char *description, const char *subdir,
                        collector_init_fn init_fn, collector_run_fn run_fn,
                        collector_cleanup_fn cleanup_fn);
void collector_registry_run_all(collector_registry_t *reg,
                                const filter_config_t *filter,
                                const char *output_dir);

/* Platform-specific: register all collectors for this OS */
void collector_register_platform(collector_registry_t *reg);

#endif /* COLLECTOR_H */
