#include "log_extract.h"
#include "collectors/auth.h"
#include "collectors/applog.h"
#include "collectors/netlog.h"
#include "collectors/filemon.h"

#ifndef _WIN32
#include "collectors/syslog.h"
#else
#include "collectors/eventlog.h"
#endif

void collector_registry_init(collector_registry_t *reg)
{
    memset(reg, 0, sizeof(*reg));
}

void collector_register(collector_registry_t *reg, const char *name,
                        const char *description, const char *subdir,
                        collector_init_fn init_fn, collector_run_fn run_fn,
                        collector_cleanup_fn cleanup_fn)
{
    collector_t *c;
    if (reg->count >= MAX_COLLECTORS) {
        log_warn("Maximum collectors reached, cannot register '%s'", name);
        return;
    }
    c = &reg->items[reg->count++];
    memset(c, 0, sizeof(*c));
    c->name = name;
    c->description = description;
    c->subdir = subdir;
    c->enabled = 0;
    c->init = init_fn;
    c->run = run_fn;
    c->cleanup = cleanup_fn;
}

void collector_registry_run_all(collector_registry_t *reg,
                                const filter_config_t *filter,
                                const char *output_dir)
{
    int i;
    for (i = 0; i < reg->count; i++) {
        collector_t *c = &reg->items[i];
        if (!c->enabled) {
            c->status = 2;
            snprintf(c->status_msg, sizeof(c->status_msg), "disabled");
            continue;
        }

        log_info("Collecting %s...", c->description);

        if (c->init(c, filter, output_dir) != 0) {
            log_warn("%s: init failed — %s", c->name,
                     c->status_msg[0] ? c->status_msg : "unknown error");
            if (c->status == 0)
                c->status = 2;
            continue;
        }

        if (c->run(c) != 0) {
            log_warn("%s: collection had errors — %s", c->name,
                     c->status_msg[0] ? c->status_msg : "partial data");
            if (c->status == 0)
                c->status = 1;
        }

        c->cleanup(c);

        if (c->status == 0) {
            log_verbose("%s: collected %ld lines", c->name, c->lines_collected);
        }
    }
}

void collector_register_platform(collector_registry_t *reg)
{
#ifndef _WIN32
    collector_register(reg, "system", "system logs", "system",
                       collect_syslog_init, collect_syslog_run,
                       collect_syslog_cleanup);
#else
    collector_register(reg, "system", "system event logs", "system",
                       collect_eventlog_init, collect_eventlog_run,
                       collect_eventlog_cleanup);
#endif

    collector_register(reg, "auth", "authentication logs", "auth",
                       collect_auth_init, collect_auth_run,
                       collect_auth_cleanup);

    collector_register(reg, "app", "application logs", "app",
                       collect_applog_init, collect_applog_run,
                       collect_applog_cleanup);

    collector_register(reg, "network", "network/firewall logs", "network",
                       collect_netlog_init, collect_netlog_run,
                       collect_netlog_cleanup);

    collector_register(reg, "filemon", "file modification logs", "filemon",
                       collect_filemon_init, collect_filemon_run,
                       collect_filemon_cleanup);
}
