#include "log_extract.h"
#include "collectors/netlog.h"

#ifndef _WIN32

#ifdef __APPLE__
static const char *netlog_paths[] = {
    "/var/log/appfirewall.log",
    "/var/log/wifi.log",
    NULL
};
#else
static const char *netlog_paths[] = {
    "/var/log/ufw.log",
    "/var/log/firewalld",
    "/var/log/iptables.log",
    NULL
};
#endif

static long collect_text_filtered(const char *path, const filter_config_t *filter,
                                  FILE *out)
{
    FILE *in;
    char line[MAX_LINE_LEN];
    long count = 0;

    in = fopen(path, "r");
    if (!in) return -1;

    while (fgets(line, sizeof(line), in)) {
        if (!filter_match_line(filter, line)) continue;
        fputs(line, out);
        count++;
    }

    fclose(in);
    return count;
}

#ifndef __APPLE__
/* Linux: scan kern.log for firewall/netfilter lines */
static long collect_kern_netfilter(const filter_config_t *filter, FILE *out)
{
    FILE *in;
    char line[MAX_LINE_LEN];
    long count = 0;

    in = fopen("/var/log/kern.log", "r");
    if (!in) return 0;

    while (fgets(line, sizeof(line), in)) {
        if (!str_contains(line, "iptables") &&
            !str_contains(line, "DROPPED") &&
            !str_contains(line, "BLOCKED") &&
            !str_contains(line, "netfilter") &&
            !str_contains(line, "UFW") &&
            !str_contains(line, "IN=") &&
            !str_contains(line, "firewall"))
            continue;

        if (!filter_match_line(filter, line)) continue;
        fputs(line, out);
        count++;
    }

    fclose(in);
    return count;
}
#endif

int collect_netlog_init(collector_t *self, const filter_config_t *filter,
                        const char *output_dir)
{
    int i, found = 0;

    self->filter = filter;
    plat_path_join(self->out_path, sizeof(self->out_path), output_dir, self->subdir);

    for (i = 0; netlog_paths[i]; i++) {
        if (plat_file_exists(netlog_paths[i])) {
            found = 1;
            break;
        }
    }

#ifdef __APPLE__
    /* macOS Unified Logging for firewall events is always available */
    if (plat_file_exists("/usr/bin/log")) found = 1;
#else
    if (plat_file_exists("/var/log/kern.log")) found = 1;
#endif

    if (!found) {
        self->status = 2;
        snprintf(self->status_msg, sizeof(self->status_msg),
                 "no firewall log sources found");
        return -1;
    }

    if (plat_mkdir_p(self->out_path) != 0) {
        self->status = 3;
        snprintf(self->status_msg, sizeof(self->status_msg), "cannot create output dir");
        return -1;
    }

    return 0;
}

int collect_netlog_run(collector_t *self)
{
    long total = 0;
    int i;

    /* Collect text-based log files */
    for (i = 0; netlog_paths[i]; i++) {
        if (!plat_file_exists(netlog_paths[i])) continue;

        {
            char out_file[MAX_PATH_LEN];
            const char *basename = strrchr(netlog_paths[i], '/');
            FILE *out;
            long n;

            basename = basename ? basename + 1 : netlog_paths[i];
            plat_path_join(out_file, sizeof(out_file), self->out_path, basename);

            out = fopen(out_file, "w");
            if (!out) continue;

            n = collect_text_filtered(netlog_paths[i], self->filter, out);
            fclose(out);

            if (n > 0) {
                total += n;
                log_verbose("network: %ld lines from %s", n, netlog_paths[i]);
            } else if (n < 0) {
                log_warn("network: cannot read %s", netlog_paths[i]);
                self->status = 1;
            }
        }
    }

#ifdef __APPLE__
    /* macOS: Unified Logging for firewall events */
    if (plat_file_exists("/usr/bin/log")) {
        char cmd[MAX_PATH_LEN * 2];
        char out_file[MAX_PATH_LEN];
        int ret;

        plat_path_join(out_file, sizeof(out_file), self->out_path,
                       "firewall_unified.log");

        snprintf(cmd, sizeof(cmd),
                 "log show --style compact --predicate "
                 "'process == \"socketfilterfw\" OR process == \"alf\" "
                 "OR (process == \"kernel\" AND eventMessage CONTAINS \"Firewall\")'");

        {
            int has_time = 0;
            if (self->filter->time_start) {
                char ts[32];
                plat_format_timestamp(self->filter->time_start, ts, sizeof(ts));
                if (str_is_shell_safe(ts)) {
                    snprintf(cmd + strlen(cmd), sizeof(cmd) - strlen(cmd),
                             " --start '%s'", ts);
                    has_time = 1;
                }
            }
            if (self->filter->time_end) {
                char ts[32];
                plat_format_timestamp(self->filter->time_end, ts, sizeof(ts));
                if (str_is_shell_safe(ts)) {
                    snprintf(cmd + strlen(cmd), sizeof(cmd) - strlen(cmd),
                             " --end '%s'", ts);
                    has_time = 1;
                }
            }
            if (!has_time)
                snprintf(cmd + strlen(cmd), sizeof(cmd) - strlen(cmd), " --last 1d");
        }

        log_verbose("network: running %s", cmd);
        ret = plat_exec_capture(cmd, out_file);
        if (ret == 0) {
            FILE *f = fopen(out_file, "r");
            if (f) {
                char line[MAX_LINE_LEN];
                long n = 0;
                while (fgets(line, sizeof(line), f)) {
                    if (self->filter->keyword[0] &&
                        !str_contains(line, self->filter->keyword))
                        continue;
                    n++;
                }
                fclose(f);
                total += n;
                log_verbose("network: %ld lines from Unified Logging", n);
            }
        }
    }
#else
    /* Linux: kernel netfilter lines */
    if (plat_file_exists("/var/log/kern.log")) {
        char out_file[MAX_PATH_LEN];
        FILE *out;
        long n;

        plat_path_join(out_file, sizeof(out_file), self->out_path,
                       "kern_netfilter.log");
        out = fopen(out_file, "w");
        if (out) {
            n = collect_kern_netfilter(self->filter, out);
            fclose(out);
            if (n > 0) {
                total += n;
                log_verbose("network: %ld lines from kern.log (netfilter)", n);
            }
        }
    }
#endif

    self->lines_collected = total;
    if (total == 0 && self->status == 0) {
        self->status = 2;
        snprintf(self->status_msg, sizeof(self->status_msg), "no matching entries");
    }

    return 0;
}

void collect_netlog_cleanup(collector_t *self)
{
    (void)self;
}

#else /* _WIN32 */

int collect_netlog_init(collector_t *self, const filter_config_t *filter,
                        const char *output_dir)
{
    self->filter = filter;
    plat_path_join(self->out_path, sizeof(self->out_path), output_dir, self->subdir);
    if (plat_mkdir_p(self->out_path) != 0) {
        self->status = 3;
        snprintf(self->status_msg, sizeof(self->status_msg), "cannot create output dir");
        return -1;
    }
    return 0;
}

int collect_netlog_run(collector_t *self)
{
    self->status = 2;
    snprintf(self->status_msg, sizeof(self->status_msg),
             "Windows network log collection not yet implemented");
    return 0;
}

void collect_netlog_cleanup(collector_t *self)
{
    (void)self;
}

#endif /* _WIN32 */
