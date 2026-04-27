#include "log_extract.h"
#include "collectors/snapshot.h"

/*
 * Snapshot collector: live system state at collection time.
 * Logs answer "what happened" — snapshot answers "what is happening right now".
 *
 * No filtering is applied; these outputs are small and the user typically wants
 * the complete picture. Time/keyword filters don't apply.
 */

typedef struct {
    const char *out_name;   /* file written under snapshot/ */
    const char *cmd;        /* command to run */
} snap_cmd_t;

#if defined(_WIN32)
static const snap_cmd_t snap_cmds[] = {
    {"processes.csv",   "tasklist /v /fo CSV"},
    {"netstat.txt",     "netstat -anob"},
    {"services.csv",    "sc query state= all"},
    {"sessions.txt",    "query user"},
    {"systeminfo.txt",  "systeminfo"},
    {"ipconfig.txt",    "ipconfig /all"},
    {"arp.txt",         "arp -a"},
    {"routes.txt",      "route print"},
    {NULL, NULL}
};
#elif defined(__APPLE__)
static const snap_cmd_t snap_cmds[] = {
    {"processes.txt",   "ps -axo pid,ppid,user,start,etime,pcpu,pmem,command"},
    {"netstat.txt",     "netstat -anv"},
    {"lsof.txt",        "lsof -nP 2>/dev/null"},
    {"who.txt",         "who"},
    {"last.txt",        "last -100"},
    {"ifconfig.txt",    "ifconfig -a"},
    {"arp.txt",         "arp -an"},
    {"routes.txt",      "netstat -rn"},
    {"loaded_kexts.txt", "kextstat 2>/dev/null"},
    {"mounts.txt",      "mount"},
    {NULL, NULL}
};
#else
static const snap_cmd_t snap_cmds[] = {
    {"processes.txt",   "ps auxf"},
    {"processes_full.txt", "ps -eo pid,ppid,user,lstart,etime,pcpu,pmem,args"},
    {"netstat.txt",     "ss -tunap 2>/dev/null || netstat -tunap"},
    {"lsof.txt",        "lsof -nP 2>/dev/null"},
    {"who.txt",         "who"},
    {"last.txt",        "last -F -100"},
    {"ip_addr.txt",     "ip addr 2>/dev/null || ifconfig -a"},
    {"ip_route.txt",    "ip route 2>/dev/null || route -n"},
    {"arp.txt",         "ip neigh 2>/dev/null || arp -an"},
    {"loaded_modules.txt", "lsmod"},
    {"mounts.txt",      "mount"},
    {"open_files.txt",  "ls -la /proc/*/exe 2>/dev/null | head -200"},
    {NULL, NULL}
};
#endif

int collect_snapshot_init(collector_t *self, const filter_config_t *filter,
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

int collect_snapshot_run(collector_t *self)
{
    long total = 0;
    int i;

    for (i = 0; snap_cmds[i].out_name; i++) {
        char out_file[MAX_PATH_LEN];
        int ret;

        plat_path_join(out_file, sizeof(out_file), self->out_path,
                       snap_cmds[i].out_name);

        log_verbose("snapshot: %s", snap_cmds[i].cmd);
        ret = plat_exec_capture(snap_cmds[i].cmd, out_file);
        if (ret != 0) {
            log_verbose("snapshot: %s returned %d (skipping)",
                        snap_cmds[i].out_name, ret);
            /* Many of these commands are best-effort; missing tools or
             * permission denied are not collector-level failures. */
            continue;
        }

        /* Count lines as a rough tally */
        {
            FILE *f = fopen(out_file, "r");
            if (f) {
                char line[MAX_LINE_LEN];
                while (fgets(line, sizeof(line), f)) total++;
                fclose(f);
            }
        }
    }

    self->lines_collected = total;
    if (total == 0) {
        self->status = 1;
        snprintf(self->status_msg, sizeof(self->status_msg),
                 "no snapshot commands produced output");
    }

    return 0;
}

void collect_snapshot_cleanup(collector_t *self)
{
    (void)self;
}
