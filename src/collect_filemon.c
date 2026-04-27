#include "log_extract.h"
#include "collectors/filemon.h"

#ifndef _WIN32

#include <pwd.h>

static const char *audit_path = "/var/log/audit/audit.log";

/* Parse auditd timestamp from: type=X msg=audit(EPOCH.MS:SERIAL): ... */
static time_t parse_audit_time(const char *line)
{
    const char *p = strstr(line, "audit(");
    double ts;
    if (!p) return 0;
    p += 6; /* skip "audit(" */
    if (sscanf(p, "%lf", &ts) != 1) return 0;
    return (time_t)ts;
}

/* Check if auditd line matches a UID (for user filtering) */
static int audit_matches_uid(const char *line, const char *uid_str)
{
    char pattern_uid[64], pattern_auid[64];

    snprintf(pattern_uid, sizeof(pattern_uid), " uid=%s", uid_str);
    snprintf(pattern_auid, sizeof(pattern_auid), " auid=%s", uid_str);

    return str_contains(line, pattern_uid) || str_contains(line, pattern_auid);
}

/* Check if line is a file-access related audit event */
static int is_file_audit_event(const char *line)
{
    return str_contains(line, "type=SYSCALL") ||
           str_contains(line, "type=PATH") ||
           str_contains(line, "type=CWD") ||
           str_contains(line, "type=PROCTITLE");
}

int collect_filemon_init(collector_t *self, const filter_config_t *filter,
                         const char *output_dir)
{
    self->filter = filter;
    plat_path_join(self->out_path, sizeof(self->out_path), output_dir, self->subdir);

    if (!plat_file_exists(audit_path)) {
        self->status = 2;
        snprintf(self->status_msg, sizeof(self->status_msg),
                 "auditd log not found (%s)", audit_path);
        return -1;
    }

    if (plat_mkdir_p(self->out_path) != 0) {
        self->status = 3;
        snprintf(self->status_msg, sizeof(self->status_msg), "cannot create output dir");
        return -1;
    }

    return 0;
}

int collect_filemon_run(collector_t *self)
{
    FILE *in, *out;
    char line[MAX_LINE_LEN];
    char out_file[MAX_PATH_LEN];
    char uid_str[32] = {0};
    long total = 0;
    time_t t;

    /* If user filter is set, resolve username to UID */
    if (self->filter->username[0]) {
        struct passwd *pw = getpwnam(self->filter->username);
        if (pw) {
            snprintf(uid_str, sizeof(uid_str), "%d", pw->pw_uid);
            log_verbose("filemon: resolved user '%s' to uid %s",
                        self->filter->username, uid_str);
        } else {
            log_warn("filemon: cannot resolve user '%s' — "
                     "will fall back to string matching", self->filter->username);
        }
    }

    in = fopen(audit_path, "r");
    if (!in) {
        self->status = 1;
        snprintf(self->status_msg, sizeof(self->status_msg),
                 "permission denied: %s", audit_path);
        return -1;
    }

    plat_path_join(out_file, sizeof(out_file), self->out_path, "audit.log");
    out = fopen(out_file, "w");
    if (!out) {
        fclose(in);
        self->status = 3;
        snprintf(self->status_msg, sizeof(self->status_msg),
                 "cannot write output file");
        return -1;
    }

    while (fgets(line, sizeof(line), in)) {
        /* Only file-access related events */
        if (!is_file_audit_event(line)) continue;

        /* Time filter */
        t = parse_audit_time(line);
        if (!filter_match_time(self->filter, t)) continue;

        /* User filter by UID */
        if (uid_str[0] && !audit_matches_uid(line, uid_str)) continue;

        /* Keyword filter */
        if (!filter_match_keyword(self->filter, line)) continue;

        fputs(line, out);
        total++;
    }

    fclose(in);
    fclose(out);

    self->lines_collected = total;
    if (total == 0) {
        self->status = 2;
        snprintf(self->status_msg, sizeof(self->status_msg), "no matching entries");
    }

    return 0;
}

void collect_filemon_cleanup(collector_t *self)
{
    (void)self;
}

#else /* _WIN32 */

int collect_filemon_init(collector_t *self, const filter_config_t *filter,
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

int collect_filemon_run(collector_t *self)
{
    /* TODO: query Security event log for EventIDs 4663/4656/4660/4670 */
    self->status = 2;
    snprintf(self->status_msg, sizeof(self->status_msg),
             "Windows file audit collection not yet implemented");
    return 0;
}

void collect_filemon_cleanup(collector_t *self)
{
    (void)self;
}

#endif /* _WIN32 */
