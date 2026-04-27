#include "log_extract.h"
#include "collectors/auth.h"

#ifndef _WIN32

#include <pwd.h>
#include <unistd.h>
#include <utmpx.h>

static const char *auth_log_paths[] = {
    "/var/log/auth.log",
    "/var/log/secure",
    NULL
};

/* Parse syslog-style timestamp from auth log line */
static time_t parse_auth_time(const char *line)
{
    struct tm tm;
    static const char *months[] = {
        "Jan","Feb","Mar","Apr","May","Jun",
        "Jul","Aug","Sep","Oct","Nov","Dec"
    };
    char mon[4];
    int i;
    time_t now;
    struct tm *now_tm;

    memset(&tm, 0, sizeof(tm));
    if (sscanf(line, "%3s %d %d:%d:%d", mon, &tm.tm_mday,
               &tm.tm_hour, &tm.tm_min, &tm.tm_sec) != 5)
        return 0;

    tm.tm_mon = -1;
    for (i = 0; i < 12; i++) {
        if (strcmp(mon, months[i]) == 0) {
            tm.tm_mon = i;
            break;
        }
    }
    if (tm.tm_mon == -1) return 0;

    now = time(NULL);
    now_tm = localtime(&now);
    tm.tm_year = now_tm->tm_year;
    tm.tm_isdst = -1;

    return mktime(&tm);
}

static long collect_auth_text(const char *path, const filter_config_t *filter,
                              FILE *out)
{
    FILE *in;
    char line[MAX_LINE_LEN];
    long count = 0;
    time_t t;

    in = fopen(path, "r");
    if (!in) return -1;

    while (fgets(line, sizeof(line), in)) {
        t = parse_auth_time(line);
        if (!filter_match_time(filter, t)) continue;
        if (!filter_match_line(filter, line)) continue;
        fputs(line, out);
        count++;
    }

    fclose(in);
    return count;
}

static const char *utmp_type_str(short type)
{
    switch (type) {
        case USER_PROCESS:  return "LOGIN";
        case DEAD_PROCESS:  return "LOGOUT";
        case BOOT_TIME:     return "BOOT";
        case LOGIN_PROCESS: return "LOGIN_PROC";
        default:            return "OTHER";
    }
}

static long collect_wtmp(const char *path, const filter_config_t *filter,
                         FILE *out)
{
    FILE *in;
    struct utmpx entry;
    long count = 0;
    char timebuf[32];

    in = fopen(path, "rb");
    if (!in) return -1;

    while (fread(&entry, sizeof(entry), 1, in) == 1) {
        time_t t = entry.ut_tv.tv_sec;

        if (!filter_match_time(filter, t)) continue;

        /* User filter: match ut_user */
        if (filter->username[0]) {
            if (strncmp(entry.ut_user, filter->username,
                        sizeof(entry.ut_user)) != 0)
                continue;
        }

        /* Keyword filter on formatted line */
        plat_format_timestamp(t, timebuf, sizeof(timebuf));

        fprintf(out, "%-12s %-8s %-12s %-16s %s\n",
                utmp_type_str(entry.ut_type),
                entry.ut_user,
                entry.ut_line,
                entry.ut_host,
                timebuf);
        count++;
    }

    fclose(in);
    return count;
}

int collect_auth_init(collector_t *self, const filter_config_t *filter,
                      const char *output_dir)
{
    char subdir[MAX_PATH_LEN];
    int found = 0;
    int i;

    self->filter = filter;
    plat_path_join(self->out_path, sizeof(self->out_path), output_dir, self->subdir);

    for (i = 0; auth_log_paths[i]; i++) {
        if (plat_file_exists(auth_log_paths[i])) {
            found = 1;
            break;
        }
    }
    if (plat_file_exists("/var/log/wtmp")) found = 1;
    if (plat_file_exists("/var/log/btmp")) found = 1;

    if (!found) {
        self->status = 2;
        snprintf(self->status_msg, sizeof(self->status_msg), "no auth log sources found");
        return -1;
    }

    plat_path_join(subdir, sizeof(subdir), output_dir, self->subdir);
    if (plat_mkdir_p(subdir) != 0) {
        self->status = 3;
        snprintf(self->status_msg, sizeof(self->status_msg), "cannot create output dir");
        return -1;
    }

    return 0;
}

int collect_auth_run(collector_t *self)
{
    long total = 0;
    int i;

    /* Text-based auth logs */
    for (i = 0; auth_log_paths[i]; i++) {
        if (!plat_file_exists(auth_log_paths[i])) continue;

        {
            char out_file[MAX_PATH_LEN];
            const char *basename = strrchr(auth_log_paths[i], '/');
            FILE *out;
            long n;

            basename = basename ? basename + 1 : auth_log_paths[i];
            plat_path_join(out_file, sizeof(out_file), self->out_path, basename);

            out = fopen(out_file, "w");
            if (!out) {
                log_warn("auth: cannot write to %s", out_file);
                continue;
            }

            n = collect_auth_text(auth_log_paths[i], self->filter, out);
            fclose(out);

            if (n < 0) {
                log_warn("auth: cannot read %s (permission denied?)",
                         auth_log_paths[i]);
                self->status = 1;
                snprintf(self->status_msg, sizeof(self->status_msg),
                         "partial: could not read %s", auth_log_paths[i]);
            } else {
                total += n;
                log_verbose("auth: %ld lines from %s", n, auth_log_paths[i]);
            }
        }
    }

    /* wtmp */
    if (plat_file_exists("/var/log/wtmp")) {
        char out_file[MAX_PATH_LEN];
        FILE *out;
        long n;

        plat_path_join(out_file, sizeof(out_file), self->out_path, "wtmp.txt");
        out = fopen(out_file, "w");
        if (out) {
            fprintf(out, "%-12s %-8s %-12s %-16s %s\n",
                    "TYPE", "USER", "TTY", "HOST", "TIME");
            fprintf(out, "%-12s %-8s %-12s %-16s %s\n",
                    "----", "----", "---", "----", "----");
            n = collect_wtmp("/var/log/wtmp", self->filter, out);
            fclose(out);
            if (n < 0) {
                log_warn("auth: cannot read /var/log/wtmp");
            } else {
                total += n;
                log_verbose("auth: %ld entries from wtmp", n);
            }
        }
    }

    /* btmp (failed logins) */
    if (plat_file_exists("/var/log/btmp")) {
        char out_file[MAX_PATH_LEN];
        FILE *out;
        long n;

        plat_path_join(out_file, sizeof(out_file), self->out_path, "btmp.txt");
        out = fopen(out_file, "w");
        if (out) {
            fprintf(out, "%-12s %-8s %-12s %-16s %s\n",
                    "TYPE", "USER", "TTY", "HOST", "TIME");
            fprintf(out, "%-12s %-8s %-12s %-16s %s\n",
                    "----", "----", "---", "----", "----");
            n = collect_wtmp("/var/log/btmp", self->filter, out);
            fclose(out);
            if (n < 0) {
                log_warn("auth: cannot read /var/log/btmp (requires root)");
                self->status = 1;
            } else {
                total += n;
                log_verbose("auth: %ld entries from btmp", n);
            }
        }
    }

    self->lines_collected = total;
    if (total == 0) {
        self->status = 2;
        snprintf(self->status_msg, sizeof(self->status_msg), "no matching entries");
    }

    return 0;
}

void collect_auth_cleanup(collector_t *self)
{
    (void)self;
}

#else /* _WIN32 */

/* Windows auth collection via Security Event Log */
/* Implemented in collect_eventlog.c helper functions */

int collect_auth_init(collector_t *self, const filter_config_t *filter,
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

int collect_auth_run(collector_t *self)
{
    /* Windows implementation uses Evt* API — see collect_eventlog.c */
    /* This is a stub that will be filled in when Windows support is built */
    self->status = 2;
    snprintf(self->status_msg, sizeof(self->status_msg),
             "Windows auth collection not yet implemented");
    return 0;
}

void collect_auth_cleanup(collector_t *self)
{
    (void)self;
}

#endif /* _WIN32 */
