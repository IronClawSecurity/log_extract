#include "log_extract.h"
#include "collectors/auth.h"
#include "jsonl.h"

#ifndef _WIN32

#include <unistd.h>

#ifndef __APPLE__
#include <pwd.h>
#include <utmpx.h>
#endif

#ifdef __APPLE__
static const char *auth_log_paths[] = {
    "/var/log/system.log",
    NULL
};
#else
static const char *auth_log_paths[] = {
    "/var/log/auth.log",
    "/var/log/secure",
    NULL
};
#endif

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
                              FILE *out, FILE *jsonl_f, const char *src_name)
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

#ifdef __APPLE__
        /* On macOS system.log, only include auth-related lines */
        if (!str_contains(line, "sshd") &&
            !str_contains(line, "sudo") &&
            !str_contains(line, "login") &&
            !str_contains(line, "auth") &&
            !str_contains(line, "screensharingd") &&
            !str_contains(line, "SecurityAgent") &&
            !str_contains(line, "authorization") &&
            !str_contains(line, "passwd"))
            continue;
#endif

        fputs(line, out);
        if (jsonl_f) {
            char trimmed[MAX_LINE_LEN];
            snprintf(trimmed, sizeof(trimmed), "%s", line);
            str_trim(trimmed);
            jsonl_emit(jsonl_f, src_name, t, -1, NULL, trimmed);
        }
        count++;
    }

    fclose(in);
    return count;
}

#ifndef __APPLE__
/* Linux-only: wtmp/btmp binary parsing */
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
                         FILE *out, FILE *jsonl_f, const char *src_name)
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

        plat_format_timestamp(t, timebuf, sizeof(timebuf));

        fprintf(out, "%-12s %-8s %-12s %-16s %s\n",
                utmp_type_str(entry.ut_type),
                entry.ut_user,
                entry.ut_line,
                entry.ut_host,
                timebuf);
        if (jsonl_f) {
            char user[33], tty[33], host[257], msg[512];
            snprintf(user, sizeof(user), "%s", entry.ut_user);
            snprintf(tty, sizeof(tty), "%s", entry.ut_line);
            snprintf(host, sizeof(host), "%s", entry.ut_host);
            snprintf(msg, sizeof(msg), "%s tty=%s host=%s",
                     utmp_type_str(entry.ut_type), tty, host);
            jsonl_emit(jsonl_f, src_name, t, -1, user, msg);
        }
        count++;
    }

    fclose(in);
    return count;
}
#endif /* !__APPLE__ */

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

#ifdef __APPLE__
    /* macOS: 'last' command and Unified Logging are always available */
    if (plat_file_exists("/usr/bin/last")) found = 1;
    if (plat_file_exists("/usr/bin/log")) found = 1;
#else
    if (plat_file_exists("/var/log/wtmp")) found = 1;
    if (plat_file_exists("/var/log/btmp")) found = 1;
#endif

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
            FILE *out, *jsonl_f;
            long n;

            basename = basename ? basename + 1 : auth_log_paths[i];
            plat_path_join(out_file, sizeof(out_file), self->out_path, basename);

            out = fopen(out_file, "w");
            if (!out) {
                log_warn("auth: cannot write to %s", out_file);
                continue;
            }

            jsonl_f = jsonl_open(self->out_path, basename);
            n = collect_auth_text(auth_log_paths[i], self->filter, out,
                                  jsonl_f, basename);
            fclose(out);
            jsonl_close(jsonl_f);

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

#ifdef __APPLE__
    /* macOS: capture 'last' command output (login history) */
    {
        char out_file[MAX_PATH_LEN];
        int ret;

        plat_path_join(out_file, sizeof(out_file), self->out_path, "last.txt");

        if (self->filter->username[0] && str_is_shell_safe(self->filter->username)) {
            char cmd[MAX_PATH_LEN];
            snprintf(cmd, sizeof(cmd), "last '%s'", self->filter->username);
            ret = plat_exec_capture(cmd, out_file);
        } else {
            ret = plat_exec_capture("last", out_file);
        }

        if (ret == 0) {
            FILE *f = fopen(out_file, "r");
            if (f) {
                char line[MAX_LINE_LEN];
                long n = 0;
                while (fgets(line, sizeof(line), f)) n++;
                fclose(f);
                total += n;
                log_verbose("auth: %ld lines from last", n);
            }
        }
    }

    /* macOS: Unified Logging auth events */
    if (plat_file_exists("/usr/bin/log")) {
        char cmd[MAX_PATH_LEN * 2];
        char out_file[MAX_PATH_LEN];
        int ret;
        long n;

        plat_path_join(out_file, sizeof(out_file), self->out_path, "auth_unified.log");

        snprintf(cmd, sizeof(cmd),
                 "log show --style compact --predicate "
                 "'process == \"loginwindow\" OR process == \"sshd\" "
                 "OR process == \"sudo\" OR process == \"screensharingd\" "
                 "OR process == \"SecurityAgent\"'");

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

        log_verbose("auth: running %s", cmd);
        ret = plat_exec_capture(cmd, out_file);
        if (ret == 0) {
            FILE *f = fopen(out_file, "r");
            if (f) {
                char line[MAX_LINE_LEN];
                n = 0;
                while (fgets(line, sizeof(line), f)) {
                    if (self->filter->username[0] &&
                        !str_contains(line, self->filter->username))
                        continue;
                    n++;
                }
                fclose(f);
                total += n;
                log_verbose("auth: %ld lines from Unified Logging", n);
            }
        } else {
            log_verbose("auth: log show returned %d", ret);
        }
    }

#else /* Linux */

    /* wtmp */
    if (plat_file_exists("/var/log/wtmp")) {
        char out_file[MAX_PATH_LEN];
        FILE *out, *jsonl_f;
        long n;

        plat_path_join(out_file, sizeof(out_file), self->out_path, "wtmp.txt");
        out = fopen(out_file, "w");
        if (out) {
            fprintf(out, "%-12s %-8s %-12s %-16s %s\n",
                    "TYPE", "USER", "TTY", "HOST", "TIME");
            fprintf(out, "%-12s %-8s %-12s %-16s %s\n",
                    "----", "----", "---", "----", "----");
            jsonl_f = jsonl_open(self->out_path, "wtmp");
            n = collect_wtmp("/var/log/wtmp", self->filter, out, jsonl_f, "wtmp");
            fclose(out);
            jsonl_close(jsonl_f);
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
        FILE *out, *jsonl_f;
        long n;

        plat_path_join(out_file, sizeof(out_file), self->out_path, "btmp.txt");
        out = fopen(out_file, "w");
        if (out) {
            fprintf(out, "%-12s %-8s %-12s %-16s %s\n",
                    "TYPE", "USER", "TTY", "HOST", "TIME");
            fprintf(out, "%-12s %-8s %-12s %-16s %s\n",
                    "----", "----", "---", "----", "----");
            jsonl_f = jsonl_open(self->out_path, "btmp");
            n = collect_wtmp("/var/log/btmp", self->filter, out, jsonl_f, "btmp");
            fclose(out);
            jsonl_close(jsonl_f);
            if (n < 0) {
                log_warn("auth: cannot read /var/log/btmp (requires root)");
                self->status = 1;
            } else {
                total += n;
                log_verbose("auth: %ld entries from btmp", n);
            }
        }
    }

#endif /* __APPLE__ / Linux */

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
