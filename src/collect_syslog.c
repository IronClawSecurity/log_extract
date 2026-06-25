#ifndef _WIN32

#include "log_extract.h"
#include "collectors/syslog.h"

#ifdef __APPLE__
static const char *syslog_paths[] = {
    "/var/log/system.log",
    "/var/log/install.log",
    NULL
};
#else
static const char *syslog_paths[] = {
    "/var/log/syslog",
    "/var/log/messages",
    NULL
};
#endif

/* Portable UTC epoch from a broken-down date. mktime() assumes local time and
 * timegm()/the `timezone` global are not in C99/-pedantic, so we compute the
 * day count from the civil date directly (Howard Hinnant's days_from_civil).
 * Fields are taken raw: y is full year, m is 1..12, d is 1..31. */
static time_t utc_from_civil(int y, int m, int d, int hh, int mm, int ss)
{
    long era, yoe, doy, doe, days;

    y -= (m <= 2);
    era = (long)(y >= 0 ? y : y - 399) / 400;
    yoe = (long)(y - era * 400);              /* [0, 399] */
    doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;  /* [0, 365] */
    doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;           /* [0, 146096] */
    days = era * 146097 + doe - 719468;       /* days since 1970-01-01 */

    return (time_t)(days * 86400L + hh * 3600L + mm * 60L + ss);
}

/* Try to parse an ISO-8601 timestamp at the start of the line:
 * "YYYY-MM-DD" with 'T' or ' ' then "HH:MM:SS", optional ".frac",
 * optional timezone ('Z' or +HH:MM / -HH:MM). Returns epoch seconds, or 0 if
 * the line does not begin with an ISO-8601 date. */
static time_t parse_iso8601_time(const char *line)
{
    int y, mo, d, hh, mm, ss, n;
    char sep;
    const char *p;
    time_t epoch;

    n = 0;
    if (sscanf(line, "%4d-%2d-%2d%c%2d:%2d:%2d%n",
               &y, &mo, &d, &sep, &hh, &mm, &ss, &n) != 7)
        return 0;
    if (sep != 'T' && sep != ' ') return 0;
    if (mo < 1 || mo > 12 || d < 1 || d > 31) return 0;

    epoch = utc_from_civil(y, mo, d, hh, mm, ss);

    /* Skip optional fractional seconds (already past HH:MM:SS via %n). */
    p = line + n;
    if (*p == '.') {
        p++;
        while (*p >= '0' && *p <= '9') p++;
    }

    /* Optional timezone. Absence means local time: re-interpret via mktime so
     * we honor the host TZ for naive timestamps. */
    if (*p == 'Z') {
        return epoch;  /* already UTC */
    } else if (*p == '+' || *p == '-') {
        int oh = 0, om = 0;
        int sign = (*p == '-') ? -1 : 1;
        if (sscanf(p + 1, "%2d:%2d", &oh, &om) >= 1)
            epoch -= sign * (oh * 3600L + om * 60L);
        return epoch;
    } else {
        struct tm tm;
        memset(&tm, 0, sizeof(tm));
        tm.tm_year = y - 1900;
        tm.tm_mon = mo - 1;
        tm.tm_mday = d;
        tm.tm_hour = hh;
        tm.tm_min = mm;
        tm.tm_sec = ss;
        tm.tm_isdst = -1;
        return mktime(&tm);
    }
}

/* Parse syslog timestamp from start of line. Recognizes ISO-8601 (modern
 * Debian/Ubuntu syslog, journald short-iso) first, falling back to legacy
 * "Mon DD HH:MM:SS" (no year — assumes current year). Returns 0 on failure;
 * filter_match_time() treats 0 as "unknown" and passes the line. */
static time_t parse_syslog_time(const char *line)
{
    struct tm tm;
    static const char *months[] = {
        "Jan","Feb","Mar","Apr","May","Jun",
        "Jul","Aug","Sep","Oct","Nov","Dec"
    };
    char mon[4];
    int i;
    time_t now, iso;
    struct tm *now_tm;

    iso = parse_iso8601_time(line);
    if (iso != 0) return iso;

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

    /* Syslog doesn't include year — assume current year */
    now = time(NULL);
    now_tm = localtime(&now);
    tm.tm_year = now_tm->tm_year;
    tm.tm_isdst = -1;

    return mktime(&tm);
}

/* Parse syslog severity from the facility.severity in <PRI> field if present */
static int parse_syslog_severity(const char *line)
{
    int pri;
    if (line[0] == '<' && sscanf(line, "<%d>", &pri) == 1)
        return pri & 0x07;  /* severity = low 3 bits */
    return -1;  /* unknown */
}

/* Per-source forensic-honesty counters, reported up so the run function can
 * warn the operator once that a requested filter could not be fully applied. */
typedef struct {
    long lines_seen;        /* total lines read from the source */
    long no_timestamp;      /* lines whose timestamp could not be parsed */
    long with_severity;     /* lines that carried a parseable <PRI> severity */
} source_stats_t;

static long collect_text_file(const char *path, const filter_config_t *filter,
                              FILE *out, source_stats_t *stats)
{
    FILE *in;
    char line[MAX_LINE_LEN];
    long count = 0;
    time_t t;
    int sev;

    in = fopen(path, "r");
    if (!in) return -1;

    while (fgets(line, sizeof(line), in)) {
        stats->lines_seen++;

        t = parse_syslog_time(line);
        if (t == 0) stats->no_timestamp++;
        if (!filter_match_time(filter, t)) continue;

        sev = parse_syslog_severity(line);
        if (sev >= 0) stats->with_severity++;
        if (sev >= 0 && !filter_match_severity(filter, sev)) continue;

        if (!filter_match_line(filter, line)) continue;

        fputs(line, out);
        count++;
    }

    fclose(in);
    return count;
}

int collect_syslog_init(collector_t *self, const filter_config_t *filter,
                        const char *output_dir)
{
    char subdir[MAX_PATH_LEN];
    int found = 0;
    int i;

    self->filter = filter;
    plat_path_join(self->out_path, sizeof(self->out_path), output_dir, self->subdir);

    /* Check if at least one source exists */
    for (i = 0; syslog_paths[i]; i++) {
        if (plat_file_exists(syslog_paths[i])) {
            found = 1;
            break;
        }
    }

#ifdef __APPLE__
    /* macOS Unified Logging is always available on 10.12+ */
    if (plat_file_exists("/usr/bin/log")) found = 1;
#else
    /* Volatile journal lives at /run/log/journal; persistent storage (most
     * servers) at /var/log/journal. The presence of journalctl alone also
     * means we can query the running journal via its socket. */
    if (plat_is_directory("/run/log/journal") ||
        plat_is_directory("/var/log/journal") ||
        plat_file_exists("/usr/bin/journalctl") ||
        plat_file_exists("/bin/journalctl"))
        found = 1;
#endif

    if (!found) {
        self->status = 2;
        snprintf(self->status_msg, sizeof(self->status_msg), "no syslog sources found");
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

/* Helper: build a macOS 'log show' or Linux 'journalctl' command with time filters.
 * If no time range is specified on macOS, defaults to --last 1d to avoid
 * scanning the entire Unified Logging store (which can take minutes). */
static int build_log_command(char *cmd, size_t cmdsz, const filter_config_t *filter,
                             const char *base_cmd, const char *start_flag,
                             const char *end_flag)
{
    int has_time = 0;

    snprintf(cmd, cmdsz, "%s", base_cmd);

    if (filter->time_start) {
        char ts[32];
        plat_format_timestamp(filter->time_start, ts, sizeof(ts));
        if (str_is_shell_safe(ts)) {
            snprintf(cmd + strlen(cmd), cmdsz - strlen(cmd),
                     " %s '%s'", start_flag, ts);
            has_time = 1;
        }
    }
    if (filter->time_end) {
        char ts[32];
        plat_format_timestamp(filter->time_end, ts, sizeof(ts));
        if (str_is_shell_safe(ts)) {
            snprintf(cmd + strlen(cmd), cmdsz - strlen(cmd),
                     " %s '%s'", end_flag, ts);
            has_time = 1;
        }
    }

#ifdef __APPLE__
    /* Default to last 24h if no time range specified, to avoid full store scan */
    if (!has_time) {
        snprintf(cmd + strlen(cmd), cmdsz - strlen(cmd), " --last 1d");
    }
#else
    (void)has_time;
#endif

    return 0;
}

/* Count lines in a file, optionally applying keyword filter */
static long count_filtered_lines(const char *path, const filter_config_t *filter)
{
    FILE *f = fopen(path, "r");
    char line[MAX_LINE_LEN];
    long count = 0;

    if (!f) return 0;

    while (fgets(line, sizeof(line), f)) {
        if (filter->keyword[0] && !str_contains(line, filter->keyword))
            continue;
        if (filter->username[0] && !str_contains(line, filter->username))
            continue;
        count++;
    }
    fclose(f);
    return count;
}

int collect_syslog_run(collector_t *self)
{
    int i;
    long total = 0;
    char out_file[MAX_PATH_LEN];
    FILE *out;
    const filter_config_t *filter = self->filter;
    int time_filter_active =
        (filter->time_start != 0 || filter->time_end != 0);
    int sev_filter_active =
        (filter->severity_min != -1 || filter->severity_max != -1);

    /* Collect text-based syslog files */
    for (i = 0; syslog_paths[i]; i++) {
        source_stats_t stats;

        if (!plat_file_exists(syslog_paths[i])) continue;

        memset(&stats, 0, sizeof(stats));

        /* Name output file after source */
        {
            const char *basename = strrchr(syslog_paths[i], '/');
            basename = basename ? basename + 1 : syslog_paths[i];
            plat_path_join(out_file, sizeof(out_file), self->out_path, basename);
        }

        out = fopen(out_file, "w");
        if (!out) {
            log_warn("syslog: cannot write to %s", out_file);
            continue;
        }

        {
            long n = collect_text_file(syslog_paths[i], self->filter, out,
                                       &stats);
            fclose(out);
            if (n < 0) {
                log_warn("syslog: cannot read %s (permission denied?)",
                         syslog_paths[i]);
                self->status = 1;
                snprintf(self->status_msg, sizeof(self->status_msg),
                         "partial: could not read %s", syslog_paths[i]);
            } else {
                total += n;
                log_verbose("syslog: %ld lines from %s", n, syslog_paths[i]);

                /* Forensic honesty: warn once per source when a requested
                 * filter could not actually be applied, so the operator knows
                 * the result is unfiltered rather than trusting it silently. */
                if (time_filter_active && stats.no_timestamp > 0) {
                    log_warn("syslog: time filter could not be applied to %ld "
                             "line(s) in %s (unparseable timestamp; kept)",
                             stats.no_timestamp, syslog_paths[i]);
                }
                if (sev_filter_active && stats.lines_seen > 0 &&
                    stats.with_severity == 0) {
                    log_warn("syslog: --level-min/--level-max could not be "
                             "applied to text source %s (no <PRI> severity; "
                             "only journald/PRI-tagged sources support it)",
                             syslog_paths[i]);
                }
            }
        }
    }

#ifdef __APPLE__
    /* macOS Unified Logging via 'log show' */
    if (plat_file_exists("/usr/bin/log")) {
        char cmd[MAX_PATH_LEN * 2];
        char unified_out[MAX_PATH_LEN];
        int ret;
        long n;

        plat_path_join(unified_out, sizeof(unified_out), self->out_path,
                       "unified.log");

        build_log_command(cmd, sizeof(cmd), self->filter,
                          "log show --style compact --info",
                          "--start", "--end");

        log_verbose("syslog: running %s", cmd);
        ret = plat_exec_capture(cmd, unified_out);
        if (ret != 0) {
            log_verbose("syslog: log show returned %d", ret);
        } else {
            n = count_filtered_lines(unified_out, self->filter);
            total += n;
            log_verbose("syslog: %ld lines from Unified Logging", n);
        }
    }
#else
    /* Linux: try journalctl if systemd journal is available. Persistent
     * storage lives at /var/log/journal, volatile at /run/log/journal, and the
     * journalctl binary alone can query the running journal via its socket. */
    if (plat_is_directory("/run/log/journal") ||
        plat_is_directory("/var/log/journal") ||
        plat_file_exists("/usr/bin/journalctl") ||
        plat_file_exists("/bin/journalctl")) {
        char cmd[MAX_PATH_LEN * 2];
        char journal_out[MAX_PATH_LEN];
        int ret;
        long n;

        plat_path_join(journal_out, sizeof(journal_out), self->out_path,
                       "journald.log");

        build_log_command(cmd, sizeof(cmd), self->filter,
                          "journalctl --no-pager -o short-iso",
                          "--since", "--until");

        if (self->filter->username[0]) {
            if (str_is_shell_safe(self->filter->username)) {
                snprintf(cmd + strlen(cmd), sizeof(cmd) - strlen(cmd),
                         " _COMM='%s'", self->filter->username);
            } else {
                log_warn("syslog: username contains unsafe characters, "
                         "skipping journalctl user filter");
            }
        }

        log_verbose("syslog: running %s", cmd);
        ret = plat_exec_capture(cmd, journal_out);
        if (ret != 0) {
            log_verbose("syslog: journalctl returned %d", ret);
        } else {
            n = count_filtered_lines(journal_out, self->filter);
            total += n;
            log_verbose("syslog: %ld lines from journald", n);
        }
    }
#endif

    self->lines_collected = total;
    if (total == 0) {
        self->status = 2;
        snprintf(self->status_msg, sizeof(self->status_msg), "no matching entries");
    }

    return 0;
}

void collect_syslog_cleanup(collector_t *self)
{
    (void)self;
}

#endif /* !_WIN32 */
