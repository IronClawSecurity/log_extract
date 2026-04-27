#ifndef _WIN32

#include "log_extract.h"
#include "collectors/syslog.h"

static const char *syslog_paths[] = {
    "/var/log/syslog",
    "/var/log/messages",
    NULL
};

/* Parse syslog timestamp: "Mon DD HH:MM:SS" from start of line */
static time_t parse_syslog_time(const char *line)
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

static long collect_text_file(const char *path, const filter_config_t *filter,
                              FILE *out)
{
    FILE *in;
    char line[MAX_LINE_LEN];
    long count = 0;
    time_t t;
    int sev;

    in = fopen(path, "r");
    if (!in) return -1;

    while (fgets(line, sizeof(line), in)) {
        t = parse_syslog_time(line);
        if (!filter_match_time(filter, t)) continue;

        sev = parse_syslog_severity(line);
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

    self->filter = filter;
    plat_path_join(self->out_path, sizeof(self->out_path), output_dir, self->subdir);

    /* Check if at least one source exists */
    if (!plat_file_exists("/var/log/syslog") &&
        !plat_file_exists("/var/log/messages") &&
        !plat_is_directory("/run/log/journal")) {
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

int collect_syslog_run(collector_t *self)
{
    int i;
    long total = 0;
    char out_file[MAX_PATH_LEN];
    FILE *out;

    /* Collect text-based syslog files */
    for (i = 0; syslog_paths[i]; i++) {
        if (!plat_file_exists(syslog_paths[i])) continue;

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
            long n = collect_text_file(syslog_paths[i], self->filter, out);
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
            }
        }
    }

    /* Try journalctl if available */
    if (plat_is_directory("/run/log/journal")) {
        char cmd[MAX_PATH_LEN];
        char journal_out[MAX_PATH_LEN];
        int ret;

        plat_path_join(journal_out, sizeof(journal_out), self->out_path,
                       "journald.log");

        snprintf(cmd, sizeof(cmd), "journalctl --no-pager -o short-iso");

        if (self->filter->time_start) {
            char ts[32];
            plat_format_timestamp(self->filter->time_start, ts, sizeof(ts));
            snprintf(cmd + strlen(cmd), sizeof(cmd) - strlen(cmd),
                     " --since \"%s\"", ts);
        }
        if (self->filter->time_end) {
            char ts[32];
            plat_format_timestamp(self->filter->time_end, ts, sizeof(ts));
            snprintf(cmd + strlen(cmd), sizeof(cmd) - strlen(cmd),
                     " --until \"%s\"", ts);
        }
        if (self->filter->username[0]) {
            snprintf(cmd + strlen(cmd), sizeof(cmd) - strlen(cmd),
                     " _COMM=%s", self->filter->username);
        }

        log_verbose("syslog: running %s", cmd);
        ret = plat_exec_capture(cmd, journal_out);
        if (ret != 0) {
            log_verbose("syslog: journalctl returned %d", ret);
        } else {
            /* Count lines in output */
            FILE *f = fopen(journal_out, "r");
            if (f) {
                char line[MAX_LINE_LEN];
                long jcount = 0;
                while (fgets(line, sizeof(line), f)) {
                    if (self->filter->keyword[0] &&
                        !str_contains(line, self->filter->keyword))
                        continue;
                    jcount++;
                }
                fclose(f);
                total += jcount;
                log_verbose("syslog: %ld lines from journald", jcount);
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

void collect_syslog_cleanup(collector_t *self)
{
    (void)self;
}

#endif /* !_WIN32 */
