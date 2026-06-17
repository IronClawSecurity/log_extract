#include "log_extract.h"
#include "collectors/auth.h"

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

/* Portable UTC epoch from a broken-down UTC time. timegm() is not in c99,
 * so compute days-since-epoch by hand (proleptic Gregorian, fields normalized
 * by the caller's ranges; year/mon/mday/h/m/s only). */
static time_t tm_to_utc(const struct tm *tm)
{
    static const int mdays[] = {31,28,31,30,31,30,31,31,30,31,30,31};
    int year = tm->tm_year + 1900;
    int mon = tm->tm_mon;
    long days = 0;
    int y, m;

    for (y = 1970; y < year; y++)
        days += (((y % 4 == 0 && y % 100 != 0) || y % 400 == 0) ? 366 : 365);
    for (m = 0; m < mon; m++) {
        days += mdays[m];
        if (m == 1 && ((year % 4 == 0 && year % 100 != 0) || year % 400 == 0))
            days += 1;
    }
    days += tm->tm_mday - 1;

    return (time_t)days * 86400 + tm->tm_hour * 3600
           + tm->tm_min * 60 + tm->tm_sec;
}

/* ISO-8601 at line start: "YYYY-MM-DD[ T]HH:MM:SS[.frac][Z|+/-HH:MM]".
 * Returns UTC epoch honoring an explicit offset, or 0 if not ISO-8601. */
static time_t parse_auth_time_iso(const char *line)
{
    struct tm tm;
    int year, mon, mday, hour, min, sec, consumed;
    time_t t;

    memset(&tm, 0, sizeof(tm));
    consumed = 0;
    /* Accept either 'T' or space between date and time. */
    if (sscanf(line, "%4d-%2d-%2d%*1[T ]%2d:%2d:%2d%n",
               &year, &mon, &mday, &hour, &min, &sec, &consumed) != 6)
        return 0;
    if (consumed <= 0) return 0;
    if (mon < 1 || mon > 12 || mday < 1 || mday > 31) return 0;

    tm.tm_year = year - 1900;
    tm.tm_mon = mon - 1;
    tm.tm_mday = mday;
    tm.tm_hour = hour;
    tm.tm_min = min;
    tm.tm_sec = sec;

    t = tm_to_utc(&tm);

    /* Skip optional fractional seconds. */
    {
        const char *p = line + consumed;
        if (*p == '.') {
            p++;
            while (*p >= '0' && *p <= '9') p++;
        }
        /* Honor explicit zone: 'Z' = UTC, +/-HH:MM = offset to subtract. */
        if (*p == '+' || *p == '-') {
            int sign = (*p == '+') ? 1 : -1;
            int oh = 0, om = 0;
            if (sscanf(p + 1, "%2d:%2d", &oh, &om) >= 1)
                t -= (time_t)sign * (oh * 3600 + om * 60);
        }
        /* 'Z' or no zone: treat as already-UTC; nothing to adjust. */
    }

    return t;
}

/* Parse a timestamp from an auth log line. Tries ISO-8601 first, then the
 * legacy syslog "Mon DD HH:MM:SS" (no year, assumes current local year). */
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
    time_t iso;

    iso = parse_auth_time_iso(line);
    if (iso) return iso;

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

#include <windows.h>
#include <winevt.h>

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

/* Build XPath selecting logon-related Security EventIDs, AND-ing in absolute
 * TimeCreated bounds when set. EventLog SystemTime is UTC, so gmtime is correct. */
static void build_auth_xpath(wchar_t *buf, size_t bufsz,
                             const filter_config_t *filter)
{
    wchar_t time_clause[512] = {0};
    static const wchar_t *id_clause =
        L"(EventID=4624 or EventID=4625 or EventID=4634 "
        L"or EventID=4647 or EventID=4648)";

    if (filter->time_start) {
        struct tm *tm = gmtime(&filter->time_start);
        if (tm) {
            _snwprintf(time_clause + wcslen(time_clause),
                512 - wcslen(time_clause),
                L"%lsTimeCreated[@SystemTime>='%04d-%02d-%02dT%02d:%02d:%02d.000Z']",
                time_clause[0] ? L" and " : L"",
                tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
                tm->tm_hour, tm->tm_min, tm->tm_sec);
            /* MinGW _snwprintf may not NUL-terminate; the next wcslen relies on it. */
            time_clause[(sizeof(time_clause)/sizeof(time_clause[0])) - 1] = L'\0';
        }
    }
    if (filter->time_end) {
        struct tm *tm = gmtime(&filter->time_end);
        if (tm) {
            _snwprintf(time_clause + wcslen(time_clause),
                512 - wcslen(time_clause),
                L"%lsTimeCreated[@SystemTime<='%04d-%02d-%02dT%02d:%02d:%02d.000Z']",
                time_clause[0] ? L" and " : L"",
                tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
                tm->tm_hour, tm->tm_min, tm->tm_sec);
            time_clause[(sizeof(time_clause)/sizeof(time_clause[0])) - 1] = L'\0';
        }
    }

    if (time_clause[0])
        _snwprintf(buf, bufsz, L"*[System[%ls and %ls]]", id_clause, time_clause);
    else
        _snwprintf(buf, bufsz, L"*[System[%ls]]", id_clause);
    if (bufsz) buf[bufsz - 1] = L'\0';
}

/* Match TargetUserName/SubjectUserName in rendered event XML (mirrors
 * event_matches_user in collect_eventlog.c). */
static int auth_event_matches_user(const wchar_t *xml, const char *username)
{
    wchar_t wuser[128];
    wchar_t pattern1[256], pattern2[256];

    if (!username || !username[0]) return 1;

    /* MultiByteToWideChar leaves the buffer unterminated when the source
     * overflows it; force termination before any wcsstr/%ls read. */
    MultiByteToWideChar(CP_UTF8, 0, username, -1, wuser, 128);
    wuser[(sizeof(wuser)/sizeof(wuser[0])) - 1] = L'\0';

    _snwprintf(pattern1, 255, L"TargetUserName'>%ls</Data", wuser);
    pattern1[(sizeof(pattern1)/sizeof(pattern1[0])) - 1] = L'\0';
    _snwprintf(pattern2, 255, L"SubjectUserName'>%ls</Data", wuser);
    pattern2[(sizeof(pattern2)/sizeof(pattern2[0])) - 1] = L'\0';

    return wcsstr(xml, pattern1) != NULL || wcsstr(xml, pattern2) != NULL;
}

static int auth_event_matches_keyword(const wchar_t *xml, const char *keyword)
{
    wchar_t wkw[256];

    if (!keyword || !keyword[0]) return 1;

    MultiByteToWideChar(CP_UTF8, 0, keyword, -1, wkw, 256);
    wkw[(sizeof(wkw)/sizeof(wkw[0])) - 1] = L'\0';
    return wcsstr(xml, wkw) != NULL;
}

/* Returns count of written events, or -1 on query failure. On
 * ERROR_ACCESS_DENIED / ERROR_EVT_CHANNEL_NOT_FOUND sets *err for the caller. */
static long query_security_auth(const filter_config_t *filter, FILE *out,
                                DWORD *err_out)
{
    wchar_t xpath[1024];
    EVT_HANDLE hResults;
    EVT_HANDLE events[100];
    DWORD returned, i;
    long count = 0;
    wchar_t *rendered = NULL;
    DWORD rendered_sz = 0;
    DWORD buf_used, prop_count;

    *err_out = ERROR_SUCCESS;
    build_auth_xpath(xpath, 1024, filter);

    hResults = EvtQuery(NULL, L"Security", xpath,
                        EvtQueryChannelPath | EvtQueryForwardDirection);
    if (!hResults) {
        *err_out = GetLastError();
        return -1;
    }

    while (EvtNext(hResults, 100, events, INFINITE, 0, &returned)) {
        for (i = 0; i < returned; i++) {
            if (!EvtRender(NULL, events[i], EvtRenderEventXml,
                           rendered_sz, rendered, &buf_used, &prop_count)) {
                if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                    rendered_sz = buf_used;
                    rendered = (wchar_t *)safe_realloc(rendered, rendered_sz);
                    EvtRender(NULL, events[i], EvtRenderEventXml,
                              rendered_sz, rendered, &buf_used, &prop_count);
                } else {
                    EvtClose(events[i]);
                    continue;
                }
            }

            if (!auth_event_matches_user(rendered, filter->username)) {
                EvtClose(events[i]);
                continue;
            }
            if (!auth_event_matches_keyword(rendered, filter->keyword)) {
                EvtClose(events[i]);
                continue;
            }

            {
                int utf8_len = WideCharToMultiByte(CP_UTF8, 0, rendered, -1,
                                                   NULL, 0, NULL, NULL);
                if (utf8_len > 0) {
                    char *utf8 = (char *)safe_malloc(utf8_len);
                    WideCharToMultiByte(CP_UTF8, 0, rendered, -1,
                                        utf8, utf8_len, NULL, NULL);
                    fputs(utf8, out);
                    fputs("\n", out);
                    free(utf8);
                    count++;
                }
            }

            EvtClose(events[i]);
        }
    }

    free(rendered);
    EvtClose(hResults);
    return count;
}

int collect_auth_run(collector_t *self)
{
    char out_file[MAX_PATH_LEN];
    FILE *out;
    long n;
    DWORD err = ERROR_SUCCESS;

    plat_path_join(out_file, sizeof(out_file), self->out_path, "security_auth.xml");

    out = fopen(out_file, "w");
    if (!out) {
        self->status = 3;
        snprintf(self->status_msg, sizeof(self->status_msg),
                 "cannot write to %.200s", out_file);
        return 0;
    }

    fprintf(out, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Events>\n");
    n = query_security_auth(self->filter, out, &err);
    fprintf(out, "</Events>\n");
    fclose(out);

    if (n < 0) {
        if (err == ERROR_ACCESS_DENIED) {
            log_warn("auth: access denied to Security channel "
                     "(run as Administrator)");
            self->status = 1;
            snprintf(self->status_msg, sizeof(self->status_msg),
                     "partial: Security channel access denied "
                     "(run as Administrator)");
        } else if (err == ERROR_EVT_CHANNEL_NOT_FOUND) {
            log_warn("auth: Security event log channel not found");
            self->status = 2;
            snprintf(self->status_msg, sizeof(self->status_msg),
                     "Security channel not found");
        } else {
            log_warn("auth: failed to query Security channel (error %lu)",
                     (unsigned long)err);
            self->status = 1;
            snprintf(self->status_msg, sizeof(self->status_msg),
                     "partial: could not query Security channel");
        }
        return 0;
    }

    self->lines_collected = n;
    log_verbose("auth: %ld logon events from Security channel", n);

    if (n == 0 && self->status == 0) {
        self->status = 2;
        snprintf(self->status_msg, sizeof(self->status_msg),
                 "no matching logon events");
    }

    return 0;
}

void collect_auth_cleanup(collector_t *self)
{
    (void)self;
}

#endif /* _WIN32 */
