#include "log_extract.h"
#include "collectors/filemon.h"

#ifndef _WIN32

#ifndef __APPLE__
#include <pwd.h>
#endif

#ifdef __APPLE__
static const char *audit_dir = "/var/audit";
#else
static const char *audit_path = "/var/log/audit/audit.log";
#endif

#ifndef __APPLE__
/* Linux: parse auditd timestamp from: type=X msg=audit(EPOCH.MS:SERIAL): ... */
static time_t parse_audit_time(const char *line)
{
    const char *p = strstr(line, "audit(");
    double ts;
    if (!p) return 0;
    p += 6;
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
#endif /* !__APPLE__ */

int collect_filemon_init(collector_t *self, const filter_config_t *filter,
                         const char *output_dir)
{
    self->filter = filter;
    plat_path_join(self->out_path, sizeof(self->out_path), output_dir, self->subdir);

#ifdef __APPLE__
    if (!plat_is_directory(audit_dir) && !plat_file_exists("/usr/bin/log")) {
        self->status = 2;
        snprintf(self->status_msg, sizeof(self->status_msg),
                 "no audit sources found (need /var/audit/ or Unified Logging)");
        return -1;
    }
#else
    if (!plat_file_exists(audit_path)) {
        self->status = 2;
        snprintf(self->status_msg, sizeof(self->status_msg),
                 "auditd log not found (%s)", audit_path);
        return -1;
    }
#endif

    if (plat_mkdir_p(self->out_path) != 0) {
        self->status = 3;
        snprintf(self->status_msg, sizeof(self->status_msg), "cannot create output dir");
        return -1;
    }

    return 0;
}

int collect_filemon_run(collector_t *self)
{
    long total = 0;

#ifdef __APPLE__
    /* macOS: use praudit to parse OpenBSM audit trails */
    if (plat_is_directory(audit_dir)) {
        char cmd[MAX_PATH_LEN * 2];
        char out_file[MAX_PATH_LEN];
        int ret;

        plat_path_join(out_file, sizeof(out_file), self->out_path, "openbsm_audit.txt");

        snprintf(cmd, sizeof(cmd), "praudit -l /var/audit/* 2>/dev/null");

        log_verbose("filemon: running %s", cmd);
        ret = plat_exec_capture(cmd, out_file);

        if (ret == 0 || plat_file_exists(out_file)) {
            /* Post-filter the output */
            FILE *in = fopen(out_file, "r");
            if (in) {
                char filtered_path[MAX_PATH_LEN];
                FILE *filtered;
                char line[MAX_LINE_LEN];
                long n = 0;

                plat_path_join(filtered_path, sizeof(filtered_path),
                               self->out_path, "audit_filtered.txt");
                filtered = fopen(filtered_path, "w");

                if (filtered) {
                    while (fgets(line, sizeof(line), in)) {
                        /* Only file-related events */
                        if (!str_contains(line, "open") &&
                            !str_contains(line, "unlink") &&
                            !str_contains(line, "rename") &&
                            !str_contains(line, "chmod") &&
                            !str_contains(line, "chown") &&
                            !str_contains(line, "write") &&
                            !str_contains(line, "create"))
                            continue;

                        if (!filter_match_line(self->filter, line)) continue;

                        fputs(line, filtered);
                        n++;
                    }
                    fclose(filtered);
                }
                fclose(in);

                /* Remove the unfiltered raw dump, keep filtered version */
                remove(out_file);

                total += n;
                log_verbose("filemon: %ld entries from OpenBSM audit", n);
            }
        } else {
            log_warn("filemon: praudit failed (permission denied?)");
            self->status = 1;
            snprintf(self->status_msg, sizeof(self->status_msg),
                     "partial: praudit failed");
        }
    }

    /* macOS: Unified Logging for file events */
    if (plat_file_exists("/usr/bin/log")) {
        char cmd[MAX_PATH_LEN * 2];
        char out_file[MAX_PATH_LEN];
        int ret;

        plat_path_join(out_file, sizeof(out_file), self->out_path,
                       "filemon_unified.log");

        snprintf(cmd, sizeof(cmd),
                 "log show --style compact --predicate "
                 "'process == \"kernel\" AND (eventMessage CONTAINS \"open\" "
                 "OR eventMessage CONTAINS \"unlink\" "
                 "OR eventMessage CONTAINS \"rename\")'");

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

        log_verbose("filemon: running %s", cmd);
        ret = plat_exec_capture(cmd, out_file);
        if (ret == 0) {
            FILE *f = fopen(out_file, "r");
            if (f) {
                char line[MAX_LINE_LEN];
                long n = 0;
                while (fgets(line, sizeof(line), f)) {
                    if (self->filter->username[0] &&
                        !str_contains(line, self->filter->username))
                        continue;
                    n++;
                }
                fclose(f);
                total += n;
                log_verbose("filemon: %ld lines from Unified Logging", n);
            }
        }
    }

#else /* Linux */

    {
        FILE *in, *out;
        char line[MAX_LINE_LEN];
        char out_file[MAX_PATH_LEN];
        char uid_str[32] = {0};
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
                         "will fall back to string matching",
                         self->filter->username);
            }
        }

        in = fopen(audit_path, "r");
        if (!in) {
            self->status = 1;
            snprintf(self->status_msg, sizeof(self->status_msg),
                     "permission denied: %s", audit_path);
            goto done;
        }

        plat_path_join(out_file, sizeof(out_file), self->out_path, "audit.log");
        out = fopen(out_file, "w");
        if (!out) {
            fclose(in);
            self->status = 3;
            snprintf(self->status_msg, sizeof(self->status_msg),
                     "cannot write output file");
            goto done;
        }

        while (fgets(line, sizeof(line), in)) {
            if (!is_file_audit_event(line)) continue;

            t = parse_audit_time(line);
            if (!filter_match_time(self->filter, t)) continue;

            if (uid_str[0] && !audit_matches_uid(line, uid_str)) continue;

            if (!filter_match_keyword(self->filter, line)) continue;

            fputs(line, out);
            total++;
        }

        fclose(in);
        fclose(out);
    }

done:

#endif /* __APPLE__ / Linux */

    self->lines_collected = total;
    if (total == 0 && self->status == 0) {
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

#include <windows.h>
#include <winevt.h>

/* File-access audit EventIDs: 4663=access attempt, 4656=handle requested,
 * 4660=object deleted, 4670=permissions changed. These live in Security. */
static void build_fileaudit_xpath(wchar_t *buf, size_t bufsz,
                                  const filter_config_t *filter)
{
    wchar_t time_clause[512] = {0};

    if (filter->time_start) {
        struct tm *tm = gmtime(&filter->time_start);
        if (tm) {
            _snwprintf(time_clause, 255,
                L"TimeCreated[@SystemTime>='%04d-%02d-%02dT%02d:%02d:%02d.000Z']",
                tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
                tm->tm_hour, tm->tm_min, tm->tm_sec);
            /* MinGW _snwprintf may not NUL-terminate; wcscat/[0] read this. */
            time_clause[(sizeof(time_clause)/sizeof(time_clause[0])) - 1] = L'\0';
        }
    }
    if (filter->time_end) {
        struct tm *tm = gmtime(&filter->time_end);
        if (tm) {
            wchar_t end_clause[256];
            _snwprintf(end_clause, 255,
                L"TimeCreated[@SystemTime<='%04d-%02d-%02dT%02d:%02d:%02d.000Z']",
                tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
                tm->tm_hour, tm->tm_min, tm->tm_sec);
            end_clause[(sizeof(end_clause)/sizeof(end_clause[0])) - 1] = L'\0';
            if (time_clause[0]) {
                wcscat(time_clause, L" and ");
                wcscat(time_clause, end_clause);
            } else {
                wcscpy(time_clause, end_clause);
            }
        }
    }

    if (time_clause[0]) {
        _snwprintf(buf, bufsz,
            L"*[System[(EventID=4663 or EventID=4656 or EventID=4660 or "
            L"EventID=4670) and %ls]]", time_clause);
    } else {
        _snwprintf(buf, bufsz,
            L"*[System[(EventID=4663 or EventID=4656 or EventID=4660 or "
            L"EventID=4670)]]");
    }
    if (bufsz) buf[bufsz - 1] = L'\0';
}

/* --user matches the actor on the audited handle via SubjectUserName. */
static int event_matches_user(const wchar_t *xml, const char *username)
{
    wchar_t wuser[128];
    wchar_t pattern[256];

    if (!username || !username[0]) return 1;

    /* MultiByteToWideChar leaves the buffer unterminated when the source
     * overflows it; force termination before any wcsstr/%ls read. */
    MultiByteToWideChar(CP_UTF8, 0, username, -1, wuser, 128);
    wuser[(sizeof(wuser)/sizeof(wuser[0])) - 1] = L'\0';
    _snwprintf(pattern, 255, L"SubjectUserName'>%ls</Data", wuser);
    pattern[(sizeof(pattern)/sizeof(pattern[0])) - 1] = L'\0';

    return wcsstr(xml, pattern) != NULL;
}

static int event_matches_keyword(const wchar_t *xml, const char *keyword)
{
    wchar_t wkw[256];

    if (!keyword || !keyword[0]) return 1;

    MultiByteToWideChar(CP_UTF8, 0, keyword, -1, wkw, 256);
    wkw[(sizeof(wkw)/sizeof(wkw[0])) - 1] = L'\0';
    return wcsstr(xml, wkw) != NULL;
}

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
    long total = 0;
    wchar_t xpath[1024];
    EVT_HANDLE hResults;
    EVT_HANDLE events[100];
    DWORD returned, i;
    wchar_t *rendered = NULL;
    DWORD rendered_sz = 0;
    DWORD buf_used, prop_count;
    char out_file[MAX_PATH_LEN];
    FILE *out;

    build_fileaudit_xpath(xpath, 1024, self->filter);

    hResults = EvtQuery(NULL, L"Security", xpath,
                        EvtQueryChannelPath | EvtQueryForwardDirection);
    if (!hResults) {
        DWORD err = GetLastError();
        if (err == ERROR_EVT_CHANNEL_NOT_FOUND) {
            self->status = 2;
            snprintf(self->status_msg, sizeof(self->status_msg),
                     "Security channel not found");
        } else if (err == ERROR_ACCESS_DENIED) {
            log_warn("filemon: access denied (run as Administrator; file-access "
                     "auditing must be enabled via audit policy)");
            self->status = 1;
            snprintf(self->status_msg, sizeof(self->status_msg),
                     "access denied: run as Administrator and enable file-access "
                     "audit policy");
        } else {
            self->status = 3;
            snprintf(self->status_msg, sizeof(self->status_msg),
                     "EvtQuery failed (error %lu)", (unsigned long)err);
        }
        return 0;
    }

    plat_path_join(out_file, sizeof(out_file), self->out_path,
                   "security_fileaudit.xml");
    out = fopen(out_file, "w");
    if (!out) {
        EvtClose(hResults);
        self->status = 3;
        snprintf(self->status_msg, sizeof(self->status_msg),
                 "cannot write output file");
        return 0;
    }

    fprintf(out, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Events>\n");

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

            if (!event_matches_user(rendered, self->filter->username)) {
                EvtClose(events[i]);
                continue;
            }
            if (!event_matches_keyword(rendered, self->filter->keyword)) {
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
                    total++;
                }
            }

            EvtClose(events[i]);
        }
    }

    fprintf(out, "</Events>\n");
    fclose(out);
    free(rendered);
    EvtClose(hResults);

    self->lines_collected = total;
    if (total == 0 && self->status == 0) {
        self->status = 2;
        snprintf(self->status_msg, sizeof(self->status_msg), "no matching events");
    }

    return 0;
}

void collect_filemon_cleanup(collector_t *self)
{
    (void)self;
}

#endif /* _WIN32 */
