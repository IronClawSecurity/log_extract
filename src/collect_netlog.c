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

#include <windows.h>
#include <winevt.h>

/* Windows Firewall text log; copied/filtered line-by-line like Linux/macOS paths */
#define WIN_FIREWALL_LOG "C:\\Windows\\System32\\LogFiles\\Firewall\\pfirewall.log"

/* Firewall event channel queried via the Evt* API (mirrors collect_eventlog.c) */
static const wchar_t *firewall_channel =
    L"Microsoft-Windows-Windows Firewall With Advanced Security/Firewall";

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

/* Emit both SystemTime>= (time_start) and SystemTime<= (time_end) bounds. */
static void build_firewall_xpath(wchar_t *buf, size_t bufsz,
                                 const filter_config_t *filter)
{
    wchar_t start_clause[256] = {0};
    wchar_t end_clause[256] = {0};

    if (filter->time_start) {
        struct tm *tm = gmtime(&filter->time_start);
        if (tm) {
            _snwprintf(start_clause, 255,
                L"TimeCreated[@SystemTime>='%04d-%02d-%02dT%02d:%02d:%02d.000Z']",
                tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
                tm->tm_hour, tm->tm_min, tm->tm_sec);
            /* MinGW _snwprintf may not NUL-terminate; [0]/%ls read this. */
            start_clause[(sizeof(start_clause)/sizeof(start_clause[0])) - 1] = L'\0';
        }
    }
    if (filter->time_end) {
        struct tm *tm = gmtime(&filter->time_end);
        if (tm) {
            _snwprintf(end_clause, 255,
                L"TimeCreated[@SystemTime<='%04d-%02d-%02dT%02d:%02d:%02d.000Z']",
                tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
                tm->tm_hour, tm->tm_min, tm->tm_sec);
            end_clause[(sizeof(end_clause)/sizeof(end_clause[0])) - 1] = L'\0';
        }
    }

    if (start_clause[0] && end_clause[0]) {
        _snwprintf(buf, bufsz, L"*[System[%ls and %ls]]", start_clause, end_clause);
    } else if (start_clause[0]) {
        _snwprintf(buf, bufsz, L"*[System[%ls]]", start_clause);
    } else if (end_clause[0]) {
        _snwprintf(buf, bufsz, L"*[System[%ls]]", end_clause);
    } else {
        _snwprintf(buf, bufsz, L"*");
    }
    if (bufsz) buf[bufsz - 1] = L'\0';
}

/* --user is best-effort on this channel: firewall events rarely carry a user
   field, so match the username anywhere in the rendered XML. */
static int firewall_matches_user(const wchar_t *xml, const char *username)
{
    wchar_t wuser[128];

    if (!username || !username[0]) return 1;

    /* MultiByteToWideChar leaves the buffer unterminated when the source
     * overflows it; force termination before the wcsstr read. */
    MultiByteToWideChar(CP_UTF8, 0, username, -1, wuser, 128);
    wuser[(sizeof(wuser)/sizeof(wuser[0])) - 1] = L'\0';
    return wcsstr(xml, wuser) != NULL;
}

static int firewall_matches_keyword(const wchar_t *xml, const char *keyword)
{
    wchar_t wkw[256];

    if (!keyword || !keyword[0]) return 1;

    MultiByteToWideChar(CP_UTF8, 0, keyword, -1, wkw, 256);
    wkw[(sizeof(wkw)/sizeof(wkw[0])) - 1] = L'\0';
    return wcsstr(xml, wkw) != NULL;
}

/* Returns event count, or -1 on channel-not-found/access-denied/query failure. */
static long query_firewall_channel(const filter_config_t *filter, FILE *out,
                                   int *access_denied)
{
    wchar_t xpath[1024];
    EVT_HANDLE hResults;
    EVT_HANDLE events[100];
    DWORD returned, i;
    long count = 0;
    wchar_t *rendered = NULL;
    DWORD rendered_sz = 0;
    DWORD buf_used, prop_count;

    build_firewall_xpath(xpath, 1024, filter);

    hResults = EvtQuery(NULL, firewall_channel, xpath,
                        EvtQueryChannelPath | EvtQueryForwardDirection);
    if (!hResults) {
        DWORD err = GetLastError();
        if (err == ERROR_EVT_CHANNEL_NOT_FOUND) {
            log_verbose("network: firewall channel not found (disabled)");
        } else if (err == ERROR_ACCESS_DENIED) {
            log_warn("network: firewall channel access denied (run as Administrator)");
            *access_denied = 1;
        } else {
            log_warn("network: failed to query firewall channel (err %lu)",
                     (unsigned long)err);
        }
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

            if (!firewall_matches_user(rendered, filter->username)) {
                EvtClose(events[i]);
                continue;
            }
            if (!firewall_matches_keyword(rendered, filter->keyword)) {
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

int collect_netlog_init(collector_t *self, const filter_config_t *filter,
                        const char *output_dir)
{
    self->filter = filter;
    plat_path_join(self->out_path, sizeof(self->out_path), output_dir, self->subdir);

    /* The event channel may be disabled, so the text log alone is not required;
       proceed and let run() attempt the channel query regardless. SKIP only if
       the text log is absent — the channel query is still attempted in run(). */
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
    int access_denied = 0;

    /* Source 1: Windows Firewall text log */
    if (plat_file_exists(WIN_FIREWALL_LOG)) {
        char out_file[MAX_PATH_LEN];
        FILE *out;

        /* Forensic honesty: collect_text_filtered applies keyword+user only, not
         * time. Warn once so the operator knows the firewall text log is kept in
         * full and the --from/--to window was not enforced on it. */
        if (self->filter->time_start || self->filter->time_end) {
            log_warn("network: --from/--to time filter cannot be applied to the "
                     "pfirewall text log; it is collected in full");
        }

        plat_path_join(out_file, sizeof(out_file), self->out_path, "pfirewall.log");
        out = fopen(out_file, "w");
        if (!out) {
            log_warn("network: cannot write to %s", out_file);
            self->status = 1;
            snprintf(self->status_msg, sizeof(self->status_msg),
                     "partial: cannot write pfirewall.log");
        } else {
            long n = collect_text_filtered(WIN_FIREWALL_LOG, self->filter, out);
            fclose(out);
            if (n > 0) {
                total += n;
                log_verbose("network: %ld lines from %s", n, WIN_FIREWALL_LOG);
            } else if (n < 0) {
                log_warn("network: cannot read %s", WIN_FIREWALL_LOG);
                self->status = 1;
                snprintf(self->status_msg, sizeof(self->status_msg),
                         "partial: cannot read pfirewall.log");
            }
        }
    }

    /* Source 2: Windows Firewall event channel */
    {
        char out_file[MAX_PATH_LEN];
        FILE *out;

        plat_path_join(out_file, sizeof(out_file), self->out_path,
                       "firewall_events.xml");
        out = fopen(out_file, "w");
        if (!out) {
            log_warn("network: cannot write to %s", out_file);
            self->status = 1;
            snprintf(self->status_msg, sizeof(self->status_msg),
                     "partial: cannot write firewall_events.xml");
        } else {
            long n;

            fprintf(out, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Events>\n");
            n = query_firewall_channel(self->filter, out, &access_denied);
            fprintf(out, "</Events>\n");
            fclose(out);

            if (n > 0) {
                total += n;
                log_verbose("network: %ld firewall events", n);
            } else if (n < 0 && access_denied) {
                self->status = 1;
                snprintf(self->status_msg, sizeof(self->status_msg),
                         "partial: firewall channel access denied");
            }
        }
    }

    self->lines_collected = total;
    if (total == 0 && self->status == 0) {
        self->status = 2;
        snprintf(self->status_msg, sizeof(self->status_msg),
                 "no firewall log or matching events");
    }

    return 0;
}

void collect_netlog_cleanup(collector_t *self)
{
    (void)self;
}

#endif /* _WIN32 */
