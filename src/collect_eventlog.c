#ifdef _WIN32

#include "log_extract.h"
#include "collectors/eventlog.h"
#include <windows.h>
#include <winevt.h>

/* Channel names to query */
static const wchar_t *channels[] = {
    L"System",
    L"Application",
    L"Security",
    NULL
};

/* Build XPath query string with optional time and severity filters */
static void build_xpath(wchar_t *buf, size_t bufsz, const filter_config_t *filter)
{
    /* Start with a basic query */
    wchar_t time_clause[256] = {0};
    wchar_t level_clause[128] = {0};

    if (filter->time_start || filter->time_end) {
        /* Use timediff in milliseconds from now, or absolute SystemTime */
        if (filter->time_start) {
            struct tm *tm = gmtime(&filter->time_start);
            if (tm) {
                _snwprintf(time_clause, 255,
                    L"TimeCreated[@SystemTime>='%04d-%02d-%02dT%02d:%02d:%02d.000Z']",
                    tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
                    tm->tm_hour, tm->tm_min, tm->tm_sec);
            }
        }
    }

    if (filter->severity_min != -1 || filter->severity_max != -1) {
        int lmin = filter->severity_min != -1 ? filter->severity_min : 0;
        int lmax = filter->severity_max != -1 ? filter->severity_max : 5;
        /* Windows levels: 1=Critical, 2=Error, 3=Warning, 4=Information, 5=Verbose */
        _snwprintf(level_clause, 127, L"(Level>=%d and Level<=%d)", lmin, lmax);
    }

    if (time_clause[0] && level_clause[0]) {
        _snwprintf(buf, bufsz, L"*[System[%ls and %ls]]",
                   time_clause, level_clause);
    } else if (time_clause[0]) {
        _snwprintf(buf, bufsz, L"*[System[%ls]]", time_clause);
    } else if (level_clause[0]) {
        _snwprintf(buf, bufsz, L"*[System[%ls]]", level_clause);
    } else {
        _snwprintf(buf, bufsz, L"*");
    }
}

/* Check if rendered event XML contains the target username */
static int event_matches_user(const wchar_t *xml, const char *username)
{
    wchar_t wuser[128];
    wchar_t pattern1[256], pattern2[256];

    if (!username || !username[0]) return 1;

    MultiByteToWideChar(CP_UTF8, 0, username, -1, wuser, 128);

    _snwprintf(pattern1, 255, L"TargetUserName'>%ls</Data", wuser);
    _snwprintf(pattern2, 255, L"SubjectUserName'>%ls</Data", wuser);

    return wcsstr(xml, pattern1) != NULL || wcsstr(xml, pattern2) != NULL;
}

/* Check if rendered XML contains the keyword */
static int event_matches_keyword(const wchar_t *xml, const char *keyword)
{
    wchar_t wkw[256];

    if (!keyword || !keyword[0]) return 1;

    MultiByteToWideChar(CP_UTF8, 0, keyword, -1, wkw, 256);
    return wcsstr(xml, wkw) != NULL;
}

static long query_channel(const wchar_t *channel, const filter_config_t *filter,
                          FILE *out)
{
    wchar_t xpath[1024];
    EVT_HANDLE hResults;
    EVT_HANDLE events[100];
    DWORD returned, i;
    long count = 0;
    wchar_t *rendered = NULL;
    DWORD rendered_sz = 0;
    DWORD buf_used, prop_count;

    build_xpath(xpath, 1024, filter);

    hResults = EvtQuery(NULL, channel, xpath,
                        EvtQueryChannelPath | EvtQueryForwardDirection);
    if (!hResults) {
        DWORD err = GetLastError();
        if (err == ERROR_EVT_CHANNEL_NOT_FOUND) {
            log_verbose("eventlog: channel not found");
        } else if (err == ERROR_ACCESS_DENIED) {
            log_warn("eventlog: access denied (run as Administrator)");
        }
        return -1;
    }

    while (EvtNext(hResults, 100, events, INFINITE, 0, &returned)) {
        for (i = 0; i < returned; i++) {
            /* Render event to XML */
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

            /* Apply user and keyword filters */
            if (!event_matches_user(rendered, filter->username)) {
                EvtClose(events[i]);
                continue;
            }
            if (!event_matches_keyword(rendered, filter->keyword)) {
                EvtClose(events[i]);
                continue;
            }
            if (filter->exclude[0]) {
                wchar_t wexcl[256];
                MultiByteToWideChar(CP_UTF8, 0, filter->exclude, -1, wexcl, 256);
                if (wcsstr(rendered, wexcl) != NULL) {
                    EvtClose(events[i]);
                    continue;
                }
            }

            /* Write XML to output as UTF-8 */
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

int collect_eventlog_init(collector_t *self, const filter_config_t *filter,
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

int collect_eventlog_run(collector_t *self)
{
    long total = 0;
    int i;

    for (i = 0; channels[i]; i++) {
        char out_file[MAX_PATH_LEN];
        char channel_name[64];
        FILE *out;
        long n;

        /* Convert channel name to narrow for filename */
        WideCharToMultiByte(CP_UTF8, 0, channels[i], -1,
                           channel_name, sizeof(channel_name), NULL, NULL);

        {
            char fname[72];
            snprintf(fname, sizeof(fname), "%s.xml", channel_name);
            plat_path_join(out_file, sizeof(out_file), self->out_path, fname);
        }

        out = fopen(out_file, "w");
        if (!out) {
            log_warn("eventlog: cannot write to %s", out_file);
            continue;
        }

        fprintf(out, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Events>\n");
        n = query_channel(channels[i], self->filter, out);
        fprintf(out, "</Events>\n");
        fclose(out);

        if (n < 0) {
            log_warn("eventlog: failed to query %s", channel_name);
            self->status = 1;
            snprintf(self->status_msg, sizeof(self->status_msg),
                     "partial: could not query %s", channel_name);
        } else {
            total += n;
            log_verbose("eventlog: %ld events from %s", n, channel_name);
        }
    }

    self->lines_collected = total;
    if (total == 0 && self->status == 0) {
        self->status = 2;
        snprintf(self->status_msg, sizeof(self->status_msg), "no matching events");
    }

    return 0;
}

void collect_eventlog_cleanup(collector_t *self)
{
    (void)self;
}

#endif /* _WIN32 */
