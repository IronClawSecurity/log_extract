#include "log_extract.h"

int filter_match_keyword(const filter_config_t *f, const char *line)
{
    if (!f->keyword[0]) return 1;  /* no filter = pass */
    return str_contains(line, f->keyword);
}

int filter_match_exclude(const filter_config_t *f, const char *line)
{
    if (!f->exclude[0]) return 1;  /* no filter = pass */
    return !str_contains(line, f->exclude);
}

int filter_match_time(const filter_config_t *f, time_t t)
{
    if (t == 0) return 1;  /* unknown timestamp = pass */
    if (f->time_start != 0 && t < f->time_start) return 0;
    if (f->time_end != 0 && t > f->time_end) return 0;
    return 1;
}

int filter_match_severity(const filter_config_t *f, int level)
{
    if (f->severity_min == -1 && f->severity_max == -1) return 1;
    if (f->severity_min != -1 && level < f->severity_min) return 0;
    if (f->severity_max != -1 && level > f->severity_max) return 0;
    return 1;
}

int filter_match_user(const filter_config_t *f, const char *line)
{
    if (!f->username[0]) return 1;  /* no filter = pass */
    return str_contains(line, f->username);
}

int filter_match_line(const filter_config_t *f, const char *line)
{
    if (!filter_match_keyword(f, line)) return 0;
    if (!filter_match_user(f, line)) return 0;
    if (!filter_match_exclude(f, line)) return 0;
    return 1;
}
