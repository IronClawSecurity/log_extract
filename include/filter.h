#ifndef FILTER_H
#define FILTER_H

#include <time.h>

typedef struct {
    time_t  time_start;     /* 0 = no lower bound */
    time_t  time_end;       /* 0 = no upper bound */
    char    keyword[256];   /* empty = no keyword filter */
    int     severity_min;   /* -1 = no filter; syslog scale: 0=emerg..7=debug */
    int     severity_max;
    char    username[128];  /* empty = no user filter */
} filter_config_t;

/* Check if a line passes the keyword filter */
int filter_match_keyword(const filter_config_t *f, const char *line);

/* Check if a timestamp falls within the time range */
int filter_match_time(const filter_config_t *f, time_t t);

/* Check if a severity level passes the filter */
int filter_match_severity(const filter_config_t *f, int level);

/* Check if a line contains the target username */
int filter_match_user(const filter_config_t *f, const char *line);

/* Combined: check keyword + user against a text line */
int filter_match_line(const filter_config_t *f, const char *line);

#endif /* FILTER_H */
