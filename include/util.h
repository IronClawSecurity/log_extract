#ifndef UTIL_H
#define UTIL_H

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

/* Logging */
void log_info(const char *fmt, ...);
void log_warn(const char *fmt, ...);
void log_error(const char *fmt, ...);
void log_verbose(const char *fmt, ...);

/* Safe allocation — exits on failure */
void *safe_malloc(size_t n);
void *safe_realloc(void *p, size_t n);
char *safe_strdup(const char *s);

/* String helpers */
int str_contains(const char *haystack, const char *needle);
int str_starts_with(const char *str, const char *prefix);
void str_trim(char *s);

#endif /* UTIL_H */
