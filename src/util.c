#include "log_extract.h"

int g_verbose = 0;
int g_quiet = 0;

void log_info(const char *fmt, ...)
{
    va_list ap;
    if (g_quiet) return;
    va_start(ap, fmt);
    fprintf(stdout, "[*] ");
    vfprintf(stdout, fmt, ap);
    fprintf(stdout, "\n");
    fflush(stdout);
    va_end(ap);
}

void log_warn(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "[!] ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    fflush(stderr);
    va_end(ap);
}

void log_error(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "[ERROR] ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    fflush(stderr);
    va_end(ap);
}

void log_verbose(const char *fmt, ...)
{
    va_list ap;
    if (!g_verbose) return;
    va_start(ap, fmt);
    fprintf(stdout, "[~] ");
    vfprintf(stdout, fmt, ap);
    fprintf(stdout, "\n");
    fflush(stdout);
    va_end(ap);
}

void *safe_malloc(size_t n)
{
    void *p = malloc(n);
    if (!p) {
        log_error("Out of memory (requested %zu bytes)", n);
        exit(1);
    }
    return p;
}

void *safe_realloc(void *p, size_t n)
{
    void *np = realloc(p, n);
    if (!np) {
        log_error("Out of memory (realloc %zu bytes)", n);
        exit(1);
    }
    return np;
}

char *safe_strdup(const char *s)
{
    char *d;
    if (!s) return NULL;
    d = safe_malloc(strlen(s) + 1);
    strcpy(d, s);
    return d;
}

int str_contains(const char *haystack, const char *needle)
{
    if (!needle || !needle[0]) return 1;
    if (!haystack) return 0;
    return strstr(haystack, needle) != NULL;
}

int str_starts_with(const char *str, const char *prefix)
{
    if (!str || !prefix) return 0;
    return strncmp(str, prefix, strlen(prefix)) == 0;
}

void str_trim(char *s)
{
    char *start, *end;
    if (!s || !*s) return;

    start = s;
    while (*start == ' ' || *start == '\t' || *start == '\n' || *start == '\r')
        start++;

    end = start + strlen(start);
    while (end > start && (*(end-1) == ' ' || *(end-1) == '\t' ||
           *(end-1) == '\n' || *(end-1) == '\r'))
        end--;

    if (start != s)
        memmove(s, start, (size_t)(end - start));
    s[end - start] = '\0';
}
