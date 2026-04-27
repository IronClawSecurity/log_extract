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
    {
        size_t len = strlen(s) + 1;
        d = safe_malloc(len);
        memcpy(d, s, len);
    }
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

int str_is_shell_safe(const char *s)
{
    if (!s) return 0;
    for (; *s; s++) {
        if ((*s >= 'a' && *s <= 'z') || (*s >= 'A' && *s <= 'Z') ||
            (*s >= '0' && *s <= '9') || *s == '-' || *s == '_' ||
            *s == '.' || *s == '/' || *s == ':' || *s == ' ')
            continue;
        return 0;
    }
    return 1;
}

int str_shell_escape(const char *src, char *dst, size_t dstsz)
{
    size_t di = 0;
    if (dstsz < 3) return -1;

    dst[di++] = '\'';
    for (; *src && di < dstsz - 2; src++) {
        if (*src == '\'') {
            /* End quote, escaped quote, restart quote: '\'' */
            if (di + 4 >= dstsz) return -1;
            dst[di++] = '\'';
            dst[di++] = '\\';
            dst[di++] = '\'';
            dst[di++] = '\'';
        } else {
            dst[di++] = *src;
        }
    }
    if (*src) return -1;  /* truncated */
    dst[di++] = '\'';
    dst[di] = '\0';
    return 0;
}
