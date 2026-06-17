#include "log_extract.h"
#include "manifest.h"
#include "hash.h"

#ifndef _WIN32
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#else
#include <windows.h>
#endif

/* The two manifest files are skipped during the walk so they never hash
 * themselves; the outer archive hash covers them instead. */
#define MANIFEST_JSON "manifest.json"
#define MANIFEST_HASHES "hashes.txt"

/* Per-file record gathered during the walk. Paths are stored relative to
 * output_dir using forward slashes so hashes.txt verifies portably with
 * `sha256sum -c`. */
typedef struct {
    char         relpath[MAX_PATH_LEN];
    long long    size_bytes;
    time_t       mtime_utc;
    char         sha256[65];
} manifest_entry_t;

typedef struct {
    manifest_entry_t *items;
    size_t            count;
    size_t            cap;
} manifest_list_t;

static void list_add(manifest_list_t *list, const manifest_entry_t *e)
{
    if (list->count == list->cap) {
        list->cap = list->cap ? list->cap * 2 : 64;
        list->items = safe_realloc(list->items,
                                   list->cap * sizeof(*list->items));
    }
    list->items[list->count++] = *e;
}

static void iso8601_zulu(time_t t, char *buf, size_t bufsz)
{
    struct tm *tm = gmtime(&t);
    if (!tm) {
        snprintf(buf, bufsz, "1970-01-01T00:00:00Z");
        return;
    }
    strftime(buf, bufsz, "%Y-%m-%dT%H:%M:%SZ", tm);
}

/* Offset of the collection host's local time east of UTC, in seconds.
 * Computed by diffing the broken-down local and UTC views of the same
 * instant rather than relying on a non-portable tm_gmtoff field. */
static long host_tz_offset_seconds(void)
{
    time_t now = time(NULL);
    struct tm lt, gt;
    struct tm *p;
    long days, secs;

    p = localtime(&now);
    if (!p) return 0;
    lt = *p;
    p = gmtime(&now);
    if (!p) return 0;
    gt = *p;

    days = (lt.tm_yday - gt.tm_yday);
    if (lt.tm_year != gt.tm_year)
        days = (lt.tm_year > gt.tm_year) ? 1 : -1;

    secs = days * 86400L
         + (lt.tm_hour - gt.tm_hour) * 3600L
         + (lt.tm_min - gt.tm_min) * 60L
         + (lt.tm_sec - gt.tm_sec);
    return secs;
}

static const char *host_privilege(void)
{
#ifdef _WIN32
    return "unknown";
#else
    return (geteuid() == 0) ? "root" : "user";
#endif
}

/* Emit a JSON string body (no surrounding quotes), escaping the characters
 * required by RFC 8259: backslash, double-quote, and C0 control chars. */
static void json_write_escaped(FILE *fp, const char *s)
{
    const unsigned char *p;
    for (p = (const unsigned char *)s; *p; p++) {
        switch (*p) {
            case '\\': fputs("\\\\", fp); break;
            case '"':  fputs("\\\"", fp); break;
            case '\b': fputs("\\b", fp);  break;
            case '\f': fputs("\\f", fp);  break;
            case '\n': fputs("\\n", fp);  break;
            case '\r': fputs("\\r", fp);  break;
            case '\t': fputs("\\t", fp);  break;
            default:
                if (*p < 0x20)
                    fprintf(fp, "\\u%04x", (unsigned)*p);
                else
                    fputc(*p, fp);
                break;
        }
    }
}

#ifndef _WIN32

static void walk_dir(const char *base, const char *rel, manifest_list_t *list)
{
    char fullpath[MAX_PATH_LEN];
    char childrel[MAX_PATH_LEN];
    DIR *d;
    struct dirent *de;

    if (rel[0])
        snprintf(fullpath, sizeof(fullpath), "%s/%s", base, rel);
    else
        snprintf(fullpath, sizeof(fullpath), "%s", base);

    d = opendir(fullpath);
    if (!d) return;

    while ((de = readdir(d)) != NULL) {
        struct stat st;
        char childfull[MAX_PATH_LEN];

        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;
        /* Skip the manifest outputs at the top level. */
        if (!rel[0] && (strcmp(de->d_name, MANIFEST_JSON) == 0 ||
                        strcmp(de->d_name, MANIFEST_HASHES) == 0))
            continue;

        if (rel[0]) {
            if (snprintf(childrel, sizeof(childrel), "%s/%s", rel, de->d_name)
                    >= (int)sizeof(childrel)) {
                log_warn("manifest: path too long, skipping %s/%s", rel, de->d_name);
                continue;
            }
        } else {
            snprintf(childrel, sizeof(childrel), "%s", de->d_name);
        }

        if (snprintf(childfull, sizeof(childfull), "%s/%s", fullpath, de->d_name)
                >= (int)sizeof(childfull)) {
            log_warn("manifest: path too long, skipping %s", childrel);
            continue;
        }

        if (lstat(childfull, &st) != 0)
            continue;
        if (S_ISDIR(st.st_mode)) {
            walk_dir(base, childrel, list);
        } else if (S_ISREG(st.st_mode)) {
            manifest_entry_t e;
            memset(&e, 0, sizeof(e));
            snprintf(e.relpath, sizeof(e.relpath), "%s", childrel);
            e.size_bytes = (long long)st.st_size;
            e.mtime_utc = st.st_mtime;
            if (hash_sha256_file(childfull, e.sha256, sizeof(e.sha256)) != 0) {
                log_warn("manifest: failed to hash %s", childrel);
                continue;
            }
            list_add(list, &e);
        }
    }
    closedir(d);
}

#else /* _WIN32 */

static time_t filetime_to_time_t(const FILETIME *ft)
{
    /* FILETIME is 100ns ticks since 1601-01-01; convert to Unix epoch. */
    ULONGLONG t = ((ULONGLONG)ft->dwHighDateTime << 32) | ft->dwLowDateTime;
    return (time_t)((t - 116444736000000000ULL) / 10000000ULL);
}

static void walk_dir(const char *base, const char *rel, manifest_list_t *list)
{
    char fullpath[MAX_PATH_LEN];
    char pattern[MAX_PATH_LEN];
    WIN32_FIND_DATAA fd;
    HANDLE h;

    if (rel[0])
        snprintf(fullpath, sizeof(fullpath), "%s\\%s", base, rel);
    else
        snprintf(fullpath, sizeof(fullpath), "%s", base);

    if (snprintf(pattern, sizeof(pattern), "%s\\*", fullpath)
            >= (int)sizeof(pattern)) {
        log_warn("manifest: path too long, skipping %s", fullpath);
        return;
    }

    h = FindFirstFileA(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) return;

    do {
        char childrel[MAX_PATH_LEN];
        char childfull[MAX_PATH_LEN];

        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0)
            continue;
        if (!rel[0] && (strcmp(fd.cFileName, MANIFEST_JSON) == 0 ||
                        strcmp(fd.cFileName, MANIFEST_HASHES) == 0))
            continue;

        /* Store relative paths with forward slashes for sha256sum portability. */
        if (rel[0])
            snprintf(childrel, sizeof(childrel), "%s/%s", rel, fd.cFileName);
        else
            snprintf(childrel, sizeof(childrel), "%s", fd.cFileName);

        if (snprintf(childfull, sizeof(childfull), "%s\\%s",
                     fullpath, fd.cFileName) >= (int)sizeof(childfull)) {
            log_warn("manifest: path too long, skipping %s", childrel);
            continue;
        }

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            walk_dir(base, childrel, list);
        } else {
            manifest_entry_t e;
            memset(&e, 0, sizeof(e));
            snprintf(e.relpath, sizeof(e.relpath), "%s", childrel);
            e.size_bytes = ((long long)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
            e.mtime_utc = filetime_to_time_t(&fd.ftLastWriteTime);
            if (hash_sha256_file(childfull, e.sha256, sizeof(e.sha256)) != 0) {
                log_warn("manifest: failed to hash %s", childrel);
                continue;
            }
            list_add(list, &e);
        }
    } while (FindNextFileA(h, &fd));

    FindClose(h);
}

#endif /* _WIN32 */

static int write_hashes_txt(const char *output_dir, const manifest_list_t *list)
{
    char path[MAX_PATH_LEN];
    FILE *fp;
    size_t i;

    snprintf(path, sizeof(path), "%s%c%s", output_dir, PATH_SEP, MANIFEST_HASHES);
    fp = fopen(path, "wb");
    if (!fp) return -1;

    for (i = 0; i < list->count; i++)
        fprintf(fp, "%s  %s\n", list->items[i].sha256, list->items[i].relpath);

    fclose(fp);
    return 0;
}

static int write_manifest_json(const char *output_dir, const manifest_list_t *list,
                               time_t start, time_t end)
{
    char path[MAX_PATH_LEN];
    char hostname[256];
    char tbuf[64];
    FILE *fp;
    size_t i;

    snprintf(path, sizeof(path), "%s%c%s", output_dir, PATH_SEP, MANIFEST_JSON);
    fp = fopen(path, "wb");
    if (!fp) return -1;

    plat_get_hostname(hostname, sizeof(hostname));

    fputs("{\n", fp);
    fprintf(fp, "  \"tool\": \"%s\",\n", LOG_EXTRACT_NAME);
    fprintf(fp, "  \"version\": \"%s\",\n", LOG_EXTRACT_VERSION);

    fputs("  \"hostname\": \"", fp);
    json_write_escaped(fp, hostname);
    fputs("\",\n", fp);

    iso8601_zulu(start, tbuf, sizeof(tbuf));
    fprintf(fp, "  \"collected_start_utc\": \"%s\",\n", tbuf);
    iso8601_zulu(end, tbuf, sizeof(tbuf));
    fprintf(fp, "  \"collected_end_utc\": \"%s\",\n", tbuf);
    iso8601_zulu(time(NULL), tbuf, sizeof(tbuf));
    fprintf(fp, "  \"generated_utc\": \"%s\",\n", tbuf);

    fprintf(fp, "  \"timezone_offset_seconds\": %ld,\n", host_tz_offset_seconds());
    fprintf(fp, "  \"privilege\": \"%s\",\n", host_privilege());

    fputs("  \"files\": [\n", fp);
    for (i = 0; i < list->count; i++) {
        const manifest_entry_t *e = &list->items[i];
        iso8601_zulu(e->mtime_utc, tbuf, sizeof(tbuf));
        fputs("    {\n", fp);
        fputs("      \"path\": \"", fp);
        json_write_escaped(fp, e->relpath);
        fputs("\",\n", fp);
        fprintf(fp, "      \"size_bytes\": %lld,\n", e->size_bytes);
        fprintf(fp, "      \"sha256\": \"%s\",\n", e->sha256);
        fprintf(fp, "      \"mtime_utc\": \"%s\"\n", tbuf);
        fprintf(fp, "    }%s\n", (i + 1 < list->count) ? "," : "");
    }
    fputs("  ]\n", fp);
    fputs("}\n", fp);

    fclose(fp);
    return 0;
}

int manifest_write(const char *output_dir, const collector_registry_t *reg,
                   time_t collect_start_utc, time_t collect_end_utc)
{
    manifest_list_t list;

    /* The registry status is reported separately by the summary printer; the
     * manifest is built purely from what actually landed on disk. */
    (void)reg;

    memset(&list, 0, sizeof(list));
    walk_dir(output_dir, "", &list);

    if (write_hashes_txt(output_dir, &list) != 0) {
        log_warn("manifest: failed to write %s", MANIFEST_HASHES);
        return -1;
    }
    if (write_manifest_json(output_dir, &list, collect_start_utc,
                            collect_end_utc) != 0) {
        log_warn("manifest: failed to write %s", MANIFEST_JSON);
        return -1;
    }
    return 0;
}
