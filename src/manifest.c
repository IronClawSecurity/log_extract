#include "log_extract.h"
#include "manifest.h"
#include "hash.h"

#ifndef _WIN32
#include <dirent.h>
#endif

/* JSON-escape s into out, return bytes written (excluding null), or -1 on overflow */
static int json_escape(const char *s, char *out, size_t outsz)
{
    size_t i = 0;
    if (!s) s = "";
    for (; *s && i + 6 < outsz; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"') { out[i++] = '\\'; out[i++] = '"'; }
        else if (c == '\\') { out[i++] = '\\'; out[i++] = '\\'; }
        else if (c == '\n') { out[i++] = '\\'; out[i++] = 'n'; }
        else if (c == '\r') { out[i++] = '\\'; out[i++] = 'r'; }
        else if (c == '\t') { out[i++] = '\\'; out[i++] = 't'; }
        else if (c < 0x20) {
            int n = snprintf(out + i, outsz - i, "\\u%04x", c);
            if (n < 0 || (size_t)n >= outsz - i) return -1;
            i += (size_t)n;
        } else {
            out[i++] = (char)c;
        }
    }
    if (*s) return -1;
    out[i] = '\0';
    return (int)i;
}

static void hash_dir_recursive(const char *base, const char *rel, FILE *out, int *first);

static void hash_one_file(const char *full_path, const char *rel_path,
                          FILE *out, int *first)
{
    char hex[65];
    char rel_esc[2048];

    if (hash_sha256_file(full_path, hex, sizeof(hex)) != 0) {
        log_verbose("manifest: cannot hash %s", full_path);
        return;
    }
    if (json_escape(rel_path, rel_esc, sizeof(rel_esc)) < 0) return;

    if (!*first) fprintf(out, ",\n");
    fprintf(out, "    {\"path\": \"%s\", \"sha256\": \"%s\"}",
            rel_esc, hex);
    *first = 0;
}

#ifndef _WIN32
static void hash_dir_recursive(const char *base, const char *rel, FILE *out, int *first)
{
    char dir_path[MAX_PATH_LEN];
    DIR *d;
    struct dirent *ent;

    if (rel[0])
        plat_path_join(dir_path, sizeof(dir_path), base, rel);
    else
        snprintf(dir_path, sizeof(dir_path), "%s", base);

    d = opendir(dir_path);
    if (!d) return;

    while ((ent = readdir(d)) != NULL) {
        char full[MAX_PATH_LEN];
        char child_rel[MAX_PATH_LEN];

        if (ent->d_name[0] == '.') continue;
        /* Skip the manifest itself */
        if (rel[0] == '\0' && strcmp(ent->d_name, "manifest.json") == 0)
            continue;

        plat_path_join(full, sizeof(full), dir_path, ent->d_name);
        if (rel[0])
            plat_path_join(child_rel, sizeof(child_rel), rel, ent->d_name);
        else
            snprintf(child_rel, sizeof(child_rel), "%s", ent->d_name);

        if (plat_is_directory(full)) {
            hash_dir_recursive(base, child_rel, out, first);
        } else {
            hash_one_file(full, child_rel, out, first);
        }
    }
    closedir(d);
}
#else
#include <windows.h>
static void hash_dir_recursive(const char *base, const char *rel, FILE *out, int *first)
{
    char dir_path[MAX_PATH_LEN];
    char glob[MAX_PATH_LEN];
    WIN32_FIND_DATAA fd;
    HANDLE h;

    if (rel[0])
        plat_path_join(dir_path, sizeof(dir_path), base, rel);
    else
        snprintf(dir_path, sizeof(dir_path), "%s", base);

    snprintf(glob, sizeof(glob), "%s\\*", dir_path);
    h = FindFirstFileA(glob, &fd);
    if (h == INVALID_HANDLE_VALUE) return;

    do {
        char full[MAX_PATH_LEN];
        char child_rel[MAX_PATH_LEN];

        if (fd.cFileName[0] == '.') continue;
        if (rel[0] == '\0' && strcmp(fd.cFileName, "manifest.json") == 0)
            continue;

        plat_path_join(full, sizeof(full), dir_path, fd.cFileName);
        if (rel[0])
            plat_path_join(child_rel, sizeof(child_rel), rel, fd.cFileName);
        else
            snprintf(child_rel, sizeof(child_rel), "%s", fd.cFileName);

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            hash_dir_recursive(base, child_rel, out, first);
        } else {
            hash_one_file(full, child_rel, out, first);
        }
    } while (FindNextFileA(h, &fd));

    FindClose(h);
}
#endif

static const char *status_str(int s)
{
    switch (s) {
        case 0: return "ok";
        case 1: return "warn";
        case 2: return "skip";
        default: return "error";
    }
}

static const char *platform_str(void)
{
#if defined(_WIN32)
    return "windows";
#elif defined(__APPLE__)
    return "macos";
#else
    return "linux";
#endif
}

int manifest_write(const char *output_dir,
                   const collector_registry_t *reg,
                   const cli_options_t *opts,
                   int argc, char *argv[])
{
    char path[MAX_PATH_LEN];
    char hostname[256];
    char now_str[32];
    char esc[2048];
    FILE *f;
    time_t now;
    int i;
    int first;

    plat_path_join(path, sizeof(path), output_dir, "manifest.json");

    f = fopen(path, "w");
    if (!f) {
        log_warn("manifest: cannot open %s", path);
        return -1;
    }

    plat_get_hostname(hostname, sizeof(hostname));
    now = time(NULL);
    plat_format_timestamp(now, now_str, sizeof(now_str));

    fprintf(f, "{\n");
    fprintf(f, "  \"tool\": \"%s\",\n", LOG_EXTRACT_NAME);
    fprintf(f, "  \"version\": \"%s\",\n", LOG_EXTRACT_VERSION);
    fprintf(f, "  \"platform\": \"%s\",\n", platform_str());

    json_escape(hostname, esc, sizeof(esc));
    fprintf(f, "  \"hostname\": \"%s\",\n", esc);

    fprintf(f, "  \"collected_at\": \"%s\",\n", now_str);

    /* Command line */
    fprintf(f, "  \"command_line\": [");
    for (i = 0; i < argc; i++) {
        if (json_escape(argv[i], esc, sizeof(esc)) < 0) continue;
        fprintf(f, "%s\"%s\"", i ? ", " : "", esc);
    }
    fprintf(f, "],\n");

    /* Filters */
    fprintf(f, "  \"filters\": {\n");
    json_escape(opts->time_start, esc, sizeof(esc));
    fprintf(f, "    \"from\": \"%s\",\n", esc);
    json_escape(opts->time_end, esc, sizeof(esc));
    fprintf(f, "    \"to\": \"%s\",\n", esc);
    json_escape(opts->keyword, esc, sizeof(esc));
    fprintf(f, "    \"grep\": \"%s\",\n", esc);
    json_escape(opts->exclude, esc, sizeof(esc));
    fprintf(f, "    \"exclude\": \"%s\",\n", esc);
    fprintf(f, "    \"level_min\": %d,\n", opts->severity_min);
    fprintf(f, "    \"level_max\": %d,\n", opts->severity_max);
    json_escape(opts->username, esc, sizeof(esc));
    fprintf(f, "    \"user\": \"%s\"\n", esc);
    fprintf(f, "  },\n");

    /* Collectors */
    fprintf(f, "  \"collectors\": [\n");
    for (i = 0; i < reg->count; i++) {
        const collector_t *c = &reg->items[i];
        char msg_esc[512];
        json_escape(c->status_msg, msg_esc, sizeof(msg_esc));
        fprintf(f, "    {\"name\": \"%s\", \"enabled\": %s, \"status\": \"%s\", "
                "\"lines_collected\": %ld, \"message\": \"%s\"}%s\n",
                c->name,
                c->enabled ? "true" : "false",
                status_str(c->status),
                c->lines_collected,
                msg_esc,
                (i + 1 < reg->count) ? "," : "");
    }
    fprintf(f, "  ],\n");

    /* File hashes (recursive) */
    fprintf(f, "  \"files\": [\n");
    first = 1;
    hash_dir_recursive(output_dir, "", f, &first);
    fprintf(f, "\n  ]\n");
    fprintf(f, "}\n");

    fclose(f);
    log_verbose("manifest: wrote %s", path);
    return 0;
}
