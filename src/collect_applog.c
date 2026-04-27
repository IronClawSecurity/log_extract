#include "log_extract.h"
#include "collectors/applog.h"
#include "jsonl.h"
#include <dirent.h>

#ifdef __APPLE__
static const char *wellknown_dirs[] = {
    "/var/log/apache2",
    "/private/var/log/apache2",
    "/opt/homebrew/var/log/nginx",
    "/usr/local/var/log/nginx",
    "/opt/homebrew/var/log/httpd",
    "/usr/local/var/log/httpd",
    NULL
};
#elif !defined(_WIN32)
static const char *wellknown_dirs[] = {
    "/var/log/apache2",
    "/var/log/httpd",
    "/var/log/nginx",
    NULL
};
#else
static const char *wellknown_dirs[] = {
    "C:\\inetpub\\logs\\LogFiles",
    NULL
};
#endif

static long collect_log_file(const char *path, const filter_config_t *filter,
                             FILE *out, FILE *jsonl_f, const char *source_name)
{
    FILE *in;
    char line[MAX_LINE_LEN];
    long count = 0;

    in = fopen(path, "r");
    if (!in) return -1;

    while (fgets(line, sizeof(line), in)) {
        if (!filter_match_line(filter, line)) continue;
        fputs(line, out);
        if (jsonl_f) {
            char trimmed[MAX_LINE_LEN];
            snprintf(trimmed, sizeof(trimmed), "%s", line);
            str_trim(trimmed);
            jsonl_emit(jsonl_f, source_name, 0, -1, NULL, trimmed);
        }
        count++;
    }

    fclose(in);
    return count;
}

static long collect_directory(const char *dir_path, const filter_config_t *filter,
                              const char *out_dir)
{
    DIR *d;
    struct dirent *ent;
    long total = 0;

    d = opendir(dir_path);
    if (!d) return -1;

    while ((ent = readdir(d)) != NULL) {
        char src[MAX_PATH_LEN], dst[MAX_PATH_LEN];
        FILE *out, *jsonl_f;
        long n;

        if (ent->d_name[0] == '.') continue;

        plat_path_join(src, sizeof(src), dir_path, ent->d_name);

        /* Skip directories — non-recursive */
        if (plat_is_directory(src)) continue;

        plat_path_join(dst, sizeof(dst), out_dir, ent->d_name);

        out = fopen(dst, "w");
        if (!out) continue;

        jsonl_f = jsonl_open(out_dir, ent->d_name);

        n = collect_log_file(src, filter, out, jsonl_f, ent->d_name);
        fclose(out);
        jsonl_close(jsonl_f);

        if (n > 0) {
            total += n;
            log_verbose("app: %ld lines from %s", n, src);
        }
    }

    closedir(d);
    return total;
}

int collect_applog_init(collector_t *self, const filter_config_t *filter,
                        const char *output_dir)
{
    int i, found = 0;

    self->filter = filter;
    plat_path_join(self->out_path, sizeof(self->out_path), output_dir, self->subdir);

    /* Check well-known paths */
    for (i = 0; wellknown_dirs[i]; i++) {
        if (plat_is_directory(wellknown_dirs[i])) {
            found = 1;
            break;
        }
    }

    /* Check user-supplied paths */
    if (g_applog_config.app_path_count > 0)
        found = 1;

    if (!found) {
        self->status = 2;
        snprintf(self->status_msg, sizeof(self->status_msg), "no application logs found");
        return -1;
    }

    if (plat_mkdir_p(self->out_path) != 0) {
        self->status = 3;
        snprintf(self->status_msg, sizeof(self->status_msg), "cannot create output dir");
        return -1;
    }

    return 0;
}

int collect_applog_run(collector_t *self)
{
    long total = 0;
    int i;

    /* Well-known directories */
    for (i = 0; wellknown_dirs[i]; i++) {
        if (!plat_is_directory(wellknown_dirs[i])) continue;

        {
            /* Create a subdirectory named after the source */
            const char *basename = strrchr(wellknown_dirs[i], PATH_SEP);
            char subout[MAX_PATH_LEN];
            long n;

            basename = basename ? basename + 1 : wellknown_dirs[i];
            plat_path_join(subout, sizeof(subout), self->out_path, basename);
            plat_mkdir_p(subout);

            n = collect_directory(wellknown_dirs[i], self->filter, subout);
            if (n > 0) total += n;
        }
    }

    /* User-supplied paths */
    for (i = 0; i < g_applog_config.app_path_count; i++) {
        const char *path = g_applog_config.app_paths[i];

        if (plat_is_directory(path)) {
            const char *basename = strrchr(path, PATH_SEP);
            char subout[MAX_PATH_LEN];
            long n;

            basename = basename ? basename + 1 : path;
            plat_path_join(subout, sizeof(subout), self->out_path, basename);
            plat_mkdir_p(subout);

            n = collect_directory(path, self->filter, subout);
            if (n > 0) total += n;
            else if (n < 0) {
                log_warn("app: cannot read directory %s", path);
                self->status = 1;
            }
        } else if (plat_file_exists(path)) {
            const char *basename = strrchr(path, PATH_SEP);
            char dst[MAX_PATH_LEN];
            FILE *out, *jsonl_f;
            long n;

            basename = basename ? basename + 1 : path;
            plat_path_join(dst, sizeof(dst), self->out_path, basename);

            out = fopen(dst, "w");
            if (!out) {
                log_warn("app: cannot write to %s", dst);
                continue;
            }

            jsonl_f = jsonl_open(self->out_path, basename);
            n = collect_log_file(path, self->filter, out, jsonl_f, basename);
            fclose(out);
            jsonl_close(jsonl_f);
            if (n > 0) total += n;
            else if (n < 0) {
                log_warn("app: cannot read %s", path);
                self->status = 1;
            }
        } else {
            log_warn("app: path not found: %s", path);
        }
    }

    self->lines_collected = total;
    if (total == 0 && self->status == 0) {
        self->status = 2;
        snprintf(self->status_msg, sizeof(self->status_msg), "no matching entries");
    }

    return 0;
}

void collect_applog_cleanup(collector_t *self)
{
    (void)self;
}
