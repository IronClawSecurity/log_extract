#ifndef _WIN32

#include "log_extract.h"
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>

int plat_mkdir_p(const char *path)
{
    char tmp[MAX_PATH_LEN];
    char *p;
    size_t len;

    snprintf(tmp, sizeof(tmp), "%s", path);
    len = strlen(tmp);
    if (len > 0 && tmp[len - 1] == '/')
        tmp[len - 1] = '\0';

    for (p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, 0755) != 0 && errno != EEXIST)
                return -1;
            *p = '/';
        }
    }
    if (mkdir(tmp, 0755) != 0 && errno != EEXIST)
        return -1;
    return 0;
}

int plat_path_join(char *buf, size_t bufsz, const char *a, const char *b)
{
    size_t alen = strlen(a);
    if (alen > 0 && a[alen - 1] == '/')
        return snprintf(buf, bufsz, "%s%s", a, b) < (int)bufsz ? 0 : -1;
    return snprintf(buf, bufsz, "%s/%s", a, b) < (int)bufsz ? 0 : -1;
}

int plat_file_copy(const char *src, const char *dst)
{
    FILE *in, *out;
    char buf[8192];
    size_t n;

    in = fopen(src, "rb");
    if (!in) return -1;

    out = fopen(dst, "wb");
    if (!out) {
        fclose(in);
        return -1;
    }

    while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
        if (fwrite(buf, 1, n, out) != n) {
            fclose(in);
            fclose(out);
            return -1;
        }
    }

    fclose(in);
    fclose(out);
    return 0;
}

int plat_file_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0;
}

int plat_is_directory(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0) return 0;
    return S_ISDIR(st.st_mode);
}

int plat_get_hostname(char *buf, size_t bufsz)
{
    if (gethostname(buf, bufsz) != 0) {
        snprintf(buf, bufsz, "unknown");
        return -1;
    }
    return 0;
}

time_t plat_parse_timestamp(const char *str)
{
    struct tm tm;
    memset(&tm, 0, sizeof(tm));

    /* Expected: "YYYY-MM-DD HH:MM:SS" */
    if (sscanf(str, "%d-%d-%d %d:%d:%d",
               &tm.tm_year, &tm.tm_mon, &tm.tm_mday,
               &tm.tm_hour, &tm.tm_min, &tm.tm_sec) != 6)
        return 0;

    tm.tm_year -= 1900;
    tm.tm_mon -= 1;
    tm.tm_isdst = -1;
    return mktime(&tm);
}

int plat_format_timestamp(time_t t, char *buf, size_t bufsz)
{
    struct tm *tm = localtime(&t);
    if (!tm) return -1;
    strftime(buf, bufsz, "%Y-%m-%d %H:%M:%S", tm);
    return 0;
}

int plat_timestamp_now(char *buf, size_t bufsz)
{
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    if (!tm) return -1;
    strftime(buf, bufsz, "%Y%m%d_%H%M%S", tm);
    return 0;
}

int plat_exec_capture(const char *cmd, const char *output_file)
{
    char full_cmd[MAX_PATH_LEN * 2];
    int ret;

    snprintf(full_cmd, sizeof(full_cmd), "%s > \"%s\" 2>&1", cmd, output_file);
    ret = system(full_cmd);
    if (ret == -1) return -1;
    return WEXITSTATUS(ret);
}

#endif /* !_WIN32 */
