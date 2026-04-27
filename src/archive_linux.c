#ifndef _WIN32

#include "log_extract.h"
#include "archive.h"

int archive_create(const char *output_dir, char *archive_path, size_t bufsz)
{
    char cmd[MAX_PATH_LEN * 2];
    char parent[MAX_PATH_LEN];
    const char *dirname;
    int ret;

    /* Split output_dir into parent + dirname */
    snprintf(parent, sizeof(parent), "%s", output_dir);
    {
        char *last_sep = strrchr(parent, '/');
        if (!last_sep) {
            log_error("archive: invalid output path: %s", output_dir);
            return -1;
        }
        dirname = last_sep + 1;
        *last_sep = '\0';
    }

    snprintf(archive_path, bufsz, "%s.tar.gz", output_dir);

    /* Validate path components before passing to shell */
    if (!str_is_shell_safe(archive_path) || !str_is_shell_safe(parent) ||
        !str_is_shell_safe(dirname)) {
        log_error("archive: output path contains unsafe characters");
        return -1;
    }

    snprintf(cmd, sizeof(cmd), "tar czf '%s' -C '%s' '%s'",
             archive_path, parent, dirname);

    log_verbose("archive: running %s", cmd);
    ret = system(cmd);
    if (ret != 0) {
        log_error("archive: tar failed (exit %d)", ret);
        log_error("archive: the uncompressed output is still at: %s", output_dir);
        return -1;
    }

    return 0;
}

#endif /* !_WIN32 */
