#ifdef _WIN32

#include "log_extract.h"
#include "archive.h"
#include <windows.h>

int archive_create(const char *output_dir, char *archive_path, size_t bufsz)
{
    char cmd[MAX_PATH_LEN * 3];
    int ret;

    snprintf(archive_path, bufsz, "%s.zip", output_dir);

    /* Try PowerShell Compress-Archive first (available on Server 2008 R2+ with PS) */
    snprintf(cmd, sizeof(cmd),
             "powershell -NoProfile -Command \"Compress-Archive -Path '%s' "
             "-DestinationPath '%s' -Force\" 2>NUL",
             output_dir, archive_path);

    log_verbose("archive: trying PowerShell...");
    ret = system(cmd);

    if (ret == 0 && plat_file_exists(archive_path)) {
        return 0;
    }

    /* Fallback: use tar if available (Windows 10+ has built-in tar) */
    {
        char parent[MAX_PATH_LEN];
        const char *dirname;

        snprintf(parent, sizeof(parent), "%s", output_dir);
        {
            char *sep = strrchr(parent, '\\');
            if (!sep) sep = strrchr(parent, '/');
            if (!sep) {
                log_error("archive: invalid output path: %s", output_dir);
                return -1;
            }
            dirname = sep + 1;
            *sep = '\0';
        }

        snprintf(archive_path, bufsz, "%s.tar.gz", output_dir);
        snprintf(cmd, sizeof(cmd), "tar czf \"%s\" -C \"%s\" \"%s\" 2>NUL",
                 archive_path, parent, dirname);

        log_verbose("archive: trying tar...");
        ret = system(cmd);

        if (ret == 0 && plat_file_exists(archive_path)) {
            return 0;
        }
    }

    log_error("archive: no archiving tool available");
    log_error("archive: the uncompressed output is at: %s", output_dir);
    return -1;
}

#endif /* _WIN32 */
