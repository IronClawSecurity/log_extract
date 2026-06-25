#ifndef PLATFORM_H
#define PLATFORM_H

#include <time.h>
#include <stddef.h>

/* Directory operations */
int  plat_mkdir_p(const char *path);
int  plat_path_join(char *buf, size_t bufsz, const char *a, const char *b);
int  plat_file_copy(const char *src, const char *dst);
int  plat_file_exists(const char *path);
int  plat_is_directory(const char *path);
int  plat_get_hostname(char *buf, size_t bufsz);

/* Free bytes on the filesystem containing path; -1 on error. */
long long plat_disk_free_bytes(const char *path);

/* Time helpers */
time_t plat_parse_timestamp(const char *str);
int    plat_format_timestamp(time_t t, char *buf, size_t bufsz);
int    plat_timestamp_now(char *buf, size_t bufsz);

/* Process execution (for archive, journalctl, etc.) */
int  plat_exec_capture(const char *cmd, const char *output_file);

#endif /* PLATFORM_H */
