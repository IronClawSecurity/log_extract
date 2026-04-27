#ifndef ARCHIVE_H
#define ARCHIVE_H

/*
 * Create a compressed archive of the output directory.
 * Linux: tar.gz via system tar
 * Windows: zip via PowerShell or built-in ZIP writer
 *
 * output_dir:  path to the directory to archive
 * archive_path: buffer to receive the created archive path
 * bufsz:       size of archive_path buffer
 *
 * Returns 0 on success, nonzero on failure.
 */
int archive_create(const char *output_dir, char *archive_path, size_t bufsz);

#endif /* ARCHIVE_H */
