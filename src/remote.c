#include "log_extract.h"
#include "remote.h"

#ifdef _WIN32

int remote_run(const cli_options_t *opts, int argc, char *argv[])
{
    (void)opts; (void)argc; (void)argv;
    log_error("--target is only supported on Linux/macOS hosts");
    return 1;
}

#else

#include <sys/wait.h>
#include <unistd.h>

/* Minimal allowlist for --target value: user@host, only chars that are safe
 * to interpolate into ssh/scp commands. Rejects spaces, quotes, $, `, ;, &, |. */
static int target_is_safe(const char *t)
{
    if (!t || !t[0]) return 0;
    for (; *t; t++) {
        char c = *t;
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') ||
            c == '@' || c == '-' || c == '_' || c == '.' || c == ':')
            continue;
        return 0;
    }
    return 1;
}

/* Build a shell-quoted version of arg into out. Uses single-quote escaping
 * via str_shell_escape so any user-supplied value is safe. */
static int quote_arg(const char *arg, char *out, size_t outsz)
{
    return str_shell_escape(arg, out, outsz);
}

int remote_run(const cli_options_t *opts, int argc, char *argv[])
{
    char remote_dir[256];
    char remote_bin[512];
    char remote_out[512];
    char cmd[8192];
    char timestamp[64];
    char hostname[64];
    int ret;
    int i;
    size_t off;

    if (!target_is_safe(opts->target)) {
        log_error("--target value contains unsafe characters: %s", opts->target);
        return 1;
    }

    /* The local binary path is argv[0]. If it isn't absolute or doesn't exist,
     * the user needs to invoke us with a full path. */
    if (!plat_file_exists(argv[0])) {
        log_error("cannot locate local binary at %s "
                  "(invoke %s with an explicit path for --target mode)",
                  argv[0], LOG_EXTRACT_NAME);
        return 1;
    }

    plat_timestamp_now(timestamp, sizeof(timestamp));
    snprintf(remote_dir, sizeof(remote_dir),
             "/tmp/log_extract_%s", timestamp);
    snprintf(remote_bin, sizeof(remote_bin),
             "%s/log_extract", remote_dir);
    snprintf(remote_out, sizeof(remote_out),
             "%s/output", remote_dir);

    log_info("remote: target=%s", opts->target);

    /* 1. Create remote staging directory */
    snprintf(cmd, sizeof(cmd),
             "ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new "
             "%s 'mkdir -p %s'",
             opts->target, remote_dir);
    log_verbose("remote: %s", cmd);
    ret = system(cmd);
    if (ret != 0) {
        log_error("remote: failed to create remote dir (ssh exit %d). "
                  "Check that ssh keys are configured for %s.",
                  WEXITSTATUS(ret), opts->target);
        return 1;
    }

    /* 2. Copy binary up */
    {
        char src_q[1024], dst_q[1024];
        if (quote_arg(argv[0], src_q, sizeof(src_q)) != 0) {
            log_error("remote: cannot escape local path");
            return 1;
        }
        snprintf(dst_q, sizeof(dst_q), "%s:%s", opts->target, remote_bin);
        snprintf(cmd, sizeof(cmd),
                 "scp -o BatchMode=yes -q %s %s",
                 src_q, dst_q);
        log_verbose("remote: %s", cmd);
        ret = system(cmd);
        if (ret != 0) {
            log_error("remote: scp upload failed (exit %d)", WEXITSTATUS(ret));
            goto cleanup;
        }
    }

    /* 3. Build remote argv (skip --target VALUE pair, force -o to remote_out) */
    off = (size_t)snprintf(cmd, sizeof(cmd),
                           "ssh -o BatchMode=yes %s 'chmod +x %s && %s",
                           opts->target, remote_bin, remote_bin);
    {
        int skip_next = 0;
        for (i = 1; i < argc; i++) {
            char qbuf[1024];
            if (skip_next) { skip_next = 0; continue; }
            if (strcmp(argv[i], "--target") == 0) {
                skip_next = 1;
                continue;
            }
            /* Strip user-supplied -o; we override with remote_out below */
            if (strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--output") == 0) {
                skip_next = 1;
                continue;
            }
            if (quote_arg(argv[i], qbuf, sizeof(qbuf)) != 0) {
                log_error("remote: cannot escape arg: %s", argv[i]);
                ret = 1;
                goto cleanup;
            }
            off += (size_t)snprintf(cmd + off, sizeof(cmd) - off, " %s", qbuf);
            if (off >= sizeof(cmd)) {
                log_error("remote: command line too long");
                ret = 1;
                goto cleanup;
            }
        }
        off += (size_t)snprintf(cmd + off, sizeof(cmd) - off,
                                " -o %s'", remote_out);
        if (off >= sizeof(cmd)) {
            log_error("remote: command line too long");
            ret = 1;
            goto cleanup;
        }
    }

    log_info("remote: executing log_extract on %s...", opts->target);
    log_verbose("remote: %s", cmd);
    ret = system(cmd);
    if (ret != 0) {
        log_warn("remote: remote execution returned %d (continuing with fetch)",
                 WEXITSTATUS(ret));
    }

    /* 4. Locate the remote hostname directory and fetch the archive(s) */
    if (plat_get_hostname(hostname, sizeof(hostname)) != 0) {
        snprintf(hostname, sizeof(hostname), "remote");
    }
    if (plat_mkdir_p(opts->output_dir) != 0) {
        log_error("remote: cannot create local output dir %s", opts->output_dir);
        ret = 1;
        goto cleanup;
    }

    snprintf(cmd, sizeof(cmd),
             "scp -o BatchMode=yes -q -r %s:%s/* %s/",
             opts->target, remote_out, opts->output_dir);
    log_verbose("remote: %s", cmd);
    ret = system(cmd);
    if (ret != 0) {
        log_error("remote: scp fetch failed (exit %d)", WEXITSTATUS(ret));
        goto cleanup;
    }

    log_info("remote: fetched results into %s", opts->output_dir);
    ret = 0;

cleanup:
    /* 5. Tear down the remote staging directory. We deliberately do NOT use
     * rm -rf with a wildcard; remote_dir is constructed under /tmp with a
     * timestamp we generated. */
    {
        char cleanup_cmd[1024];
        snprintf(cleanup_cmd, sizeof(cleanup_cmd),
                 "ssh -o BatchMode=yes %s 'rm -rf %s' 2>/dev/null",
                 opts->target, remote_dir);
        log_verbose("remote: %s", cleanup_cmd);
        system(cleanup_cmd);
    }

    return ret;
}

#endif /* !_WIN32 */
