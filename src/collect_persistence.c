#include "log_extract.h"
#include "collectors/persistence.h"

/*
 * Persistence collector: artifacts that grant code execution at boot/login.
 * Captures the artifacts themselves (or directory listings + content) rather
 * than their logs — analysts inspect these for unauthorized entries.
 */

typedef struct {
    const char *out_name;
    const char *cmd;        /* either a shell command, or NULL to copy a file */
    const char *file;       /* NULL unless we're copying a single file */
    int         is_dir_list;/* 1 = listing+contents of dir, 0 = single command */
} pers_item_t;

#if defined(_WIN32)
static const pers_item_t pers_items[] = {
    {"scheduled_tasks.csv",  "schtasks /query /fo CSV /v", NULL, 0},
    {"run_hkcu.txt",
     "reg query \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /s",
     NULL, 0},
    {"run_hklm.txt",
     "reg query \"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /s",
     NULL, 0},
    {"runonce_hklm.txt",
     "reg query \"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\" /s",
     NULL, 0},
    {"services.csv",         "sc query state= all", NULL, 0},
    {"winlogon.txt",
     "reg query \"HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" /s",
     NULL, 0},
    {"image_file_options.txt",
     "reg query \"HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\" /s",
     NULL, 0},
    {"startup_folder_user.txt",
     "dir /b /s \"%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\"",
     NULL, 0},
    {"startup_folder_all.txt",
     "dir /b /s \"%PROGRAMDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\"",
     NULL, 0},
    {NULL, NULL, NULL, 0}
};
#elif defined(__APPLE__)
static const pers_item_t pers_items[] = {
    {"launchagents_user.txt",
     "ls -la ~/Library/LaunchAgents/ 2>/dev/null && "
     "echo '--- contents ---' && cat ~/Library/LaunchAgents/*.plist 2>/dev/null",
     NULL, 1},
    {"launchagents_system.txt",
     "ls -la /Library/LaunchAgents/ 2>/dev/null && "
     "echo '--- contents ---' && cat /Library/LaunchAgents/*.plist 2>/dev/null",
     NULL, 1},
    {"launchdaemons.txt",
     "ls -la /Library/LaunchDaemons/ 2>/dev/null && "
     "echo '--- contents ---' && cat /Library/LaunchDaemons/*.plist 2>/dev/null",
     NULL, 1},
    {"system_launchdaemons.txt",
     "ls -la /System/Library/LaunchDaemons/ 2>/dev/null", NULL, 0},
    {"cron_root.txt",         "crontab -u root -l 2>/dev/null", NULL, 0},
    {"cron_user.txt",         "crontab -l 2>/dev/null", NULL, 0},
    {"periodic.txt",          "ls -laR /etc/periodic/ 2>/dev/null", NULL, 0},
    {"loginhook.txt",
     "defaults read com.apple.loginwindow LoginHook 2>/dev/null; "
     "defaults read com.apple.loginwindow LogoutHook 2>/dev/null", NULL, 0},
    {"login_items.txt",
     "osascript -e 'tell application \"System Events\" to get the name of "
     "every login item' 2>/dev/null", NULL, 0},
    {"sudoers.txt",           "cat /etc/sudoers 2>/dev/null && "
                              "ls -la /etc/sudoers.d/ 2>/dev/null && "
                              "cat /etc/sudoers.d/* 2>/dev/null", NULL, 0},
    {"authorized_keys.txt",
     "for d in /Users/*/; do echo \"=== $d ===\"; "
     "cat \"$d/.ssh/authorized_keys\" 2>/dev/null; done", NULL, 0},
    {"kexts.txt",             "kextstat 2>/dev/null", NULL, 0},
    {NULL, NULL, NULL, 0}
};
#else
static const pers_item_t pers_items[] = {
    {"systemd_units.txt",
     "systemctl list-unit-files --no-pager 2>/dev/null", NULL, 0},
    {"systemd_enabled.txt",
     "systemctl list-unit-files --state=enabled --no-pager 2>/dev/null", NULL, 0},
    {"systemd_timers.txt",
     "systemctl list-timers --all --no-pager 2>/dev/null", NULL, 0},
    {"cron_root.txt",          "crontab -u root -l 2>/dev/null", NULL, 0},
    {"cron_dirs.txt",
     "ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ "
     "/etc/cron.weekly/ /etc/cron.monthly/ 2>/dev/null && "
     "echo '--- contents of /etc/cron.d ---' && "
     "cat /etc/cron.d/* 2>/dev/null", NULL, 0},
    {"crontab_etc.txt",        "cat /etc/crontab 2>/dev/null", NULL, 0},
    {"user_crontabs.txt",      "ls -la /var/spool/cron/ /var/spool/cron/crontabs/ 2>/dev/null",
     NULL, 0},
    {"rc_local.txt",           "cat /etc/rc.local 2>/dev/null", NULL, 0},
    {"profile_d.txt",
     "ls -la /etc/profile.d/ 2>/dev/null && "
     "echo '--- contents ---' && cat /etc/profile.d/*.sh 2>/dev/null", NULL, 0},
    {"shells_rc.txt",
     "cat /etc/bashrc /etc/bash.bashrc /etc/zshrc /etc/profile 2>/dev/null", NULL, 0},
    {"sudoers.txt",            "cat /etc/sudoers 2>/dev/null && "
                               "ls -la /etc/sudoers.d/ 2>/dev/null && "
                               "cat /etc/sudoers.d/* 2>/dev/null", NULL, 0},
    {"passwd.txt",             "cat /etc/passwd 2>/dev/null", NULL, 0},
    {"group.txt",              "cat /etc/group 2>/dev/null", NULL, 0},
    {"authorized_keys.txt",
     "for d in /home/*/ /root/; do echo \"=== $d ===\"; "
     "cat \"$d/.ssh/authorized_keys\" 2>/dev/null; done", NULL, 0},
    {"ssh_config.txt",         "cat /etc/ssh/sshd_config 2>/dev/null", NULL, 0},
    {"loaded_modules.txt",     "lsmod 2>/dev/null", NULL, 0},
    {"ld_so_preload.txt",      "cat /etc/ld.so.preload 2>/dev/null", NULL, 0},
    {NULL, NULL, NULL, 0}
};
#endif

int collect_persistence_init(collector_t *self, const filter_config_t *filter,
                             const char *output_dir)
{
    self->filter = filter;
    plat_path_join(self->out_path, sizeof(self->out_path), output_dir, self->subdir);

    if (plat_mkdir_p(self->out_path) != 0) {
        self->status = 3;
        snprintf(self->status_msg, sizeof(self->status_msg), "cannot create output dir");
        return -1;
    }
    return 0;
}

int collect_persistence_run(collector_t *self)
{
    long total = 0;
    int i;

    for (i = 0; pers_items[i].out_name; i++) {
        char out_file[MAX_PATH_LEN];
        int ret;

        plat_path_join(out_file, sizeof(out_file), self->out_path,
                       pers_items[i].out_name);

        log_verbose("persistence: %s", pers_items[i].cmd);
        ret = plat_exec_capture(pers_items[i].cmd, out_file);
        if (ret != 0) {
            log_verbose("persistence: %s returned %d",
                        pers_items[i].out_name, ret);
            /* Best-effort; don't fail the collector for missing tools */
            continue;
        }

        {
            FILE *f = fopen(out_file, "r");
            if (f) {
                char line[MAX_LINE_LEN];
                while (fgets(line, sizeof(line), f)) total++;
                fclose(f);
            }
        }
    }

    self->lines_collected = total;
    if (total == 0) {
        self->status = 1;
        snprintf(self->status_msg, sizeof(self->status_msg),
                 "no persistence indicators captured");
    }
    return 0;
}

void collect_persistence_cleanup(collector_t *self)
{
    (void)self;
}
