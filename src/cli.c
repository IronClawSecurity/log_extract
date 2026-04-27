#include "log_extract.h"

static void cli_defaults(cli_options_t *opts)
{
    memset(opts, 0, sizeof(*opts));
    opts->collect_all = 1;
    opts->severity_min = -1;
    opts->severity_max = -1;
    snprintf(opts->output_dir, sizeof(opts->output_dir), "./output");
}

static int match_flag(const char *arg, const char *short_f, const char *long_f)
{
    if (short_f && strcmp(arg, short_f) == 0) return 1;
    if (long_f && strcmp(arg, long_f) == 0) return 1;
    return 0;
}

static const char *next_arg(int argc, char *argv[], int i, const char *flag)
{
    if (i + 1 >= argc) {
        log_error("Option '%s' requires a value", flag);
        return NULL;
    }
    return argv[i + 1];
}

int cli_parse(int argc, char *argv[], cli_options_t *opts)
{
    int i;
    int any_collector = 0;

    cli_defaults(opts);

    for (i = 1; i < argc; i++) {
        const char *arg = argv[i];

        /* Collector flags */
        if (match_flag(arg, "-S", "--system")) {
            opts->collect_system = 1; any_collector = 1;
        } else if (match_flag(arg, "-A", "--auth")) {
            opts->collect_auth = 1; any_collector = 1;
        } else if (match_flag(arg, "-P", "--app")) {
            opts->collect_app = 1; any_collector = 1;
        } else if (match_flag(arg, "-N", "--network")) {
            opts->collect_network = 1; any_collector = 1;
        } else if (match_flag(arg, "-F", "--filemon")) {
            opts->collect_filemon = 1; any_collector = 1;
        } else if (match_flag(arg, "-a", "--all")) {
            opts->collect_all = 1;
        }
        /* Filter flags */
        else if (match_flag(arg, NULL, "--from")) {
            const char *v = next_arg(argc, argv, i, arg);
            if (!v) return -1;
            snprintf(opts->time_start, sizeof(opts->time_start), "%s", v);
            i++;
        } else if (match_flag(arg, NULL, "--to")) {
            const char *v = next_arg(argc, argv, i, arg);
            if (!v) return -1;
            snprintf(opts->time_end, sizeof(opts->time_end), "%s", v);
            i++;
        } else if (match_flag(arg, NULL, "--grep")) {
            const char *v = next_arg(argc, argv, i, arg);
            if (!v) return -1;
            snprintf(opts->keyword, sizeof(opts->keyword), "%s", v);
            i++;
        } else if (match_flag(arg, NULL, "--level-min")) {
            const char *v = next_arg(argc, argv, i, arg);
            if (!v) return -1;
            opts->severity_min = atoi(v);
            i++;
        } else if (match_flag(arg, NULL, "--level-max")) {
            const char *v = next_arg(argc, argv, i, arg);
            if (!v) return -1;
            opts->severity_max = atoi(v);
            i++;
        } else if (match_flag(arg, NULL, "--user")) {
            const char *v = next_arg(argc, argv, i, arg);
            if (!v) return -1;
            snprintf(opts->username, sizeof(opts->username), "%s", v);
            i++;
        }
        /* App log paths */
        else if (match_flag(arg, NULL, "--app-path")) {
            const char *v = next_arg(argc, argv, i, arg);
            if (!v) return -1;
            if (opts->app_path_count < 32) {
                opts->app_paths[opts->app_path_count++] = safe_strdup(v);
            } else {
                log_warn("Maximum of 32 app paths supported, ignoring: %s", v);
            }
            i++;
        }
        /* Output flags */
        else if (match_flag(arg, "-o", "--output")) {
            const char *v = next_arg(argc, argv, i, arg);
            if (!v) return -1;
            snprintf(opts->output_dir, sizeof(opts->output_dir), "%s", v);
            i++;
        } else if (match_flag(arg, "-v", "--verbose")) {
            opts->verbose = 1;
        } else if (match_flag(arg, "-q", "--quiet")) {
            opts->quiet = 1;
        } else if (match_flag(arg, NULL, "--dry-run")) {
            opts->dry_run = 1;
        } else if (match_flag(arg, NULL, "--no-archive")) {
            opts->no_archive = 1;
        } else if (match_flag(arg, NULL, "--no-hash")) {
            opts->no_hash = 1;
        } else if (match_flag(arg, "-h", "--help")) {
            opts->show_help = 1;
            return 0;
        } else if (match_flag(arg, NULL, "--version")) {
            opts->show_version = 1;
            return 0;
        } else {
            log_error("Unknown option: %s", arg);
            return -1;
        }
    }

    /* If any specific collector was selected, turn off collect_all */
    if (any_collector)
        opts->collect_all = 0;

    return 0;
}

void cli_print_usage(void)
{
    printf("Usage: %s [OPTIONS]\n", LOG_EXTRACT_NAME);
    printf("\n");
    printf("Forensic log extraction tool. Collects and packages system logs.\n");
    printf("\n");
    printf("Collector selection (default: all applicable to this OS):\n");
    printf("  -S, --system         System logs (syslog/journald or Windows Event Log)\n");
    printf("  -A, --auth           Authentication/login logs\n");
    printf("  -P, --app            Application logs (IIS/Apache/nginx)\n");
    printf("  -N, --network        Network/firewall logs\n");
    printf("  -F, --filemon        File modification audit logs\n");
    printf("  -a, --all            All collectors (default)\n");
    printf("\n");
    printf("Filters:\n");
    printf("  --from DATETIME      Start time, format: \"YYYY-MM-DD HH:MM:SS\"\n");
    printf("  --to   DATETIME      End time,   format: \"YYYY-MM-DD HH:MM:SS\"\n");
    printf("  --grep PATTERN       Include only lines matching pattern (substring)\n");
    printf("  --level-min N        Minimum severity (0=emergency .. 7=debug)\n");
    printf("  --level-max N        Maximum severity\n");
    printf("  --user USERNAME      Filter for specific user\n");
    printf("\n");
    printf("Application log paths:\n");
    printf("  --app-path PATH      Add a custom log file/directory (repeatable)\n");
    printf("\n");
    printf("Output:\n");
    printf("  -o, --output DIR     Output base directory (default: ./output)\n");
    printf("  -v, --verbose        Verbose output\n");
    printf("  -q, --quiet          Suppress non-error output\n");
    printf("  --dry-run            Show what would be collected, don't collect\n");
    printf("  --no-archive         Skip archive creation\n");
    printf("  --no-hash            Skip SHA-256 hash of archive\n");
    printf("  -h, --help           Show this help message\n");
    printf("  --version            Show version\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s -a                              Collect everything\n", LOG_EXTRACT_NAME);
    printf("  %s -S -A --user jsmith             System + auth logs for user jsmith\n", LOG_EXTRACT_NAME);
    printf("  %s -A --from \"2026-03-01 00:00:00\" Auth logs from March 1 onward\n", LOG_EXTRACT_NAME);
    printf("  %s -P --app-path /var/log/nginx    Collect nginx logs\n", LOG_EXTRACT_NAME);
    printf("  %s -S -N --grep \"failed\"           System + network logs matching \"failed\"\n", LOG_EXTRACT_NAME);
}

void cli_print_version(void)
{
    printf("%s version %s\n", LOG_EXTRACT_NAME, LOG_EXTRACT_VERSION);
}

void cli_to_filter(const cli_options_t *opts, filter_config_t *filter)
{
    memset(filter, 0, sizeof(*filter));

    if (opts->time_start[0])
        filter->time_start = plat_parse_timestamp(opts->time_start);
    if (opts->time_end[0])
        filter->time_end = plat_parse_timestamp(opts->time_end);

    snprintf(filter->keyword, sizeof(filter->keyword), "%s", opts->keyword);
    filter->severity_min = opts->severity_min;
    filter->severity_max = opts->severity_max;
    snprintf(filter->username, sizeof(filter->username), "%s", opts->username);
}
