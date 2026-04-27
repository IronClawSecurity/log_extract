#ifndef CLI_H
#define CLI_H

typedef struct {
    /* Collector selection */
    int   collect_system;
    int   collect_auth;
    int   collect_app;
    int   collect_network;
    int   collect_filemon;
    int   collect_snapshot;
    int   collect_persistence;
    int   collect_all;

    /* Filters */
    char  time_start[32];
    char  time_end[32];
    char  keyword[256];
    char  exclude[256];
    int   severity_min;
    int   severity_max;
    char  username[128];

    /* Application log paths */
    char  *app_paths[32];
    int    app_path_count;

    /* macOS fs_usage live capture duration (seconds). 0 = disabled. */
    int   fs_usage_secs;

    /* Network target (SSH-based remote collection). Empty = local mode. */
    char  target[256];

    /* Output */
    char  output_dir[1024];
    int   verbose;
    int   quiet;
    int   dry_run;
    int   no_archive;
    int   no_hash;
    int   jsonl;
    int   show_help;
    int   show_version;
} cli_options_t;

/* Parse command line arguments. Returns 0 on success, nonzero on error. */
int  cli_parse(int argc, char *argv[], cli_options_t *opts);

/* Print usage/help text to stdout. */
void cli_print_usage(void);

/* Print version to stdout. */
void cli_print_version(void);

/* Convert parsed CLI options to a filter config. */
void cli_to_filter(const cli_options_t *opts, filter_config_t *filter);

#endif /* CLI_H */
