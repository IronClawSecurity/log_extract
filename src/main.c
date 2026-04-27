#include "log_extract.h"
#include "archive.h"
#include "hash.h"
#include "collectors/applog.h"

applog_config_t g_applog_config;

static void enable_collectors(collector_registry_t *reg, const cli_options_t *opts)
{
    int i;
    for (i = 0; i < reg->count; i++) {
        collector_t *c = &reg->items[i];
        if (opts->collect_all) {
            c->enabled = 1;
        } else {
            if (opts->collect_system && strcmp(c->name, "system") == 0)
                c->enabled = 1;
            if (opts->collect_auth && strcmp(c->name, "auth") == 0)
                c->enabled = 1;
            if (opts->collect_app && strcmp(c->name, "app") == 0)
                c->enabled = 1;
            if (opts->collect_network && strcmp(c->name, "network") == 0)
                c->enabled = 1;
            if (opts->collect_filemon && strcmp(c->name, "filemon") == 0)
                c->enabled = 1;
        }
    }
}

static void print_summary(const collector_registry_t *reg,
                           const char *output_dir,
                           const char *archive_path,
                           const char *hash_hex)
{
    char hostname[256];
    int i;

    plat_get_hostname(hostname, sizeof(hostname));

    printf("\n=== %s summary ===\n", LOG_EXTRACT_NAME);
    printf("Host:       %s\n", hostname);
    printf("Output:     %s\n", output_dir);
    printf("Collectors:\n");

    for (i = 0; i < reg->count; i++) {
        const collector_t *c = &reg->items[i];
        const char *stat;
        switch (c->status) {
            case 0: stat = "OK";   break;
            case 1: stat = "WARN"; break;
            case 2: stat = "SKIP"; break;
            default: stat = "ERR"; break;
        }
        if (c->status == 2 && !c->enabled) {
            printf("  %-10s %-6s disabled\n", c->name, stat);
        } else if (c->status == 2) {
            printf("  %-10s %-6s %s\n", c->name, stat,
                   c->status_msg[0] ? c->status_msg : "no data found");
        } else if (c->lines_collected > 0) {
            printf("  %-10s %-6s %ld lines\n", c->name, stat,
                   c->lines_collected);
        } else {
            printf("  %-10s %-6s %s\n", c->name, stat,
                   c->status_msg[0] ? c->status_msg : "");
        }
    }

    if (archive_path && archive_path[0])
        printf("Archive:    %s\n", archive_path);
    if (hash_hex && hash_hex[0])
        printf("SHA-256:    %s\n", hash_hex);
}

static void print_dry_run(const collector_registry_t *reg)
{
    int i;
    printf("Dry run — the following collectors would execute:\n\n");
    for (i = 0; i < reg->count; i++) {
        const collector_t *c = &reg->items[i];
        if (c->enabled)
            printf("  [+] %s — %s\n", c->name, c->description);
        else
            printf("  [-] %s — disabled\n", c->name);
    }
}

int main(int argc, char *argv[])
{
    cli_options_t opts;
    filter_config_t filter;
    collector_registry_t registry;
    char hostname[256];
    char timestamp[64];
    char output_dir[MAX_PATH_LEN];
    char archive_path[MAX_PATH_LEN] = {0};
    char hash_hex[65] = {0};
    int i, any_data;

    /* Parse CLI */
    if (cli_parse(argc, argv, &opts) != 0) {
        fprintf(stderr, "\nRun '%s --help' for usage.\n", LOG_EXTRACT_NAME);
        return 2;
    }

    if (opts.show_help) {
        cli_print_usage();
        return 0;
    }
    if (opts.show_version) {
        cli_print_version();
        return 0;
    }

    /* Apply global settings */
    g_verbose = opts.verbose;
    g_quiet = opts.quiet;

    /* Set up app log config from CLI */
    memset(&g_applog_config, 0, sizeof(g_applog_config));
    for (i = 0; i < opts.app_path_count && i < 32; i++)
        g_applog_config.app_paths[i] = opts.app_paths[i];
    g_applog_config.app_path_count = opts.app_path_count;

    /* Build filter */
    cli_to_filter(&opts, &filter);

    /* Build output directory: base/hostname_timestamp/ */
    plat_get_hostname(hostname, sizeof(hostname));
    plat_timestamp_now(timestamp, sizeof(timestamp));
    snprintf(output_dir, sizeof(output_dir), "%s%c%s_%s",
             opts.output_dir, PATH_SEP, hostname, timestamp);

    /* Register collectors */
    collector_registry_init(&registry);
    collector_register_platform(&registry);
    enable_collectors(&registry, &opts);

    /* Dry run? */
    if (opts.dry_run) {
        print_dry_run(&registry);
        return 0;
    }

    /* Create output directory */
    if (plat_mkdir_p(output_dir) != 0) {
        log_error("Failed to create output directory: %s", output_dir);
        return 1;
    }

    log_info("Output directory: %s", output_dir);

    /* Run collectors */
    collector_registry_run_all(&registry, &filter, output_dir);

    /* Check if any collector produced data */
    any_data = 0;
    for (i = 0; i < registry.count; i++) {
        if (registry.items[i].enabled && registry.items[i].status <= 1
            && registry.items[i].lines_collected > 0) {
            any_data = 1;
            break;
        }
    }

    if (!any_data) {
        log_warn("No data was collected from any source");
    }

    /* Archive */
    if (!opts.no_archive && any_data) {
        log_info("Creating archive...");
        if (archive_create(output_dir, archive_path, sizeof(archive_path)) != 0) {
            log_error("Failed to create archive");
            print_summary(&registry, output_dir, NULL, NULL);
            return 1;
        }
        log_info("Archive: %s", archive_path);
    }

    /* Hash */
    if (!opts.no_hash && !opts.no_archive && archive_path[0] && any_data) {
        log_info("Computing SHA-256 hash...");
        if (hash_sha256_file(archive_path, hash_hex, sizeof(hash_hex)) != 0) {
            log_error("Failed to compute hash");
            print_summary(&registry, output_dir, archive_path, NULL);
            return 1;
        }
        hash_write_sidecar(archive_path, hash_hex);
    }

    /* Summary */
    print_summary(&registry, output_dir, archive_path, hash_hex);

    /* Free app paths */
    for (i = 0; i < opts.app_path_count; i++)
        free(opts.app_paths[i]);

    return any_data ? 0 : 1;
}
