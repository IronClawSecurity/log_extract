# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`log_extract` is a single-binary C99 forensic log extraction tool for Linux, macOS, and Windows. It collects, filters, and packages system logs into a hash-verified archive for incident response and forensic investigations.

## Build Commands

```bash
make                # Build for current platform (Linux/macOS → log_extract, Windows MinGW → log_extract.exe)
make clean          # Remove build/ directory and binaries
mingw32-make        # Windows build via MinGW
```

The MSVC build is a single explicit `cl` invocation listed in `README.md` — there's no Makefile path for MSVC, so update the README command list when adding/removing source files.

There are **no tests, no linter config, and no CI**. The only correctness signals are:
1. `gcc -Wall -Wextra -pedantic -std=c99` warnings (the Makefile already enforces these)
2. Manual run: `./log_extract --dry-run` then `./log_extract -a -o /tmp/test`

When changing code, build clean and check for new warnings — the Makefile is strict and any new warning should be treated as a regression.

## Architecture

### Collector pattern (the central abstraction)

Every log source is a **collector** that implements three functions: `init`, `run`, `cleanup` (see `include/collector.h`). Collectors are registered into a `collector_registry_t` at startup by `collector_register_platform()` in `src/collector.c`, then `collector_registry_run_all()` walks the registry, calling the lifecycle functions on every enabled collector.

A collector communicates results back through fields on its own `collector_t` struct: `lines_collected`, `status` (0=ok, 1=warn/partial, 2=skip, 3=error), and `status_msg`. The orchestrator never inspects collected files — it only reads these fields to build the summary.

**To add a new collector**:
1. Create `include/collectors/<name>.h` with the three function declarations
2. Create `src/collect_<name>.c` implementing them
3. Register it in `collector_register_platform()` in `src/collector.c`
4. Add the source file to `SRC_COMMON` (or the platform-specific list) in the `Makefile`
5. If it needs CLI flags, extend `cli_options_t` in `include/cli.h`, parse in `src/cli.c`, and wire enabling in `enable_collectors()` in `src/main.c`

### Platform isolation

Cross-platform code lives in common files. Platform-specific code is split three ways:
- **Compile-time selection** in `Makefile`: Linux/macOS gets `platform_linux.c`, `collect_syslog.c`, `archive_linux.c`; Windows gets `platform_win32.c`, `collect_eventlog.c`, `archive_win32.c`
- **`#ifdef _WIN32` / `#ifndef _WIN32` / `#ifdef __APPLE__`** inside collector files that are compiled on all platforms (auth, applog, netlog, filemon). These files have separate Linux, macOS, and Windows code paths in the same source file
- **`platform.h` abstractions** (`plat_mkdir_p`, `plat_path_join`, `plat_exec_capture`, `plat_parse_timestamp`, etc.) so collector code doesn't directly call POSIX or Win32 APIs

When extending a collector, keep these three paths in sync — do not add a feature on Linux without considering whether the macOS/Windows branches need an equivalent or an explicit "not implemented" stub (see `collect_auth.c` and `collect_filemon.c` Windows stubs as the pattern).

### Filter pipeline

`filter_config_t` (in `include/filter.h`) is built once from CLI options by `cli_to_filter()` and passed read-only to every collector's `init`. Collectors apply filters per-line themselves — there is no central filter loop. Available helpers: `filter_match_keyword`, `filter_match_time`, `filter_match_severity`, `filter_match_user`, `filter_match_line` (combines keyword+user).

The `--user` flag is interpreted differently per collector: text grep for syslog/applog/netlog, `ut_user` field match for wtmp/btmp, UID resolution via `getpwnam` for auditd, and XML element match (`TargetUserName`/`SubjectUserName`) for Windows Event Log. When changing user-filtering behavior, update the per-collector table in `README.md` "User-Specific Collection".

### Output and packaging

`main.c` builds the output path as `<opts.output_dir>/<hostname>_<timestamp>/`, then collectors write into `<that>/<collector.subdir>/`. After all collectors run, `archive_create()` packages the directory (tar.gz on Linux/macOS, zip on Windows) and `hash_sha256_file()` writes a `.sha256` sidecar.

The SHA-256 implementation in `src/hash.c` is a self-contained public-domain implementation — there is no OpenSSL or other crypto dependency. Don't replace it with a system call.

## Conventions

### Strict C99, no external dependencies

The codebase compiles with `-std=c99 -pedantic` and depends on **only** libc + platform APIs (POSIX on Linux/macOS, Win32 + `wevtapi`/`shlwapi`/`advapi32` on Windows). Do not introduce dependencies. Variable declarations should be at the top of blocks where C99 strictness matters, though mid-block declarations do appear in the codebase.

### Shell-safety for `system()` calls

Several collectors shell out (`journalctl`, `log show`, `praudit`, `tar`). All user-controlled strings going into shell commands **must** be validated with `str_is_shell_safe()` (alphanumerics, `-_./: `, space) before being interpolated, or escaped with `str_shell_escape()`. See `collect_syslog.c` `build_log_command()` and `archive_linux.c` for the pattern. Never pass `filter->username`, `filter->keyword`, or paths to shell without one of these.

### Logging

Use the `log_info` / `log_warn` / `log_error` / `log_verbose` macros from `util.h` rather than `printf`/`fprintf`. They respect the `g_quiet` and `g_verbose` globals set from CLI flags. `log_verbose` only fires when `-v` is passed.

### Memory

`safe_malloc` / `safe_realloc` / `safe_strdup` exit on allocation failure — there is no recovery path. The only allocations the program manually frees are `opts.app_paths[i]` strings in `main.c`. Other transient allocations are intentionally process-lifetime; do not add cleanup churn.

### Status reporting

Always set `self->status` AND `self->status_msg` together when reporting non-OK state. Status codes: `0=OK`, `1=WARN/partial`, `2=SKIP`, `3=ERROR`. The summary printer in `main.c::print_summary` switches on these.

### Style

- Comments are sparse and explain *why* (constraints, formats, security rationale). Don't add comments that describe what the code does.
- Functions are small and file-scoped (`static`) unless exported via a header.
- Header guards are `#ifndef NAME_H` style.
- The `log_extract.h` umbrella header pulls in the common headers (`util.h`, `platform.h`, `filter.h`, `collector.h`, `cli.h`) — most `.c` files just `#include "log_extract.h"` plus their specific collector header.
