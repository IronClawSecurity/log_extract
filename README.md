# log_extract

Forensic log extraction tool for Linux and Windows systems. Collects, filters, and packages system logs into a structured archive with SHA-256 integrity verification.

Designed for incident response and forensic investigations — deploy to a target machine, run it, and get a single tamper-evident archive of all relevant logs.

---

## Table of Contents

- [Features](#features)
- [Supported Platforms](#supported-platforms)
- [Building](#building)
- [Quick Start](#quick-start)
- [Usage Reference](#usage-reference)
- [Log Sources](#log-sources)
- [Filtering](#filtering)
- [Output Structure](#output-structure)
- [Deployment Guide](#deployment-guide)
- [Examples](#examples)
- [Troubleshooting](#troubleshooting)
- [Architecture](#architecture)

---

## Features

- **Cross-platform**: Single codebase for Linux and Windows (Server 2008+)
- **Modular collectors**: Enable only the log sources you need per engagement
- **User-targeted extraction**: Focus collection on a specific username across all log types
- **Time-range filtering**: Extract logs from a specific window
- **Keyword filtering**: Grep for patterns across all collected sources
- **Severity filtering**: Filter by syslog severity / Windows event level
- **Structured output**: Organized directory tree of collected logs
- **Archive creation**: Automatic tar.gz (Linux) or zip (Windows) packaging
- **Forensic integrity**: SHA-256 hash with sidecar file for chain-of-custody
- **Zero dependencies**: Compiles to a single static binary, no runtime requirements
- **Minimal footprint**: Small binary, runs without installation

---

## Supported Platforms

| Platform | Minimum Version | Compiler |
|----------|----------------|----------|
| Linux | Kernel 2.6+ (any modern distro) | gcc, clang |
| Windows | Server 2008 R2 / Windows 7 | MinGW, MSVC |
| macOS | 10.12+ (for development/testing) | clang (Xcode) |

---

## Building

### Prerequisites

- A C99 compiler (gcc, clang, or MSVC)
- `make` (GNU Make, or nmake on Windows)

### Linux / macOS

```bash
make
```

This produces the `log_extract` binary in the project root.

### Windows (MinGW)

```bash
mingw32-make
```

Produces `log_extract.exe`.

### Windows (MSVC)

```cmd
cl /Iinclude /Fe:log_extract.exe src\main.c src\cli.c src\filter.c src\collector.c src\collect_auth.c src\collect_applog.c src\collect_netlog.c src\collect_filemon.c src\hash.c src\util.c src\platform_win32.c src\collect_eventlog.c src\archive_win32.c /link wevtapi.lib advapi32.lib shlwapi.lib
```

### Clean Build

```bash
make clean && make
```

---

## Quick Start

Collect all available logs from the current machine:

```bash
sudo ./log_extract
```

Collect only authentication logs for a specific user:

```bash
sudo ./log_extract -A --user jsmith
```

Collect system and network logs from the last 24 hours:

```bash
sudo ./log_extract -S -N --from "2026-04-26 00:00:00"
```

Preview what would be collected without actually collecting:

```bash
./log_extract --dry-run
```

---

## Usage Reference

```
log_extract [OPTIONS]
```

### Collector Selection

By default, all collectors applicable to the current OS are enabled. Selecting any specific collector disables the others.

| Flag | Long Form | Description |
|------|-----------|-------------|
| `-S` | `--system` | System logs (syslog/journald on Linux, Event Log on Windows) |
| `-A` | `--auth` | Authentication and login logs |
| `-P` | `--app` | Application logs (Apache/nginx/IIS) |
| `-N` | `--network` | Network and firewall logs |
| `-F` | `--filemon` | File modification audit logs |
| `-a` | `--all` | All collectors (default) |

Flags can be combined: `-S -A` collects system + auth logs only.

### Filter Options

| Flag | Description |
|------|-------------|
| `--from DATETIME` | Start of time window. Format: `"YYYY-MM-DD HH:MM:SS"` |
| `--to DATETIME` | End of time window. Format: `"YYYY-MM-DD HH:MM:SS"` |
| `--grep PATTERN` | Include only lines/events containing this substring |
| `--level-min N` | Minimum severity level (0=emergency, 7=debug) |
| `--level-max N` | Maximum severity level |
| `--user USERNAME` | Filter for a specific user across all collectors |

### Application Log Paths

| Flag | Description |
|------|-------------|
| `--app-path PATH` | Add a custom log file or directory to collect. Can be repeated up to 32 times. |

### Output Options

| Flag | Long Form | Description |
|------|-----------|-------------|
| `-o` | `--output DIR` | Base output directory (default: `./output`) |
| `-v` | `--verbose` | Show detailed progress |
| `-q` | `--quiet` | Suppress non-error output |
| | `--dry-run` | Show what would be collected, don't do it |
| | `--no-archive` | Skip archive creation (keep directory only) |
| | `--no-hash` | Skip SHA-256 hash computation |
| `-h` | `--help` | Show help text |
| | `--version` | Show version |

---

## Log Sources

### Linux

| Collector | Sources | Notes |
|-----------|---------|-------|
| System (`-S`) | `/var/log/syslog`, `/var/log/messages`, journalctl | Automatically detects which are available |
| Auth (`-A`) | `/var/log/auth.log`, `/var/log/secure`, `/var/log/wtmp`, `/var/log/btmp` | wtmp/btmp parsed to human-readable text; btmp requires root |
| App (`-P`) | `/var/log/apache2/`, `/var/log/httpd/`, `/var/log/nginx/`, custom paths | Use `--app-path` for non-standard locations |
| Network (`-N`) | `/var/log/ufw.log`, `/var/log/firewalld`, `/var/log/iptables.log`, `/var/log/kern.log` (netfilter entries) | kern.log is scanned for firewall-related lines only |
| Filemon (`-F`) | `/var/log/audit/audit.log` | Requires auditd to be active; user filter resolves to UID |

### Windows

| Collector | Sources | Notes |
|-----------|---------|-------|
| System (`-S`) | Event Log: System, Application, Security channels | Uses Evt* API (Server 2008+); Security channel requires admin |
| Auth (`-A`) | Security Event Log: EventIDs 4624, 4625, 4634, 4647, 4648 | Logon, failed logon, logoff events; user filter matches TargetUserName |
| App (`-P`) | `C:\inetpub\logs\LogFiles\`, custom paths | Use `--app-path` for custom application logs |
| Network (`-N`) | `C:\Windows\System32\LogFiles\Firewall\pfirewall.log`, Firewall event channel | Windows Firewall must be configured to log |
| Filemon (`-F`) | Security Event Log: EventIDs 4663, 4656, 4660, 4670 | File access auditing must be enabled; user filter matches SubjectUserName |

---

## Filtering

### Time Range

Filter logs to a specific window. Both `--from` and `--to` are optional and can be used independently.

```bash
# Everything after March 1
./log_extract --from "2026-03-01 00:00:00"

# Everything before April 15
./log_extract --to "2026-04-15 23:59:59"

# Specific 3-day window
./log_extract --from "2026-04-01 00:00:00" --to "2026-04-03 23:59:59"
```

Timestamps are interpreted in local time.

### Keyword Search

Substring matching across all log lines/events:

```bash
# Find all entries mentioning "failed"
./log_extract --grep "failed"

# Find SSH-related entries
./log_extract -A --grep "sshd"
```

### Severity Filtering

Uses the syslog severity scale (0=emergency through 7=debug). On Windows, this maps to event levels (1=Critical through 5=Verbose).

```bash
# Only errors and above (emergency through error)
./log_extract --level-min 0 --level-max 3

# Only warnings
./log_extract --level-min 4 --level-max 4
```

### User-Specific Collection

The `--user` flag focuses extraction on a specific username. How this is applied depends on the collector:

| Collector | Linux Behavior | Windows Behavior |
|-----------|---------------|-----------------|
| System | Grep for username in log lines | N/A (system events rarely have user context) |
| Auth | Match username in auth.log lines + `ut_user` in wtmp/btmp | Match TargetUserName/SubjectUserName in Security events |
| App | Grep for username in access log lines | Same text-based grep |
| Network | Grep for username (best-effort) | Grep in pfirewall.log |
| Filemon | Resolve to UID, match `uid=`/`auid=` in auditd | Match SubjectUserName in Security events |

---

## Output Structure

```
output/
  hostname_20260427_153045/        # Host + timestamp directory
    system/
      syslog                       # Filtered syslog entries
      messages                     # Filtered messages entries
      journald.log                 # Journalctl output
    auth/
      auth.log                     # Filtered auth log
      wtmp.txt                     # Parsed wtmp (human-readable)
      btmp.txt                     # Parsed btmp (human-readable)
    app/
      apache2/
        access.log                 # Filtered Apache access log
        error.log                  # Filtered Apache error log
      nginx/
        access.log
    network/
      ufw.log                     # Filtered UFW log
      kern_netfilter.log           # Kernel firewall entries
    filemon/
      audit.log                    # Filtered auditd entries
  hostname_20260427_153045.tar.gz  # Compressed archive
  hostname_20260427_153045.tar.gz.sha256  # Hash sidecar
```

The `.sha256` file is in the standard checksum format and can be verified with:

```bash
sha256sum -c hostname_20260427_153045.tar.gz.sha256
```

---

## Deployment Guide

### Pre-Engagement Checklist

1. **Build for the target platform** — compile on a matching OS or cross-compile
2. **Test the binary** — run `./log_extract --dry-run` on a test system
3. **Plan your collection scope** — determine which collectors and filters you need
4. **Verify access** — most log sources require root/Administrator privileges

### Deploying to a Target Machine

1. Copy the single `log_extract` binary to the target via your preferred method (USB, SCP, SMB, etc.)
2. Open a terminal / command prompt with elevated privileges
3. Run the extraction:

**Linux:**
```bash
sudo ./log_extract -a -o /tmp/evidence
```

**Windows (run as Administrator):**
```cmd
log_extract.exe -a -o C:\temp\evidence
```

4. Retrieve the archive file and its `.sha256` sidecar
5. Verify integrity on your analysis machine:

```bash
sha256sum -c evidence.tar.gz.sha256
```

### Permissions Required

| Platform | Privilege | Required For |
|----------|-----------|-------------|
| Linux | root | `/var/log/secure`, `/var/log/btmp`, `/var/log/audit/audit.log`, journalctl |
| Linux | read access | `/var/log/syslog`, `/var/log/auth.log`, `/var/log/wtmp` |
| Windows | Administrator | Security event log, file audit events |
| Windows | Standard user | Application event log, firewall log file |

If run without sufficient privileges, the tool will warn about inaccessible sources and continue collecting from accessible ones.

### Output Size Considerations

- Unfiltered collection on an active server can produce hundreds of MB of logs
- Use `--from` / `--to` to limit the time window
- Use specific collector flags (`-A`, `-S`, etc.) to collect only what you need
- Use `--no-archive` if you want to review the raw files before archiving

---

## Examples

### Incident Response — Investigate Compromised Account

```bash
sudo ./log_extract -A -F --user compromised_user \
  --from "2026-04-20 00:00:00" \
  -o /tmp/ir_evidence
```

Collects authentication events and file modification audit logs for `compromised_user` since April 20th.

### Compliance Audit — Full System Log Collection

```bash
sudo ./log_extract -a \
  --from "2026-01-01 00:00:00" --to "2026-03-31 23:59:59" \
  -o /tmp/q1_audit
```

Collects all available logs for Q1 2026.

### Investigate Failed Login Attempts

```bash
sudo ./log_extract -A --grep "failed" -v
```

Collects all auth logs containing "failed" with verbose output.

### Collect Custom Application Logs

```bash
sudo ./log_extract -P \
  --app-path /opt/myapp/logs \
  --app-path /var/log/custom_service.log \
  -o /tmp/app_review
```

Collects standard web server logs plus custom application log paths.

### Windows — Collect Security Events for Specific User

```cmd
log_extract.exe -S -A -F --user jsmith -o C:\temp\investigation
```

Collects system event logs, authentication events, and file access audit events filtered for user `jsmith`.

### Preview Without Collecting

```bash
./log_extract -S -A --from "2026-04-01 00:00:00" --dry-run
```

Shows which collectors would run and which sources exist, without extracting any data.

---

## Troubleshooting

### "Permission denied" warnings

Most log sources require elevated privileges. Run with `sudo` (Linux) or as Administrator (Windows).

### "No syslog sources found"

The system may use a non-standard log location. Check:
- Is the system using systemd-journald exclusively? The tool will try `journalctl` automatically.
- Are logs in a custom path? Use `--app-path` to include them.

### "journalctl returned non-zero"

The `journalctl` command may not be available (older systems without systemd). Text-based syslog files will still be collected if present.

### Archive creation fails

- **Linux**: Ensure `tar` is installed (it is on virtually all systems)
- **Windows**: Ensure PowerShell is available, or the tool will attempt `tar` as a fallback
- Use `--no-archive` to skip archiving and retrieve the raw output directory

### No data collected

- Verify the log files exist: `ls -la /var/log/` (Linux) or check Event Viewer (Windows)
- Check if your time filter is too narrow
- Check if your keyword filter is too restrictive
- Run with `-v` (verbose) to see detailed progress per source

### Windows Event Log access denied

The Security event log requires `SeSecurityPrivilege`. Run the command prompt as Administrator. If using a service account, ensure it has "Manage auditing and security log" privilege.

### Large output files

For systems with heavy logging:
- Use `--from` / `--to` to limit the time range
- Select only the collectors you need (e.g., `-A` instead of `-a`)
- Use `--grep` to pre-filter for relevant entries

---

## Architecture

```
main.c
  |
  +-- cli.c          Parse command line arguments
  +-- filter.c       Time/keyword/severity/user matching
  +-- collector.c    Collector registry and execution loop
  |     |
  |     +-- collect_syslog.c    Linux system logs
  |     +-- collect_eventlog.c  Windows Event Log (Evt* API)
  |     +-- collect_auth.c      Auth/login logs (both platforms)
  |     +-- collect_applog.c    Application logs (both platforms)
  |     +-- collect_netlog.c    Firewall logs (both platforms)
  |     +-- collect_filemon.c   File audit logs (both platforms)
  |
  +-- archive_linux.c / archive_win32.c   Archive creation
  +-- hash.c                               SHA-256 integrity
  +-- platform_linux.c / platform_win32.c  OS abstraction
  +-- util.c                               Logging, memory, strings
```

Each collector implements three functions: `init`, `run`, and `cleanup`. Collectors are registered at startup and enabled/disabled based on CLI flags. Platform-specific code is isolated in separate `.c` files compiled conditionally.

---

## License

Internal tool. All rights reserved.
