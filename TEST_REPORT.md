# log_extract — Cross-Platform Test Report

Date: 2026-06-17
Scope: verify fixes for issues #1, #2, #3, #4, #7, #8 and confirm a runnable, working
solution on **Windows** and **Linux** (target environment unknown), with every function
exercised where the platform permits real execution.

## Build matrix — all CLEAN (`-Wall -Wextra -pedantic -std=c99`, zero warnings)

| Toolchain | Target | Result | Artifact |
|-----------|--------|--------|----------|
| Apple clang 12 (native) | macOS arm64 | ✅ clean | `dist/log_extract-macos-arm64` |
| gcc 12 (Debian, Docker) | Linux x86-64 *(via gcc:13 image)* | ✅ clean | `dist/log_extract-linux-x86_64` |
| gcc (Debian, Docker) | Linux arm64 | ✅ clean | `dist/log_extract-linux-arm64` |
| x86_64-w64-mingw32-gcc | Windows x86-64 (PE32+) | ✅ clean | `dist/log_extract.exe` |

> Note: real Linux gcc surfaced a `-Wformat-truncation` warning in `manifest.c:149` that
> Apple clang did **not** emit. Fixed (POSIX `walk_dir` now skips+warns on path truncation,
> matching the Windows branch). This is the value of testing on the actual target toolchain.

Checksums: `dist/SHA256SUMS`.

## Linux — full runtime testing (Docker, real execution)

Tested with synthetic `/var/log` fixtures (known timestamps in mixed formats) and a `utmpx`
generator for binary wtmp/btmp, on a **non-UTC host (`TZ=Europe/Budapest`, UTC+2)**.

| Area | Result |
|------|--------|
| `--version`, `--help`, `--dry-run` | ✅ |
| Full `-a` collect (system/auth/app/network/filemon) | ✅ all collectors OK, archive + sidecar produced |
| Per-collector `-S/-A/-P/-N/-F` | ✅ correct files + counts |
| wtmp/btmp binary parse (`ut_user`, types, time) | ✅ human-readable output correct |
| `--grep` keyword filter | ✅ |
| `--user` (text grep + `ut_user` match) | ✅ |
| auditd file-event filtering (filemon) | ✅ |
| `--from` / `--to` time window | ✅ (see timezone investigation) |
| `--app-path` (custom file + dir) | ✅ |
| `--no-archive`, `--no-hash` | ✅ (no sidecar when `--no-hash`) |
| **Manifest #3**: `manifest.json` fields + `hashes.txt` | ✅ `sha256sum -c hashes.txt` → ALL OK |
| Archive `.sha256` sidecar | ✅ verifies |
| **Severity #4**: warning on raw text logs | ✅ "could not be applied … no `<PRI>`" |
| **Time #2**: unparseable-timestamp warning (line kept) | ✅ "unparseable timestamp; kept" |
| **journald #7**: detection via `/var/log/journal` + journalctl | ✅ (logic verified; no journal in container) |
| **Disk guard #8**: warn-only below 200 MB | ✅ (statvfs path) |

### Timezone investigation (adversarial-review CRITICAL — RESOLVED, was a false positive)

The automated review claimed mixed local/UTC reference frames would silently drop evidence.
**Disproven empirically.** On a UTC+2 host with `--from "2026-06-15 13:00:00"` (= 11:00Z),
across lines written as `…Z`, `…+02:00`, zone-less ISO-8601, and legacy `Mon DD`:

- Survivors were exactly the four lines at/after 13:00 local; the three earlier lines were
  excluded — correct.
- Adding `--to "2026-06-15 13:45:00"` correctly narrowed to the single in-window line.

`time_t` is an absolute instant; `mktime` (local→absolute) and `gmtime` (absolute→UTC) are
used consistently, so comparisons are apples-to-apples. No fix required; the review finding
was an arithmetic misread.

## Windows — compile-verified + test harness (cannot be runtime-tested off-Windows)

The Windows collectors query the live **Windows Event Log via the `Evt*` API** (Security /
Firewall channels). This cannot be validated on Linux/macOS — and **not under wine either**,
which does not implement `wevtapi`. So Windows verification here is:

- ✅ **Clean MinGW compile** of all Windows paths (auth/filemon/network/system, manifest,
  disk guard) → `dist/log_extract.exe`.
- ✅ **Static review** (handles closed on every event + result handle, `EvtRender`
  buffer-resize loop, UTF-8 conversion, EventID/XPath selection) vs. the working
  `collect_eventlog.c`. Hardened: explicit null-termination on all `_snwprintf` /
  `MultiByteToWideChar` buffers (#4); pfirewall text log now warns that `--from/--to`
  can't be applied to it (#3).
- ⏳ **Runtime verification on the engagement host**: run `test/windows_test.ps1` in an
  **elevated** PowerShell. It exercises every flag/collector/filter, parses `manifest.json`,
  recomputes every `hashes.txt` entry with `Get-FileHash`, and verifies the archive sidecar.
  See `test/README_WINDOWS_TEST.md`.

Implemented Windows collectors:
- auth → Security EventIDs 4624/4625/4634/4647/4648 → `auth/security_auth.xml`
- filemon → 4663/4656/4660/4670 → `filemon/security_fileaudit.xml`
- network → `pfirewall.log` + `Microsoft-Windows-…/Firewall` channel → `network/firewall_events.xml`
- system → System/Application/Security channels (with `--to` bound now applied)

## Known limitations (documented, not bugs)

- **`--user` on text logs is substring grep** (e.g. `root` matches `chroot`). wtmp/btmp/auditd
  use precise field/UID matching. Documented in README.
- **Severity filter** only applies to `<PRI>`/journald (Linux) and Windows event `Level`; raw
  text logs pass through with a warning (never silently dropped).
- **pfirewall.log (Windows)** is collected in full; the `--from/--to` window is not applied to
  that text source (warned). The Firewall event channel does apply the window.
- Legacy yearless syslog timestamps are assumed current-year + host-local (inherent to the
  format; ISO-8601 lines are unaffected).

## Artifacts

```
dist/
  log_extract.exe              Windows x86-64 (PE32+)
  log_extract-linux-x86_64     Linux x86-64 (ELF)
  log_extract-linux-arm64      Linux arm64 (ELF)
  log_extract-macos-arm64      macOS arm64 (Mach-O)
  SHA256SUMS
test/
  windows_test.ps1             elevated-PowerShell test harness for the engagement host
  README_WINDOWS_TEST.md
```
