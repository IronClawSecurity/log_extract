# log_extract.exe — Windows Test Harness

`windows_test.ps1` is a self-contained PowerShell harness that validates the
Windows build of `log_extract.exe` (the forensic log collector). It exercises
the CLI, the five collectors, the filter flags, and the integrity artifacts
(`manifest.json`, `hashes.txt`, and the archive `.sha256` sidecar).

## 1. Build the exe

The harness does not build the tool — build it first, on Windows.

### MinGW (produces `log_extract.exe`)

```
mingw32-make
```

### MSVC (single `cl` invocation, from a Developer Command Prompt)

```
cl /Iinclude /Fe:log_extract.exe src\main.c src\cli.c src\filter.c src\collector.c src\collect_auth.c src\collect_applog.c src\collect_netlog.c src\collect_filemon.c src\hash.c src\manifest.c src\util.c src\platform_win32.c src\collect_eventlog.c src\archive_win32.c /link wevtapi.lib advapi32.lib shlwapi.lib
```

Both produce `log_extract.exe` in the repo root.

## 2. Run the harness (ELEVATED)

Open **PowerShell as Administrator**, then:

```powershell
# From the directory containing log_extract.exe and this test folder:
powershell -ExecutionPolicy Bypass -File .\test\windows_test.ps1

# Or point it at a specific exe / output location:
powershell -ExecutionPolicy Bypass -File .\test\windows_test.ps1 `
    -ExePath C:\tools\log_extract.exe -OutRoot C:\temp\le_test
```

Parameters:

| Param      | Default              | Meaning                                   |
|------------|----------------------|-------------------------------------------|
| `-ExePath` | `.\log_extract.exe`  | Path to the binary under test             |
| `-OutRoot` | `$env:TEMP\le_test`  | Scratch output root (wiped at start)       |

PowerShell 5.1+ is required. No modules and no internet access are needed.

## 3. Why Administrator + audit policy matter

Several collectors read the Windows **Security** event channel, which is
inaccessible to a standard user:

- **`-A` auth** reads Security EventIDs **4624 / 4625 / 4634 / 4647 / 4648**
  (logon / logoff / failed logon).
- **`-F` filemon** reads Security EventIDs **4663 / 4656 / 4660 / 4670**
  (object access / handle / delete / permission change).

For these to return *data* (not merely run cleanly):

- **filemon** also requires **file-access (object-access) auditing** to be
  enabled in audit policy *and* a SACL on the watched objects. Without it the
  Security channel simply has no 466x events — an **empty result, not a failure**.
- **`-N` network** needs **Windows Firewall logging** enabled for
  `pfirewall.log` to exist, and the
  `Microsoft-Windows-Windows Firewall With Advanced Security/Firewall`
  channel enabled for `firewall_events.xml` to contain events. Either may be
  empty without it being a failure.

The harness deliberately treats an **empty channel, a graceful SKIP, or an
access-denied partial** as acceptable. The only hard failures are a **crash**,
a **hang** (each exe invocation is run under a timeout), or a **missing output
artifact that the tool promised to produce**.

## 4. Reading the results

Each check prints `[PASS]`, `[FAIL]`, or `[SKIP]` as it runs, with a short
detail line. A summary table is printed at the end:

```
PASS: 18   FAIL: 0   SKIP: 4
```

- **PASS** — behaved as expected.
- **SKIP** — not applicable on this host (e.g. no Security data to verify, no
  archive because nothing was collected). Not a defect.
- **FAIL** — a crash, hang, parse error, missing artifact, or hash mismatch.

The process **exit code equals the number of FAILs** (`$LASTEXITCODE`), so the
harness drops cleanly into CI or a `cmd /c` check: `0` means all green.

Collected output is left under `-OutRoot` for manual inspection.

### What each group checks

1. **CLI** — `--version` prints a version; `--help` prints usage. (Safe without elevation.)
2. **`--dry-run`** — lists all five collectors (system, auth, app, network, filemon).
3. **Full run (`-a`)** — exit `0` or `1` accepted; asserts the
   `<hostname>_<timestamp>` run dir, `manifest.json`, `hashes.txt`, an archive
   (`.zip`, or `.tar.gz` fallback), and the archive `.sha256` sidecar appear
   (artifact checks SKIP if no data was collected).
4. **Per-collector** — `-S` (System/Application/Security `.xml`),
   `-A` (`security_auth.xml`), `-F` (`security_fileaudit.xml`),
   `-N` (`pfirewall.log` and/or `firewall_events.xml`), `-P` with `--app-path`
   pointing at a temp folder containing a sample `.log` (asserts the sample
   round-trips into `app\<dir>\sample.log`).
5. **Filters** — `--from`/`--to` (recent window), `--grep`, `--user`
   (`$env:USERNAME`), `--level-min`/`--level-max` all run cleanly and produce a
   run directory without a parse error.
6. **Integrity** — parses `manifest.json` (asserts `tool`, `version`,
   `hostname`, `collected_start_utc`, `collected_end_utc`,
   `timezone_offset_seconds`, `privilege`, `files[]`); recomputes
   `Get-FileHash -Algorithm SHA256` for every `hashes.txt` entry (translating
   the forward-slash relpath to a Windows path) and asserts a match; verifies
   the archive `.sha256` sidecar matches the archive's hash.
7. **Flag behavior** — `--no-hash` (archive built but no `.sha256` sidecar),
   `--no-archive` (run directory kept, no archive).

## 5. Platform note (important)

The Windows Event Log collectors (`-S`, `-A`, `-F`, and the firewall channel in
`-N`) query the live `Evt*` (Windows Event Log) API on a real Windows host. They
**cannot be meaningfully validated on Linux, macOS, or under Wine** — those
platforms have no Security/Firewall event channels and the Windows code paths
are compiled out entirely. A genuine validation requires:

- a **real Windows host** (Server 2008 R2 / Windows 7 or newer),
- an **elevated (Administrator)** session, and
- the **appropriate audit policy** enabled for filemon/firewall to surface data.
