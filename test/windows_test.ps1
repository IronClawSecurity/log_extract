<#
.SYNOPSIS
    Self-contained test harness for log_extract.exe (forensic log collector) on Windows.

.DESCRIPTION
    Exercises the CLI surface, the collector outputs, the filter flags, and the
    integrity artifacts (manifest.json / hashes.txt / archive .sha256 sidecar)
    of log_extract.exe.

    ============================ RUN ELEVATED ============================
    This script MUST be run from an ELEVATED PowerShell session (Run as
    Administrator). The Windows Security Event Log channels that several
    collectors read require administrative rights:

      * auth    (-A) reads Security EventIDs 4624 / 4625 / 4634 / 4647 / 4648
      * filemon (-F) reads Security EventIDs 4663 / 4656 / 4660 / 4670

    Additional host configuration affects whether these collectors return any
    DATA (as opposed to running cleanly with an empty result):

      * filemon (-F): "Audit Object Access" / file-access (SACL) auditing must
        be enabled via the local/Group audit policy AND a SACL must exist on the
        watched objects, or the Security channel will simply contain no 466x
        events. An empty result is NOT a test failure.
      * network (-N): Windows Firewall logging must be enabled for
        pfirewall.log to exist, and the
        "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"
        event channel must be enabled for firewall_events.xml to contain events.
        Either/both being empty is NOT a test failure.

    The harness treats an empty channel, a graceful SKIP, or an access-denied
    partial as ACCEPTABLE. Only a crash, a hang, or a missing-output-artifact
    where one was promised is a FAIL.
    ======================================================================

.PARAMETER ExePath
    Path to log_extract.exe. Default: .\log_extract.exe

.PARAMETER OutRoot
    Temp output root the harness collects into. Default: $env:TEMP\le_test

.NOTES
    PowerShell 5.1+ compatible. No external modules. No network access.
    Exit code = number of FAILED checks (0 = all passed).
#>

[CmdletBinding()]
param(
    [string]$ExePath  = ".\log_extract.exe",
    [string]$OutRoot  = (Join-Path $env:TEMP "le_test")
)

# Be strict but do not let a single failing check abort the whole run; each
# check is wrapped in try/catch by Run-Check.
$ErrorActionPreference = "Continue"

# ---------------------------------------------------------------------------
# Result tracking + Run-Check helper
# ---------------------------------------------------------------------------
$script:Results = New-Object System.Collections.ArrayList

function Add-Result {
    param(
        [string]$Name,
        [string]$Status,   # PASS | FAIL | SKIP
        [string]$Message
    )
    [void]$script:Results.Add([pscustomobject]@{
        Check   = $Name
        Status  = $Status
        Message = $Message
    })
    $color = switch ($Status) {
        "PASS" { "Green" }
        "FAIL" { "Red" }
        "SKIP" { "Yellow" }
        default { "Gray" }
    }
    Write-Host ("  [{0}] {1}" -f $Status, $Name) -ForegroundColor $color
    if ($Message) { Write-Host ("        {0}" -f $Message) -ForegroundColor DarkGray }
}

# Run-Check runs a scriptblock that must return $true (PASS), $false (FAIL),
# or the string "SKIP". Any thrown exception is captured as a FAIL (a crash in
# a check must never abort the whole harness). The scriptblock may set
# $script:LastMsg to attach detail to the result.
function Run-Check {
    param(
        [string]$Name,
        [scriptblock]$Body
    )
    $script:LastMsg = ""
    try {
        $r = & $Body
        if ($r -is [string] -and $r -eq "SKIP") {
            Add-Result -Name $Name -Status "SKIP" -Message $script:LastMsg
        }
        elseif ($r) {
            Add-Result -Name $Name -Status "PASS" -Message $script:LastMsg
        }
        else {
            Add-Result -Name $Name -Status "FAIL" -Message $script:LastMsg
        }
    }
    catch {
        Add-Result -Name $Name -Status "FAIL" -Message ("exception: " + $_.Exception.Message)
    }
}

# ---------------------------------------------------------------------------
# Exec helper: run the exe with a timeout so a hang is a FAIL, not a stuck run.
# Returns a PSCustomObject { ExitCode; StdOut; StdErr; TimedOut }.
# ---------------------------------------------------------------------------
function Invoke-Exe {
    param(
        [string[]]$Arguments,
        [int]$TimeoutSec = 180
    )
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName               = $script:ExeFull
    $psi.Arguments              = ($Arguments | ForEach-Object {
                                      if ($_ -match '\s') { '"' + $_ + '"' } else { $_ }
                                  }) -join ' '
    $psi.UseShellExecute        = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.CreateNoWindow         = $true

    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $psi

    # Async read avoids deadlock when a pipe buffer fills.
    $sbOut = New-Object System.Text.StringBuilder
    $sbErr = New-Object System.Text.StringBuilder
    $outEvt = Register-ObjectEvent -InputObject $p -EventName OutputDataReceived -Action {
        if ($EventArgs.Data) { [void]$Event.MessageData.AppendLine($EventArgs.Data) }
    } -MessageData $sbOut
    $errEvt = Register-ObjectEvent -InputObject $p -EventName ErrorDataReceived -Action {
        if ($EventArgs.Data) { [void]$Event.MessageData.AppendLine($EventArgs.Data) }
    } -MessageData $sbErr

    [void]$p.Start()
    $p.BeginOutputReadLine()
    $p.BeginErrorReadLine()

    $timedOut = $false
    if (-not $p.WaitForExit($TimeoutSec * 1000)) {
        $timedOut = $true
        try { $p.Kill() } catch {}
        $p.WaitForExit()
    }
    # Give the async handlers a moment to flush.
    Start-Sleep -Milliseconds 100

    Unregister-Event -SourceIdentifier $outEvt.Name -ErrorAction SilentlyContinue
    Unregister-Event -SourceIdentifier $errEvt.Name -ErrorAction SilentlyContinue

    [pscustomobject]@{
        ExitCode = $(if ($timedOut) { -1 } else { $p.ExitCode })
        StdOut   = $sbOut.ToString()
        StdErr   = $sbErr.ToString()
        TimedOut = $timedOut
    }
}

# Find the single <hostname>_<timestamp> run directory created inside a base.
function Get-RunDir {
    param([string]$BaseDir)
    if (-not (Test-Path $BaseDir)) { return $null }
    Get-ChildItem -Path $BaseDir -Directory |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
}

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------
Write-Host "log_extract.exe Windows test harness" -ForegroundColor Cyan
Write-Host ("=" * 60)

$script:ExeFull = (Resolve-Path -Path $ExePath -ErrorAction SilentlyContinue)
if (-not $script:ExeFull) {
    Write-Host "FATAL: cannot find exe at '$ExePath'." -ForegroundColor Red
    Write-Host "Pass -ExePath <path-to-log_extract.exe>." -ForegroundColor Red
    exit 255
}
$script:ExeFull = $script:ExeFull.Path
Write-Host ("Exe:     {0}" -f $script:ExeFull)
Write-Host ("OutRoot: {0}" -f $OutRoot)

# Elevation check (informational — non-elevated checks still run).
$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($isAdmin) {
    Write-Host "Elevation: Administrator (Security/Firewall channels are reachable)" -ForegroundColor Green
} else {
    Write-Host "Elevation: NOT elevated — auth/filemon will likely report access-denied/partial." -ForegroundColor Yellow
    Write-Host "           Re-run from an elevated PowerShell for a full validation." -ForegroundColor Yellow
}

# Clean slate.
if (Test-Path $OutRoot) { Remove-Item -Path $OutRoot -Recurse -Force -ErrorAction SilentlyContinue }
New-Item -ItemType Directory -Path $OutRoot -Force | Out-Null

# ===========================================================================
# CHECK 1 — --version / --help (safe without elevation)
# ===========================================================================
Write-Host "`n[1] CLI: --version and --help" -ForegroundColor Cyan

Run-Check "1a --version prints a version" {
    $r = Invoke-Exe -Arguments @("--version") -TimeoutSec 30
    if ($r.TimedOut) { $script:LastMsg = "process hung"; return $false }
    # Expected: "log_extract version 0.1.0"
    $ok = ($r.ExitCode -eq 0) -and ($r.StdOut -match "version\s+\d+\.\d+")
    $script:LastMsg = ($r.StdOut.Trim())
    return $ok
}

Run-Check "1b --help prints usage" {
    $r = Invoke-Exe -Arguments @("--help") -TimeoutSec 30
    if ($r.TimedOut) { $script:LastMsg = "process hung"; return $false }
    $ok = ($r.ExitCode -eq 0) -and ($r.StdOut -match "Usage:") -and ($r.StdOut -match "--system")
    if (-not $ok) { $script:LastMsg = "usage text not as expected" }
    return $ok
}

# ===========================================================================
# CHECK 2 — --dry-run lists the 5 collectors
# ===========================================================================
Write-Host "`n[2] --dry-run lists collectors" -ForegroundColor Cyan

Run-Check "2 --dry-run names all 5 collectors" {
    $r = Invoke-Exe -Arguments @("-a", "--dry-run") -TimeoutSec 30
    if ($r.TimedOut) { $script:LastMsg = "process hung"; return $false }
    # main.c print_dry_run lists each collector name: system/auth/app/network/filemon
    $names = @("system", "auth", "app", "network", "filemon")
    $missing = $names | Where-Object { $r.StdOut -notmatch [regex]::Escape($_) }
    if ($missing) { $script:LastMsg = "missing from dry-run: $($missing -join ', ')"; return $false }
    $script:LastMsg = "all 5 collectors listed"
    return ($r.ExitCode -eq 0)
}

# ===========================================================================
# CHECK 3 — Full run: -a -o <out>  (exit 0 or 1 acceptable)
# ===========================================================================
Write-Host "`n[3] Full collection run (-a)" -ForegroundColor Cyan

$fullOut = Join-Path $OutRoot "full"
$script:FullRunDir = $null

Run-Check "3a full run completes (exit 0 or 1, no hang)" {
    $r = Invoke-Exe -Arguments @("-a", "-o", $fullOut) -TimeoutSec 300
    if ($r.TimedOut) { $script:LastMsg = "process hung past timeout"; return $false }
    # 0 = data collected; 1 = nothing collected (both are legitimate outcomes).
    $ok = ($r.ExitCode -eq 0 -or $r.ExitCode -eq 1)
    $script:LastMsg = "exit=$($r.ExitCode)"
    $script:FullRunDir = Get-RunDir -BaseDir $fullOut
    return $ok
}

Run-Check "3b run directory <hostname>_<timestamp> was created" {
    if (-not $script:FullRunDir) { $script:LastMsg = "no run dir under $fullOut"; return $false }
    # Sanity: directory name shape host_YYYYMMDD... — we only assert it exists
    # and contains a recognizable timestamp separator.
    $script:LastMsg = $script:FullRunDir.Name
    return ($script:FullRunDir.Name -match "_")
}

# The remaining check-3 artifacts only exist when SOME data was collected
# (main.c only writes manifest/archive when any_data). If the run dir is empty
# of collector data, treat artifact checks as SKIP, not FAIL.
$script:FullHasData = $false
if ($script:FullRunDir) {
    $manifestPath = Join-Path $script:FullRunDir.FullName "manifest.json"
    $script:FullHasData = Test-Path $manifestPath
}

Run-Check "3c manifest.json present (or SKIP if no data collected)" {
    if (-not $script:FullRunDir) { $script:LastMsg = "no run dir"; return $false }
    if (-not $script:FullHasData) {
        $script:LastMsg = "no manifest.json — collectors returned no data (acceptable on a quiet host)"
        return "SKIP"
    }
    return $true
}

Run-Check "3d hashes.txt present (when data collected)" {
    if (-not $script:FullHasData) { $script:LastMsg = "no data collected"; return "SKIP" }
    $p = Join-Path $script:FullRunDir.FullName "hashes.txt"
    $script:LastMsg = $p
    return (Test-Path $p)
}

Run-Check "3e archive (.zip or .tar.gz fallback) present (when data collected)" {
    if (-not $script:FullHasData) { $script:LastMsg = "no data collected"; return "SKIP" }
    # archive_create() names it <run_dir>.zip, or <run_dir>.tar.gz on the tar fallback.
    $zip   = $script:FullRunDir.FullName + ".zip"
    $targz = $script:FullRunDir.FullName + ".tar.gz"
    $script:FullArchive = $null
    if (Test-Path $zip)        { $script:FullArchive = $zip }
    elseif (Test-Path $targz)  { $script:FullArchive = $targz }
    $script:LastMsg = $(if ($script:FullArchive) { $script:FullArchive } else { "no .zip / .tar.gz next to run dir" })
    return ($null -ne $script:FullArchive)
}

Run-Check "3f archive .sha256 sidecar present (when archive built)" {
    if (-not $script:FullHasData)  { $script:LastMsg = "no data collected"; return "SKIP" }
    if (-not $script:FullArchive)  { $script:LastMsg = "no archive"; return "SKIP" }
    $p = $script:FullArchive + ".sha256"
    $script:LastMsg = $p
    return (Test-Path $p)
}

# ===========================================================================
# CHECK 4 — Per-collector runs
# Each: assert expected file appears OR a graceful SKIP/partial status.
# A crash/hang is the only hard FAIL.
# ===========================================================================
Write-Host "`n[4] Per-collector runs" -ForegroundColor Cyan

# Generic per-collector runner. $ExpectFiles are paths relative to <subdir>;
# PASS if the run did not crash/hang AND (at least one expected file exists OR
# we accept an empty/partial collection — empty channels are not failures).
function Test-Collector {
    param(
        [string]$Flag,
        [string]$SubDir,
        [string[]]$ExpectFiles,
        [string[]]$ExtraArgs = @()
    )
    $base = Join-Path $OutRoot ("coll_" + $SubDir)
    $exeArgs = @($Flag, "-o", $base) + $ExtraArgs
    $r = Invoke-Exe -Arguments $exeArgs -TimeoutSec 240
    if ($r.TimedOut) { $script:LastMsg = "process hung"; return $false }
    if ($r.ExitCode -ne 0 -and $r.ExitCode -ne 1) {
        $script:LastMsg = "unexpected exit=$($r.ExitCode) (crash?)"
        return $false
    }

    $runDir = Get-RunDir -BaseDir $base
    if (-not $runDir) {
        # No run dir at all is only acceptable for a clean dry-run; here it means
        # mkdir failed. That is a FAIL.
        $script:LastMsg = "no run directory created"
        return $false
    }

    $subPath = Join-Path $runDir.FullName $SubDir
    $found = @()
    foreach ($f in $ExpectFiles) {
        $candidate = Join-Path $subPath $f
        if (Test-Path $candidate) { $found += $f }
    }

    if ($found.Count -gt 0) {
        $script:LastMsg = ("exit=$($r.ExitCode); produced: " + ($found -join ", "))
        return $true
    }

    # No expected file present. The collector may have legitimately SKIPped
    # (channel not found, access denied, no data). The summary text reflects
    # this. Accept it as a graceful SKIP rather than a failure.
    $script:LastMsg = ("exit=$($r.ExitCode); no expected file in $SubDir/ — " +
                       "treated as graceful skip/empty (acceptable)")
    return "SKIP"
}

Run-Check "4a -S system (System/Application/Security .xml)" {
    Test-Collector -Flag "-S" -SubDir "system" `
        -ExpectFiles @("System.xml", "Application.xml", "Security.xml")
}

Run-Check "4b -A auth (security_auth.xml; needs Admin for data)" {
    Test-Collector -Flag "-A" -SubDir "auth" -ExpectFiles @("security_auth.xml")
}

Run-Check "4c -F filemon (security_fileaudit.xml; needs Admin + audit policy)" {
    Test-Collector -Flag "-F" -SubDir "filemon" -ExpectFiles @("security_fileaudit.xml")
}

Run-Check "4d -N network (pfirewall.log and/or firewall_events.xml)" {
    Test-Collector -Flag "-N" -SubDir "network" `
        -ExpectFiles @("pfirewall.log", "firewall_events.xml")
}

# -P app: feed a temp directory containing a sample .log via --app-path.
# applog copies <dir-basename>/<file> under the app/ subdir. We assert the
# sample line round-trips into the output.
$script:AppSrcDir = Join-Path $OutRoot "appsrc"
New-Item -ItemType Directory -Path $script:AppSrcDir -Force | Out-Null
$script:AppSampleLine = "2026-06-15 12:00:00 TEST-APP sample log line for harness"
Set-Content -Path (Join-Path $script:AppSrcDir "sample.log") `
    -Value $script:AppSampleLine -Encoding ascii

Run-Check "4e -P app with --app-path (sample .log round-trips)" {
    $base = Join-Path $OutRoot "coll_app"
    $r = Invoke-Exe -Arguments @("-P", "--app-path", $script:AppSrcDir, "-o", $base) -TimeoutSec 120
    if ($r.TimedOut) { $script:LastMsg = "process hung"; return $false }
    if ($r.ExitCode -ne 0 -and $r.ExitCode -ne 1) {
        $script:LastMsg = "unexpected exit=$($r.ExitCode)"; return $false
    }
    $runDir = Get-RunDir -BaseDir $base
    if (-not $runDir) { $script:LastMsg = "no run dir"; return $false }

    # applog writes: <run>/app/<src-dir-basename>/sample.log
    $srcBase = Split-Path -Leaf $script:AppSrcDir
    $copied  = Join-Path (Join-Path (Join-Path $runDir.FullName "app") $srcBase) "sample.log"
    if (-not (Test-Path $copied)) {
        $script:LastMsg = "expected copy not found at $copied"
        return $false
    }
    $content = Get-Content -Path $copied -Raw
    $ok = $content -match [regex]::Escape("sample log line for harness")
    $script:LastMsg = $(if ($ok) { "sample.log collected and content matched" } else { "content mismatch" })
    return $ok
}

# ===========================================================================
# CHECK 5 — Filters run cleanly and produce output without error
# ===========================================================================
Write-Host "`n[5] Filter flags run cleanly" -ForegroundColor Cyan

# Recent window: last 7 days .. now, in the tool's expected format.
$fromStr = (Get-Date).AddDays(-7).ToString("yyyy-MM-dd HH:mm:ss")
$toStr   = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")

function Test-FilterRun {
    param([string]$Label, [string[]]$FilterArgs)
    $base = Join-Path $OutRoot ("filt_" + ($Label -replace '\W', '_'))
    $r = Invoke-Exe -Arguments (@("-a", "-o", $base) + $FilterArgs) -TimeoutSec 300
    if ($r.TimedOut) { $script:LastMsg = "process hung"; return $false }
    if ($r.ExitCode -ne 0 -and $r.ExitCode -ne 1) {
        $script:LastMsg = "unexpected exit=$($r.ExitCode); stderr: $($r.StdErr.Trim())"
        return $false
    }
    # "Unknown option" / "requires a value" would mean a parse error (exit 2).
    if ($r.StdErr -match "Unknown option" -or $r.StdErr -match "requires a value") {
        $script:LastMsg = "argument parse error: $($r.StdErr.Trim())"
        return $false
    }
    $runDir = Get-RunDir -BaseDir $base
    if (-not $runDir) { $script:LastMsg = "no run dir created"; return $false }
    $script:LastMsg = "exit=$($r.ExitCode); ran cleanly"
    return $true
}

Run-Check "5a --from / --to (recent 7-day window)" {
    Test-FilterRun -Label "fromto" -FilterArgs @("--from", $fromStr, "--to", $toStr)
}
Run-Check "5b --grep PATTERN" {
    Test-FilterRun -Label "grep" -FilterArgs @("--grep", "the")
}
Run-Check "5c --user (current user)" {
    Test-FilterRun -Label "user" -FilterArgs @("--user", $env:USERNAME)
}
Run-Check "5d --level-min / --level-max" {
    Test-FilterRun -Label "level" -FilterArgs @("--level-min", "1", "--level-max", "4")
}

# ===========================================================================
# CHECK 6 — Integrity verification (manifest.json + hashes.txt + sidecar)
# Reuses the full-run output from CHECK 3 when it produced data.
# ===========================================================================
Write-Host "`n[6] Integrity verification" -ForegroundColor Cyan

if (-not $script:FullHasData) {
    Run-Check "6 integrity (no data collected to verify)" {
        $script:LastMsg = "full run produced no manifest — cannot verify integrity on this host"
        return "SKIP"
    }
} else {
    $runDir       = $script:FullRunDir.FullName
    $manifestPath = Join-Path $runDir "manifest.json"
    $hashesPath   = Join-Path $runDir "hashes.txt"

    Run-Check "6a manifest.json parses and has required top-level fields" {
        $json = Get-Content -Path $manifestPath -Raw | ConvertFrom-Json
        $required = @("tool", "version", "hostname", "collected_start_utc",
                      "collected_end_utc", "timezone_offset_seconds",
                      "privilege", "files")
        $missing = @()
        foreach ($field in $required) {
            if (-not ($json.PSObject.Properties.Name -contains $field)) { $missing += $field }
        }
        if ($missing.Count -gt 0) {
            $script:LastMsg = "missing fields: $($missing -join ', ')"
            return $false
        }
        if ($json.tool -ne "log_extract") {
            $script:LastMsg = "tool field = '$($json.tool)' (expected log_extract)"
            return $false
        }
        if (-not ($json.files -is [array]) -and $null -eq $json.files) {
            $script:LastMsg = "files[] not present"
            return $false
        }
        $script:LastMsg = ("tool=$($json.tool) version=$($json.version) " +
                           "host=$($json.hostname) files=$($json.files.Count)")
        return $true
    }

    Run-Check "6b every hashes.txt entry recomputes correctly (SHA-256)" {
        if (-not (Test-Path $hashesPath)) { $script:LastMsg = "no hashes.txt"; return $false }
        $lines = Get-Content -Path $hashesPath | Where-Object { $_.Trim() -ne "" }
        if ($lines.Count -eq 0) { $script:LastMsg = "hashes.txt is empty"; return "SKIP" }

        $bad      = @()
        $missing  = @()
        $checked  = 0
        foreach ($line in $lines) {
            # Format: "<64-hex><two spaces><forward-slash relpath>"
            if ($line -notmatch '^([0-9a-fA-F]{64})\s\s(.+)$') {
                $bad += "malformed line: $line"
                continue
            }
            $expected = $Matches[1].ToLower()
            $rel      = $Matches[2]
            # Forward-slash relpath -> Windows path under the run dir.
            $winRel   = $rel -replace '/', '\'
            $full     = Join-Path $runDir $winRel
            if (-not (Test-Path $full)) { $missing += $rel; continue }
            $actual = (Get-FileHash -Path $full -Algorithm SHA256).Hash.ToLower()
            if ($actual -ne $expected) { $bad += $rel }
            $checked++
        }
        if ($missing.Count -gt 0) { $script:LastMsg = "files in hashes.txt not on disk: $($missing -join ', ')"; return $false }
        if ($bad.Count -gt 0)     { $script:LastMsg = "hash mismatch / malformed: $($bad -join ', ')"; return $false }
        $script:LastMsg = "$checked file(s) verified against hashes.txt"
        return $true
    }

    Run-Check "6c archive .sha256 sidecar matches Get-FileHash of the archive" {
        if (-not $script:FullArchive)             { $script:LastMsg = "no archive built"; return "SKIP" }
        $sidecar = $script:FullArchive + ".sha256"
        if (-not (Test-Path $sidecar))            { $script:LastMsg = "no sidecar (was --no-hash used?)"; return "SKIP" }
        # Sidecar format: "<hex>  <archive-basename>"
        $line = (Get-Content -Path $sidecar | Where-Object { $_.Trim() -ne "" } | Select-Object -First 1)
        if ($line -notmatch '^([0-9a-fA-F]{64})\s') {
            $script:LastMsg = "sidecar not in '<hex>  <name>' form: $line"
            return $false
        }
        $expected = $Matches[1].ToLower()
        $actual   = (Get-FileHash -Path $script:FullArchive -Algorithm SHA256).Hash.ToLower()
        $script:LastMsg = $(if ($actual -eq $expected) { "sidecar matches archive" } else { "MISMATCH expected=$expected actual=$actual" })
        return ($actual -eq $expected)
    }
}

# ===========================================================================
# CHECK 7 — --no-hash and --no-archive flag behavior
# ===========================================================================
Write-Host "`n[7] --no-hash / --no-archive" -ForegroundColor Cyan

Run-Check "7a --no-hash: archive built but NO .sha256 sidecar" {
    $base = Join-Path $OutRoot "nohash"
    $r = Invoke-Exe -Arguments @("-a", "--no-hash", "-o", $base) -TimeoutSec 300
    if ($r.TimedOut) { $script:LastMsg = "process hung"; return $false }
    $runDir = Get-RunDir -BaseDir $base
    if (-not $runDir) { $script:LastMsg = "no run dir"; return $false }
    # If no data was collected, no archive is built at all -> sidecar absence is trivially true.
    $zip   = $runDir.FullName + ".zip"
    $targz = $runDir.FullName + ".tar.gz"
    $arc   = $null
    if (Test-Path $zip) { $arc = $zip } elseif (Test-Path $targz) { $arc = $targz }
    if (-not $arc) {
        $script:LastMsg = "no archive (no data collected) — sidecar trivially absent"
        return "SKIP"
    }
    $sidecar = $arc + ".sha256"
    $absent = -not (Test-Path $sidecar)
    $script:LastMsg = $(if ($absent) { "archive present, sidecar correctly absent" } else { "ERROR: sidecar exists despite --no-hash" })
    return $absent
}

Run-Check "7b --no-archive: run directory kept, NO archive created" {
    $base = Join-Path $OutRoot "noarchive"
    $r = Invoke-Exe -Arguments @("-a", "--no-archive", "-o", $base) -TimeoutSec 300
    if ($r.TimedOut) { $script:LastMsg = "process hung"; return $false }
    $runDir = Get-RunDir -BaseDir $base
    if (-not $runDir) { $script:LastMsg = "no run dir kept"; return $false }
    $zip   = $runDir.FullName + ".zip"
    $targz = $runDir.FullName + ".tar.gz"
    $noArchive = (-not (Test-Path $zip)) -and (-not (Test-Path $targz))
    $script:LastMsg = $(if ($noArchive) { "directory kept, no archive (correct)" } else { "ERROR: archive created despite --no-archive" })
    return ($noArchive -and (Test-Path $runDir.FullName))
}

# ===========================================================================
# Summary
# ===========================================================================
Write-Host "`n$('=' * 60)"
Write-Host "SUMMARY" -ForegroundColor Cyan
$script:Results | Format-Table -AutoSize Check, Status, Message | Out-String | Write-Host

$pass = ($script:Results | Where-Object { $_.Status -eq "PASS" }).Count
$fail = ($script:Results | Where-Object { $_.Status -eq "FAIL" }).Count
$skip = ($script:Results | Where-Object { $_.Status -eq "SKIP" }).Count

Write-Host ("PASS: {0}   FAIL: {1}   SKIP: {2}" -f $pass, $fail, $skip) `
    -ForegroundColor $(if ($fail -eq 0) { "Green" } else { "Red" })
Write-Host ("Output kept under: {0}" -f $OutRoot) -ForegroundColor DarkGray

# Exit code = number of failures (0 = clean).
$global:LASTEXITCODE = $fail
exit $fail
