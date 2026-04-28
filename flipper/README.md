# Flipper Zero deployment

This directory contains the Flipper-side assets for running `log_extract` on
a target machine over USB and pulling the resulting archive back onto the
Flipper's SD card. **No changes are made to `log_extract` itself** — local
invocation (`./log_extract -a -o /tmp/test`) works exactly as before. The
Flipper integration is purely additive: pre-built binaries plus two
launchers plus three BadUSB payloads.

## How it works

The Flipper enumerates as **two USB devices at once**: a HID keyboard
(BadUSB) and a Mass Storage device backed by the Flipper's SD card. The
BadUSB payload types a single command into the target that locates the
mounted SD volume by label and invokes the launcher script that lives on
it. The launcher runs the appropriate pre-built `log_extract` binary with
`-o <flipper-drive>/output`, so the archive (`*.tar.gz` / `*.zip` plus
`.sha256` sidecar) lands directly back on the Flipper SD card. Unplug the
Flipper and the logs come with it.

## Requirements

- A Flipper Zero running firmware with **both** BadUSB and USB Mass Storage
  apps. Stock OFW does not ship Mass Storage; use Momentum, Unleashed, or
  RogueMaster.
- The Flipper's SD card volume label must be set to **`LOGXTRACT`**. The
  BadUSB payloads locate the drive by label so they don't have to guess at
  drive letters / mountpoints.
- Pre-built `log_extract` binaries for whichever target OS you might
  encounter (see *SD card layout* below).
- Administrator (Windows) / root (Linux / macOS) on the target. Several
  log sources are privileged — Windows Event Log, journald system scope,
  `/var/log/auth.log`, auditd, `log show --predicate` on macOS, etc.

## Building the binaries

Build once per target architecture from the project root:

```bash
# Linux x86_64
make
mv log_extract /path/to/flipper-sd/log_extract_linux

# macOS (run on a Mac)
make
mv log_extract /path/to/flipper-sd/log_extract_macos

# Windows (MinGW cross-compile or native)
mingw32-make
mv log_extract.exe /path/to/flipper-sd/log_extract.exe
```

You only need binaries for the OS families you intend to collect from.

## SD card layout

Place the following at the **root** of the Flipper SD card (i.e. the path
that appears as the drive root when Mass Storage is active):

```
/log_extract.exe          <- Windows binary
/log_extract_linux        <- Linux binary  (chmod +x)
/log_extract_macos        <- macOS binary  (chmod +x)
/run.bat                  <- copy from flipper/launcher/run.bat
/run.sh                   <- copy from flipper/launcher/run.sh  (chmod +x)
```

Copy the BadUSB payloads (`flipper/badusb/windows.txt`, `linux.txt`,
`macos.txt`) into the Flipper's BadUSB app directory, typically
`/badusb/` on the SD card.

## Operating procedure

1. On the Flipper, open the **USB Mass Storage** app and start it. This
   exposes the SD card so the target sees the binaries and launchers. Do
   **not** plug in yet.
2. Plug the Flipper into the target via USB. Wait for the OS to mount the
   `LOGXTRACT` volume.
3. On the Flipper, exit Mass Storage and open **BadUSB**. (Mass Storage
   stays mounted on the host — exiting the app on the Flipper just stops
   re-enumerating; on most firmwares the volume remains visible to the
   host until physical disconnect. If your firmware drops MSC on app exit,
   use a build that supports composite HID+MSC simultaneously, or enable
   the "keep MSC active" option if present.)
4. Select the payload matching the target OS (`windows.txt`, `linux.txt`,
   or `macos.txt`) and run it.
5. Approve the privilege prompt on the target:
   - **Windows**: a UAC dialog appears for `run.bat` — click *Yes*.
   - **Linux / macOS**: a terminal opens running `sudo sh run.sh` — type
     the sudo password.
6. Wait for the launcher to finish. The Windows console pauses 8 s on
   exit; the POSIX launcher pauses 5 s. The archive plus `.sha256` will
   be in `<LOGXTRACT>/output/<hostname>_<timestamp>/`.
7. Unplug the Flipper. The logs are on its SD card.

## Notes and limitations

- **The operator still needs physical access and a privilege prompt
  click.** This is an authorised IR / pentest collection workflow, not a
  bypass for endpoint protection.
- BadUSB payloads are **OS-specific** — the Flipper has no way to detect
  the target's OS, so pick the right script. Running `windows.txt`
  against a Linux box just types garbage into whatever has focus.
- The Linux payload assumes `Ctrl+Alt+T` opens a terminal (default on
  GNOME / Ubuntu / many DEs). If the target uses KDE without that
  binding, edit the payload to drive whatever terminal launcher is
  available.
- The macOS payload assumes Spotlight is bound to `Cmd+Space`. If the
  target rebound Spotlight, edit the payload accordingly.
- SD card free space must comfortably exceed the expected archive size.
  `log_extract -a` collects every enabled source — on a busy server this
  can be hundreds of MB.
- The launcher writes back to the same volume it ran from, so the SD
  card must be mounted read-write. Some host configurations mount
  unknown USB media read-only by policy; that will cause the archive
  step to fail.
- `log_extract` runs **locally** on the target — none of this changes
  that. The Flipper is just a delivery + exfil dongle.
