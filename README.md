# Mirror-port capture + TLS handshake analysis

Continuous packet capture off a SPAN/mirror port, rotating to a new file
every hour, plus automatic scanning of each hour's capture for TCP streams
where a TLS handshake started but never completed.

**These scripts are written for the Windows machine running Wireshark on
the mirror port** - they were built and syntax/logic-tested on a different
machine (no access to your capture box or its interface), then verified
against a real capture with both a successful and a deliberately broken
TLS handshake. Copy this folder to the capture machine and run from there.

## Files

- `capture.ps1` — the continuous capture loop. Runs `tshark` in ring-buffer
  mode (`-b duration:3600`), which handles the hourly file rotation
  internally; the outer loop just restarts tshark if it ever exits
  unexpectedly.
- `analyze-tls.ps1` — analyzes a single pcap, writes `<name>.tls-findings.csv`
  next to it. Can be run standalone against any pcap, not just ones
  produced by `capture.ps1`.
- `watch-and-analyze.ps1` — polls `C:\tracedump` for hourly files that have
  finished rotating (i.e. not the one currently being written), runs
  `analyze-tls.ps1` on any that don't have a report yet, maintains a daily
  aggregate report and a persistent error log, and prunes old files (with
  captures containing findings kept separately from clean ones - see
  below).

## Prerequisites

- Wireshark/tshark installed at `C:\Program Files\Wireshark\tshark.exe`
  (already confirmed present on your machine)
- **Run as Administrator.** Npcap (Wireshark's capture driver) requires
  elevated privileges for live capture by default - both `capture.ps1` and
  any Scheduled Task running it need to run elevated, or capture will fail
  immediately with a permissions error.
- Confirm your mirror port's interface number/name with `tshark -D` before
  running - `capture.ps1` currently has `$Interface = "1"` hardcoded to
  match the `tshark -D` output you shared (`Ethernet0 2`). If interface
  numbering ever shifts (e.g. after adding/removing an adapter), that
  number can point to the wrong NIC - check `tshark -D` again if capture
  ever looks like it's grabbing the wrong traffic.

## Quick test (foreground, before committing to a Scheduled Task)

```powershell
cd C:\path\to\tracedump-capture
.\capture.ps1
```

Let it run a few minutes, `Ctrl+C`, then check `C:\tracedump` for a `.pcap`
file. Run the analyzer against it manually:

```powershell
.\analyze-tls.ps1 -PcapPath "C:\tracedump\mirror.pcap"
```

## Running continuously (Scheduled Task)

Two independent tasks - capture and analysis are deliberately separate
processes, so a slow/hung analysis pass can never interrupt the live
capture. Run these yourself in an **elevated** PowerShell on the capture
machine (I can't reach that machine to run them for you):

```powershell
$capArgs = "-NoProfile -ExecutionPolicy Bypass -File `"C:\path\to\tracedump-capture\capture.ps1`""
schtasks /create /tn "Mirror Port Capture" /tr "powershell.exe $capArgs" /sc onstart /ru SYSTEM /rl HIGHEST /f

$watchArgs = "-NoProfile -ExecutionPolicy Bypass -File `"C:\path\to\tracedump-capture\watch-and-analyze.ps1`""
schtasks /create /tn "Mirror Port Analysis" /tr "powershell.exe $watchArgs" /sc onstart /ru SYSTEM /rl HIGHEST /f

# Start both now rather than waiting for next reboot:
schtasks /run /tn "Mirror Port Capture"
schtasks /run /tn "Mirror Port Analysis"
```

`/ru SYSTEM /rl HIGHEST` runs elevated without needing to store a user
password in the task. Adjust the path in `-File` to wherever you actually
put this folder.

## Configuration

Edit the `# ---- config ----` block near the top of each script:

| Script | Setting | Default | Meaning |
|---|---|---|---|
| `capture.ps1` | `$Interface` | `"1"` | tshark interface number from `tshark -D` |
| `capture.ps1` | `$OutDir` | `C:\tracedump` | where hourly pcaps land |
| `capture.ps1` | `$RotateSecs` | `3600` | seconds per file (1 hour) |
| `watch-and-analyze.ps1` | `$PollSeconds` | `300` | how often to check for finished files |
| `watch-and-analyze.ps1` | `$RetentionDays` | `7` | auto-delete **clean** (no findings) pcaps + reports older than this; `0` = keep forever |
| `watch-and-analyze.ps1` | `$ErrorRetentionDays` | `0` (forever) | auto-delete pcaps **with findings** older than this; separate from `$RetentionDays` so error captures can be kept longer (or forever) |

## Captures with findings, daily reports, and the persistent error log

Three things `watch-and-analyze.ps1` maintains beyond the per-hour reports:

- **Error-flagged pcaps are kept separately from clean ones.** Any hourly
  `.pcap` whose findings CSV has at least one flagged row is retained per
  `$ErrorRetentionDays` (default: forever) instead of `$RetentionDays`. A
  clean hour with no findings still gets pruned after 7 days as before -
  only hours with something worth keeping stick around longer, so disk
  usage doesn't grow forever just because *most* traffic is fine.
- **Daily report** — `C:\tracedump\daily-reports\YYYY-MM-DD.csv` (every
  flagged row for that calendar day, across all its hourly files) and
  `YYYY-MM-DD-summary.txt` (counts by status + top 10 affected SNIs).
  Today's report is regenerated from scratch on every poll cycle, so it's
  always current as the day progresses; once the day ends it simply stops
  changing (no separate "finalize" step needed).
- **Persistent error log** — `C:\tracedump\error-log.csv`. Every flagged
  finding, from every hour, ever, appended once (at analysis time) with a
  `SourceFile` column for traceability. This is deliberately independent
  of pcap retention: even after `$ErrorRetentionDays` eventually prunes an
  old error-flagged pcap, its findings remain in this log permanently. This
  is the file to point a dashboard/alerting tool at if you ever want one -
  it's a single flat, ever-growing CSV of every problem this has ever
  detected.

All three behaviors (error-pcap retention split, daily report content and
refresh, error-log append-once-per-hour) were exercised against real
capture data - including deliberately backdating files to confirm a clean
old file gets pruned while an error-flagged old file of the same age
survives - before being handed over.

## How the TLS analysis works (and its limits)

For every TCP stream containing a TLS ClientHello, it's classified as:

- **Complete** — ClientHello + ServerHello + at least one Application Data
  record afterward (the strongest signal available *without decryption
  keys* that encrypted traffic actually flowed post-handshake). Not
  written to the report - only problems are.
- **No response** — ClientHello sent, server never sent a ServerHello at
  all. Dropped, blackholed, or filtered.
- **Aborted** — ServerHello arrived, but no Application Data ever followed
  before the stream went quiet or reset. Handshake started, didn't finish.
- **TLS alert** — an explicit alert (other than `close_notify`, which is
  normal connection teardown) appeared - a protocol-level failure signal
  regardless of the above.

Findings CSV columns: `Stream, Status, Client, Server, SNI, FirstSeen,
LastSeen, Reset, Alerts`.

**This is a heuristic, not a certainty.** Two real limitations:
1. No decryption keys are involved, so "Application Data present" is the
   best available proxy for "the handshake actually finished" - it's a
   good signal, not proof.
2. A stream open across an hourly rotation boundary is only evaluated
   within the single file it's checked against. A handshake that
   legitimately completes a few seconds into the *next* hour's file will
   show as incomplete in this hour's report. Cross-file stream stitching
   isn't implemented - if this matters for your traffic patterns, worth
   knowing before treating every "Aborted" row as a real problem.

Verified against a real capture with one genuine successful handshake and
one deliberately broken one (a TLS ClientHello sent to a plain HTTP port)
before being handed over - both classified correctly, including on IPv6
traffic (an early version had a bug where IPv6 source/dest were blank;
fixed and re-verified).
