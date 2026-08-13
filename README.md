# Mirror-port capture + TLS handshake analysis

Continuous packet capture off a SPAN/mirror port on Windows, rotating to a
new file every hour, with automatic scanning of each hour's capture for
TCP streams where a TLS handshake started but never completed.

## Files

- **`capture.ps1`** — continuous capture loop. Runs `tshark` in ring-buffer
  mode (`-b duration:3600`), which handles hourly file rotation internally;
  the outer loop just restarts tshark if it ever exits unexpectedly.
- **`analyze-tls.ps1`** — analyzes a single pcap, writes
  `<name>.tls-findings.csv` next to it. Can be run standalone against any
  pcap, not just ones produced by `capture.ps1`.
- **`watch-and-analyze.ps1`** — polls `C:\tracedump` for hourly files that
  have finished rotating, runs `analyze-tls.ps1` on any that don't have a
  report yet, maintains a daily aggregate report and a persistent error
  log, and prunes old files.

## Prerequisites

- Wireshark/tshark at `C:\Program Files\Wireshark\tshark.exe`
- **Run as Administrator** — Npcap requires elevated privileges for live
  capture; both `capture.ps1` and any Scheduled Task running it need to
  run elevated
- Confirm the mirror port's interface number with `tshark -D` — set in
  `capture.ps1` as `$Interface`. Interface numbering can shift if adapters
  are added/removed, so re-check if capture ever looks wrong.

## Setup

Foreground test first:

```powershell
cd C:\path\to\tracedump-capture
.\capture.ps1
```

Let it run a few minutes, `Ctrl+C`, then check `C:\tracedump` for a
`.pcap` file, and run the analyzer against it manually:

```powershell
.\analyze-tls.ps1 -PcapPath "C:\tracedump\mirror.pcap"
```

For continuous operation, install both scripts as separate Scheduled
Tasks — capture and analysis are deliberately independent processes, so a
slow/hung analysis pass can never interrupt the live capture:

```powershell
$capArgs = "-NoProfile -ExecutionPolicy Bypass -File `"C:\path\to\tracedump-capture\capture.ps1`""
schtasks /create /tn "Mirror Port Capture" /tr "powershell.exe $capArgs" /sc onstart /ru SYSTEM /rl HIGHEST /f

$watchArgs = "-NoProfile -ExecutionPolicy Bypass -File `"C:\path\to\tracedump-capture\watch-and-analyze.ps1`""
schtasks /create /tn "Mirror Port Analysis" /tr "powershell.exe $watchArgs" /sc onstart /ru SYSTEM /rl HIGHEST /f

schtasks /run /tn "Mirror Port Capture"
schtasks /run /tn "Mirror Port Analysis"
```

`/ru SYSTEM /rl HIGHEST` runs elevated without storing a user password in
the task. Adjust the `-File` paths to match where this folder actually is.

## Configuration

Edit the `# ---- config ----` block near the top of each script:

| Script | Setting | Default | Meaning |
|---|---|---|---|
| `capture.ps1` | `$Interface` | `"1"` | tshark interface number from `tshark -D` |
| `capture.ps1` | `$OutDir` | `C:\tracedump` | where hourly pcaps land |
| `capture.ps1` | `$RotateSecs` | `3600` | seconds per file |
| `watch-and-analyze.ps1` | `$PollSeconds` | `300` | how often to check for finished files |
| `watch-and-analyze.ps1` | `$RetentionDays` | `7` | auto-delete **clean** pcaps + reports older than this; `0` = keep forever |
| `watch-and-analyze.ps1` | `$ErrorRetentionDays` | `0` (forever) | auto-delete pcaps **with findings** older than this |

## Output

- **Per-hour findings** — `<pcap-name>.tls-findings.csv` next to each pcap.
- **Retention split** — pcaps with at least one flagged finding are kept
  per `$ErrorRetentionDays` instead of `$RetentionDays`, so hours with
  something worth keeping stick around longer (or forever) while routine
  clean hours still get pruned on schedule.
- **Daily report** — `daily-reports\YYYY-MM-DD.csv` (every flagged row for
  the day) and `YYYY-MM-DD-summary.txt` (counts by status, top 10 affected
  SNIs). Regenerated from scratch each poll cycle, so it's always current.
- **Persistent error log** — `error-log.csv`. Every flagged finding, from
  every hour, appended once with a `SourceFile` column, independent of
  pcap retention — findings stay here permanently even after their source
  pcap is eventually pruned. Point any future dashboard/alerting at this
  file.

## How the TLS analysis works

For every TCP stream containing a TLS ClientHello:

| Status | Meaning |
|---|---|
| Complete | ClientHello + ServerHello + Application Data afterward (not written to the report) |
| No response | ClientHello sent, server never replied — dropped/blackholed/filtered |
| Aborted | ServerHello arrived, but no Application Data ever followed |
| TLS alert | An explicit alert (other than `close_notify`) appeared |

Findings CSV columns: `Stream, Status, Client, Server, SNI, FirstSeen,
LastSeen, Reset, Alerts`.

**This is a heuristic, not a certainty:**
1. No decryption keys are involved, so "Application Data present" is the
   best available proxy for "the handshake finished" — a good signal, not
   proof.
2. A stream open across an hourly rotation boundary is only evaluated
   within the file it's checked against — a handshake that completes a
   few seconds into the next hour's file will show as incomplete here.
   Cross-file stream stitching isn't implemented.
