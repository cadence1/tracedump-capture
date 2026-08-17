<#
.SYNOPSIS
    Cross-references a list of externally-reported failure timestamps +
    hostnames against the persistent error-log.csv from
    watch-and-analyze.ps1, to check whether the packet capture
    independently observed a TLS handshake problem for that host around
    that time.

.PARAMETER FailuresCsv
    CSV with columns: Timestamp,Host,Description
    Timestamp should be parseable by [datetime], e.g. "2026-08-15 09:03"
    (assumed to already be in the same timezone as the capture machine -
    error-log.csv timestamps are local time, not UTC).

.PARAMETER ErrorLogPath
    Path to error-log.csv (default: C:\tracedump\error-log.csv)

.PARAMETER WindowMinutes
    How many minutes before/after the reported time counts as a match
    (default: 15) - a generous window since "the failure was reported at
    09:03" doesn't mean the TCP stream started at exactly 09:03:00.

.EXAMPLE
    .\correlate-failures.ps1 -FailuresCsv .\ci-failures.csv
#>
param(
    [Parameter(Mandatory = $true)]
    [string]$FailuresCsv,
    [string]$ErrorLogPath = "C:\tracedump\error-log.csv",
    [int]$WindowMinutes = 15
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $FailuresCsv)) { throw "Failures CSV not found: $FailuresCsv" }
if (-not (Test-Path $ErrorLogPath)) { throw "error-log.csv not found: $ErrorLogPath" }

$failures = Import-Csv $FailuresCsv
$errorLog = Import-Csv $ErrorLogPath

Write-Host "Loaded $($failures.Count) reported failure(s), searching $($errorLog.Count) capture finding(s) (+/-$WindowMinutes min window)..."
Write-Host ""

$matchedCount = 0
foreach ($fail in $failures) {
    $reportedTime = [datetime]$fail.Timestamp
    $windowStart = $reportedTime.AddMinutes(-$WindowMinutes)
    $windowEnd = $reportedTime.AddMinutes($WindowMinutes)

    $matches = $errorLog | Where-Object {
        $_.SNI -eq $fail.Host -and $_.FirstSeen -and
        ([datetime]$_.FirstSeen) -ge $windowStart -and ([datetime]$_.FirstSeen) -le $windowEnd
    }

    Write-Host "[$($fail.Timestamp)] $($fail.Host) - $($fail.Description)"
    if ($matches.Count -gt 0) {
        $matchedCount++
        Write-Host "  MATCHED $($matches.Count) capture finding(s):" -ForegroundColor Green
        foreach ($m in $matches) {
            Write-Host "    $($m.FirstSeen)  Status=$($m.Status)  Client=$($m.Client)  Server=$($m.Server)  SourceFile=$($m.SourceFile)"
            if ($m.Alerts) { Write-Host "      Alerts: $($m.Alerts)" }
        }
    } else {
        Write-Host "  NO MATCH in capture data within the window" -ForegroundColor Yellow
    }
    Write-Host ""
}

Write-Host "---"
Write-Host "$matchedCount / $($failures.Count) reported failures had a corresponding capture finding."
Write-Host "For unmatched entries, the heuristic may have classified that stream as 'Complete' (a real"
Write-Host "handshake that failed at the application layer after TLS finished won't show up here), the"
Write-Host "relevant hourly pcap may already have been pruned, or the mirror genuinely didn't capture it"
Write-Host "(see the ERSPAN packet-loss discussion). To check a specific hour's raw pcap directly:"
Write-Host '  & "C:\Program Files\Wireshark\tshark.exe" -r <hour''s pcap> -Y "tls.handshake.extensions_server_name==""<host>""" -T fields -e frame.time -e tcp.stream -e tls.handshake.type'
