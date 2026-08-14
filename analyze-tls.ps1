<#
.SYNOPSIS
    Scans a single pcap for TCP streams with a ClientHello that never
    reached a completed TLS handshake, and writes a findings report next
    to the pcap.

.DESCRIPTION
    Heuristic-based (no decryption keys involved), classifying each TCP
    stream that contains a TLS ClientHello as:
      - Complete      : ClientHello + ServerHello + at least one
                         Application Data record afterward (the strongest
                         signal available without keys that real encrypted
                         traffic actually flowed post-handshake)
      - No response   : ClientHello sent, server never sent a ServerHello
                         at all (dropped/blackholed/filtered)
      - Aborted        : ServerHello was sent but no Application Data ever
                         followed before the stream ended (RST/FIN, or
                         just went quiet) - handshake started but didn't
                         finish
      - TLS alert      : an alert (other than close_notify) appeared,
                         which is an explicit protocol-level failure
                         signal regardless of the above

    KNOWN LIMITATION: streams open across an hourly file-rotation boundary
    are only analyzed within the single file they're evaluated against, so
    a handshake that legitimately completes a few seconds into the next
    hour's file will show as incomplete here. This is a heuristic tool for
    spotting patterns, not a definitive per-connection verdict.

.PARAMETER PcapPath
    Path to a single .pcap file to analyze.
#>
param(
    [Parameter(Mandatory = $true)]
    [string]$PcapPath
)

$ErrorActionPreference = "Stop"
$TsharkExe = "C:\Program Files\Wireshark\tshark.exe"

if (-not (Test-Path $PcapPath)) { throw "File not found: $PcapPath" }
if (-not (Test-Path $TsharkExe)) { throw "tshark.exe not found at $TsharkExe" }

$filter = "tls.handshake.type or tls.alert_message or tls.record.content_type==23 or tcp.flags.reset==1"
$fields = @(
    "frame.time_epoch", "tcp.stream", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst", "tcp.srcport", "tcp.dstport",
    "tls.handshake.type", "tls.alert_message.level", "tls.alert_message.desc",
    "tls.record.content_type", "tcp.flags.reset", "tls.handshake.extensions_server_name"
)
$tsharkArgs = @("-r", $PcapPath, "-Y", $filter, "-T", "fields")
foreach ($f in $fields) { $tsharkArgs += @("-e", $f) }
$tsharkArgs += @("-E", "separator=/t", "-E", "quote=n", "-E", "header=n", "-E", "occurrence=a")
# We don't care about JSON payloads at all here (TLS fields only), and the
# JSON dissector has a known bug where a sufficiently large/nested JSON body
# in captured traffic trips an internal safety limit ("Dissector bug ...
# possible infinite loop") and aborts the whole tshark run. Disabling it
# sidesteps the bug entirely rather than trying to tune its limits.
$tsharkArgs += @("--disable-protocol", "json")

function Test-ContainsValue([string]$field, [string]$value) {
    if ([string]::IsNullOrEmpty($field)) { return $false }
    return ($field -split ",") -contains $value
}

$streams = @{}
$stderrCapture = [System.IO.Path]::GetTempFileName()
$tsharkExitCode = 0

# Scope $ErrorActionPreference down to SilentlyContinue for just this call.
# tshark routinely writes warnings to stderr (e.g. "file appears to have
# been cut short") for real problems we want to know about, but under
# $ErrorActionPreference="Stop" any stderr write - or non-zero exit code,
# depending on PowerShell version/settings - can get converted into an
# uncaught terminating exception instead of something we can inspect and
# report on. That previously meant a single bad pcap (truncated file, a
# dissector bug, etc.) killed this script before it ever wrote a findings
# report, which left watch-and-analyze.ps1 retrying the same file forever
# since it only stops retrying once a report file exists. Redirecting
# stderr to its own file (separate from the stdout pipe used for parsing)
# plus the scoped EAP override means a tshark failure now becomes data we
# report on, not an exception that skips reporting entirely.
$prevEAP = $ErrorActionPreference
$ErrorActionPreference = "SilentlyContinue"
try {
    & $TsharkExe @tsharkArgs 2> $stderrCapture | ForEach-Object {
        $parts = $_ -split "`t"
        if ($parts.Count -lt 14) { return }
        $time = $parts[0]; $streamId = $parts[1]
        # ERSPAN/GRE-encapsulated captures have TWO ip layers per packet -
        # the outer tunnel endpoints and the inner original packet. With
        # -E occurrence=a, a field that appears twice comes back comma-
        # joined in outer-to-inner tree order, so the LAST value is the
        # real (innermost) address; a plain, non-encapsulated capture just
        # has one value and this is a no-op.
        $srcIp = if ($parts[2]) { ($parts[2] -split ",")[-1] } else { ($parts[4] -split ",")[-1] }   # ip.src, else ipv6.src
        $dstIp = if ($parts[3]) { ($parts[3] -split ",")[-1] } else { ($parts[5] -split ",")[-1] }   # ip.dst, else ipv6.dst
        $srcPort = $parts[6]; $dstPort = $parts[7]; $hsType = $parts[8]
        $alertLevel = $parts[9]; $alertDesc = $parts[10]; $contentType = $parts[11]
        $reset = $parts[12]; $sni = $parts[13]

        if ([string]::IsNullOrEmpty($streamId)) { return }

        if (-not $streams.ContainsKey($streamId)) {
            $streams[$streamId] = [PSCustomObject]@{
                Stream         = $streamId
                SrcIP          = $srcIp; SrcPort = $srcPort
                DstIP          = $dstIp; DstPort = $dstPort
                SNI            = ""
                FirstSeen      = $time
                LastSeen       = $time
                HasClientHello = $false
                HasServerHello = $false
                HasAppData     = $false
                HasReset       = $false
                Alerts         = New-Object System.Collections.Generic.List[string]
            }
        }
        $s = $streams[$streamId]
        $s.LastSeen = $time

        if (Test-ContainsValue $hsType "1") { $s.HasClientHello = $true; if ($sni) { $s.SNI = $sni } }
        if (Test-ContainsValue $hsType "2") { $s.HasServerHello = $true }
        if (Test-ContainsValue $contentType "23") { $s.HasAppData = $true }
        if ($reset -eq "1") { $s.HasReset = $true }
        if (-not [string]::IsNullOrEmpty($alertDesc)) {
            # alert desc 0 = close_notify, a normal/benign teardown - don't flag on its own
            if ($alertDesc -ne "0") {
                $s.Alerts.Add("level=$alertLevel desc=$alertDesc")
            }
        }
    }
    $tsharkExitCode = $LASTEXITCODE
} finally {
    $ErrorActionPreference = $prevEAP
}
$tsharkStderr = ""
if (Test-Path $stderrCapture) {
    # Get-Content -Raw returns $null (not "") for a zero-byte file - which
    # happens when tshark exits non-zero without ever writing to stderr
    # (e.g. an abrupt kill/crash). Guard against that explicitly rather
    # than calling .Trim() on a possible $null further down.
    $capturedContent = Get-Content $stderrCapture -Raw -ErrorAction SilentlyContinue
    if ($null -ne $capturedContent) { $tsharkStderr = $capturedContent }
}
Remove-Item $stderrCapture -ErrorAction SilentlyContinue

function Format-HostPort([string]$ip, [string]$port) {
    if ($ip -match ":") { return "[$ip]:$port" }  # IPv6 needs brackets when paired with a port
    return "${ip}:${port}"
}

$results = @()
foreach ($s in $streams.Values) {
    if (-not $s.HasClientHello) { continue }  # not a client-initiated TLS stream we care about

    $status = "Complete"
    if ($s.Alerts.Count -gt 0) {
        $status = "TLS alert"
    } elseif (-not $s.HasServerHello) {
        $status = "No response"
    } elseif (-not $s.HasAppData) {
        $status = "Aborted"
    }

    if ($status -ne "Complete") {
        $results += [PSCustomObject]@{
            Stream    = $s.Stream
            Status    = $status
            Client    = Format-HostPort $s.SrcIP $s.SrcPort
            Server    = Format-HostPort $s.DstIP $s.DstPort
            SNI       = $s.SNI
            FirstSeen = [DateTimeOffset]::FromUnixTimeSeconds([math]::Floor([double]$s.FirstSeen)).LocalDateTime
            LastSeen  = [DateTimeOffset]::FromUnixTimeSeconds([math]::Floor([double]$s.LastSeen)).LocalDateTime
            Reset     = $s.HasReset
            Alerts    = ($s.Alerts -join "; ")
        }
    }
}

# tshark itself failed (non-zero exit - e.g. a truncated/corrupt pcap, or a
# dissector bug it hit) rather than just finding zero TLS problems. Flag
# this explicitly instead of silently writing an empty/misleading "all
# clear" report - whatever streams WERE parsed before the failure (if any)
# are still included above; this is additive, not a replacement.
if ($tsharkExitCode -ne 0) {
    $results += [PSCustomObject]@{
        Stream    = ""
        Status    = "Analysis Error"
        Client    = ""
        Server    = ""
        SNI       = ""
        FirstSeen = ""
        LastSeen  = ""
        Reset     = ""
        Alerts    = "tshark exited with code ${tsharkExitCode}: $($tsharkStderr.Trim() -replace '\s+', ' ')"
    }
    Write-Host "WARNING: tshark exited with code $tsharkExitCode reading this file - see Analysis Error row in the report"
}

$reportPath = [System.IO.Path]::ChangeExtension($PcapPath, $null).TrimEnd(".") + ".tls-findings.csv"
if ($results.Count -gt 0) {
    $results | Sort-Object FirstSeen | Export-Csv -Path $reportPath -NoTypeInformation
} else {
    # still write an (empty-of-findings) report so downstream tooling can tell this hour was checked
    "Stream,Status,Client,Server,SNI,FirstSeen,LastSeen,Reset,Alerts" | Out-File -FilePath $reportPath -Encoding utf8
}

$totalStreams = ($streams.Values | Where-Object { $_.HasClientHello }).Count
Write-Host "Analyzed: $PcapPath"
Write-Host "  TLS streams (ClientHello seen): $totalStreams"
Write-Host "  Flagged (incomplete/dropped/alert): $($results.Count)"
if ($results.Count -gt 0) {
    $results | Group-Object Status | ForEach-Object { Write-Host "    $($_.Name): $($_.Count)" }
}
Write-Host "  Report: $reportPath"
