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

function Test-ContainsValue([string]$field, [string]$value) {
    if ([string]::IsNullOrEmpty($field)) { return $false }
    return ($field -split ",") -contains $value
}

$streams = @{}

& $TsharkExe @tsharkArgs | ForEach-Object {
    $parts = $_ -split "`t"
    if ($parts.Count -lt 14) { return }
    $time = $parts[0]; $streamId = $parts[1]
    $srcIp = if ($parts[2]) { $parts[2] } else { $parts[4] }   # ip.src, else ipv6.src
    $dstIp = if ($parts[3]) { $parts[3] } else { $parts[5] }   # ip.dst, else ipv6.dst
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
