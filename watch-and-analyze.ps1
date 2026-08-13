<#
.SYNOPSIS
    Companion process to capture.ps1. Watches C:\tracedump for hourly
    pcap files that tshark has finished writing (rotated past), analyzes
    each one exactly once, and maintains:
      - retention pruning (clean captures pruned after $RetentionDays;
        captures with findings kept separately per $ErrorRetentionDays)
      - a daily aggregate report (CSV + text summary) per calendar day
      - error-log.csv: a persistent, append-only ledger of every flagged
        finding ever seen, independent of whether the source pcap is
        later pruned

.NOTES
    Run this alongside capture.ps1 (separate process/Scheduled Task) -
    not merged into it, so a hung/slow analysis pass never risks
    interrupting the live capture.
#>

$ErrorActionPreference = "Stop"

# ---- config ----------------------------------------------------------
$OutDir             = "C:\tracedump"
$FilePrefix         = "mirror"
$PollSeconds        = 300              # check every 5 minutes
$RetentionDays      = 7                # clean (no findings) pcaps; 0 = keep forever
$ErrorRetentionDays = 0                # pcaps WITH findings; 0 = keep forever
$AnalyzeScript      = Join-Path $PSScriptRoot "analyze-tls.ps1"
$LogFile            = Join-Path $OutDir "watch.log"
$ErrorLogPath       = Join-Path $OutDir "error-log.csv"
$DailyReportDir     = Join-Path $OutDir "daily-reports"
# ------------------------------------------------------------------------

function Write-Log($msg) {
    $line = "[{0}] {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $msg
    Write-Host $line
    Add-Content -Path $LogFile -Value $line
}

function Get-FindingsPath([string]$pcapFullName) {
    return [System.IO.Path]::ChangeExtension($pcapFullName, $null).TrimEnd(".") + ".tls-findings.csv"
}

function Get-FileDateStamp([string]$fileName) {
    # tshark ring-buffer naming: mirror_00001_20260813162720.pcap
    if ($fileName -match '_(\d{8})\d{6}\.pcap$') { return $matches[1] }
    return $null
}

function Test-HasFindings([string]$csvPath) {
    if (-not (Test-Path $csvPath)) { return $false }
    # header-only file has exactly 1 line
    return (Get-Content -Path $csvPath | Measure-Object -Line).Lines -gt 1
}

function Add-ToErrorLog([string]$findingsPath, [string]$sourceFileName) {
    if (-not (Test-HasFindings $findingsPath)) { return }
    $rows = Import-Csv $findingsPath | ForEach-Object {
        $_ | Add-Member -NotePropertyName "SourceFile" -NotePropertyValue $sourceFileName -PassThru
    }
    if (Test-Path $ErrorLogPath) {
        $rows | Export-Csv -Path $ErrorLogPath -NoTypeInformation -Append
    } else {
        $rows | Export-Csv -Path $ErrorLogPath -NoTypeInformation
    }
    Write-Log "Appended $($rows.Count) finding(s) from $sourceFileName to error-log.csv"
}

function Update-DailyReport {
    if (-not (Test-Path $DailyReportDir)) { New-Item -ItemType Directory -Path $DailyReportDir -Force | Out-Null }
    $today = Get-Date -Format "yyyyMMdd"

    $todaysFindingsFiles = Get-ChildItem -Path $OutDir -Filter "$FilePrefix*.tls-findings.csv" -ErrorAction SilentlyContinue |
        Where-Object { (Get-FileDateStamp ($_.Name -replace '\.tls-findings\.csv$', '.pcap')) -eq $today }

    $allRows = @()
    foreach ($f in $todaysFindingsFiles) {
        if (Test-HasFindings $f.FullName) {
            $sourceName = $f.Name -replace '\.tls-findings\.csv$', '.pcap'
            $allRows += Import-Csv $f.FullName | ForEach-Object {
                $_ | Add-Member -NotePropertyName "SourceFile" -NotePropertyValue $sourceName -PassThru
            }
        }
    }

    $reportDate = [datetime]::ParseExact($today, "yyyyMMdd", $null).ToString("yyyy-MM-dd")
    $csvPath = Join-Path $DailyReportDir "$reportDate.csv"
    $summaryPath = Join-Path $DailyReportDir "$reportDate-summary.txt"

    if ($allRows.Count -gt 0) {
        $allRows | Sort-Object FirstSeen | Export-Csv -Path $csvPath -NoTypeInformation
    } else {
        "Stream,Status,Client,Server,SNI,FirstSeen,LastSeen,Reset,Alerts,SourceFile" | Out-File -FilePath $csvPath -Encoding utf8
    }

    $summary = @(
        "Daily TLS handshake report - $reportDate",
        "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') (today's report is refreshed every poll until the day ends)",
        "Hourly files checked so far: $($todaysFindingsFiles.Count)",
        "Total flagged streams: $($allRows.Count)"
    )
    if ($allRows.Count -gt 0) {
        $summary += ""
        $summary += "By status:"
        $allRows | Group-Object Status | Sort-Object Count -Descending | ForEach-Object {
            $summary += "  $($_.Name): $($_.Count)"
        }
        $summary += ""
        $summary += "Top affected SNIs:"
        $allRows | Where-Object { $_.SNI } | Group-Object SNI | Sort-Object Count -Descending |
            Select-Object -First 10 | ForEach-Object { $summary += "  $($_.Name): $($_.Count)" }
    }
    $summary | Out-File -FilePath $summaryPath -Encoding utf8
}

if (-not (Test-Path $OutDir)) {
    throw "$OutDir does not exist yet - start capture.ps1 first."
}

Write-Log "Watching $OutDir every ${PollSeconds}s (clean retention: $RetentionDays d, error retention: $(if ($ErrorRetentionDays -gt 0) { \"$ErrorRetentionDays d\" } else { 'forever' }))"

while ($true) {
    try {
        $pcaps = Get-ChildItem -Path $OutDir -Filter "$FilePrefix*.pcap" | Sort-Object LastWriteTime

        if ($pcaps.Count -gt 1) {
            # The most recently modified file is presumed still being written
            # by tshark - skip it, analyze everything else that doesn't yet
            # have a report.
            $inProgress = $pcaps[-1]
            $finalized = $pcaps | Where-Object { $_.FullName -ne $inProgress.FullName }

            foreach ($f in $finalized) {
                $findingsPath = Get-FindingsPath $f.FullName
                if (-not (Test-Path $findingsPath)) {
                    Write-Log "Analyzing $($f.Name)..."
                    try {
                        & $AnalyzeScript -PcapPath $f.FullName 2>&1 | ForEach-Object { Add-Content -Path $LogFile -Value $_ }
                        Add-ToErrorLog -findingsPath $findingsPath -sourceFileName $f.Name
                    } catch {
                        Write-Log "Analysis failed for $($f.Name): $_"
                    }
                }
            }
        }

        Update-DailyReport

        # ---- retention: clean captures vs. error-flagged captures -------
        $cleanCutoff = if ($RetentionDays -gt 0) { (Get-Date).AddDays(-$RetentionDays) } else { $null }
        $errorCutoff = if ($ErrorRetentionDays -gt 0) { (Get-Date).AddDays(-$ErrorRetentionDays) } else { $null }

        if ($cleanCutoff -or $errorCutoff) {
            $allPcaps = Get-ChildItem -Path $OutDir -Filter "$FilePrefix*.pcap" -File
            foreach ($f in $allPcaps) {
                $findingsPath = Get-FindingsPath $f.FullName
                $hasFindings = Test-HasFindings $findingsPath

                if ($hasFindings) {
                    if ($errorCutoff -and $f.LastWriteTime -lt $errorCutoff) {
                        Write-Log "Pruning old ERROR-flagged capture (>${ErrorRetentionDays}d, already in error-log.csv): $($f.Name)"
                        Remove-Item -Path $f.FullName -Force
                        Remove-Item -Path $findingsPath -Force -ErrorAction SilentlyContinue
                    }
                    # else kept - either ErrorRetentionDays=0 (forever) or not yet past its own cutoff
                } elseif ($cleanCutoff -and $f.LastWriteTime -lt $cleanCutoff) {
                    Write-Log "Pruning old clean capture (>${RetentionDays}d): $($f.Name)"
                    Remove-Item -Path $f.FullName -Force
                    Remove-Item -Path $findingsPath -Force -ErrorAction SilentlyContinue
                }
            }
        }
    } catch {
        Write-Log "Watch loop error: $_"
    }
    Start-Sleep -Seconds $PollSeconds
}
