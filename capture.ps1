<#
.SYNOPSIS
    Continuous packet capture off a mirror/SPAN port, rotating to a new
    file every hour. Runs tshark in ring-buffer mode as a single
    long-lived process (tshark itself handles the hourly file rotation -
    no external loop needed for that part), with an outer restart loop
    in case tshark exits unexpectedly (crash, adapter hiccup, etc).

.NOTES
    Run this directly for a foreground test, or install as a Scheduled
    Task for persistent/unattended operation (see README.md).
#>

$ErrorActionPreference = "Stop"

# ---- config ----------------------------------------------------------
$TsharkExe   = "C:\Program Files\Wireshark\tshark.exe"
$Interface   = "1"                      # from `tshark -D`: Ethernet0 2 (mirror port)
$OutDir      = "C:\tracedump"
$FilePrefix  = "mirror"
$RotateSecs  = 3600                     # 1 hour
$LogFile     = Join-Path $OutDir "capture.log"
# ------------------------------------------------------------------------

if (-not (Test-Path $TsharkExe)) {
    throw "tshark.exe not found at $TsharkExe - adjust `$TsharkExe at the top of this script."
}
if (-not (Test-Path $OutDir)) {
    New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
}

function Write-Log($msg) {
    $line = "[{0}] {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $msg
    Write-Host $line
    Add-Content -Path $LogFile -Value $line
}

Write-Log "Starting capture loop on interface $Interface -> $OutDir (rotate every ${RotateSecs}s)"

while ($true) {
    $outFile = Join-Path $OutDir "$FilePrefix.pcap"
    $args = @(
        "-i", $Interface,
        "-b", "duration:$RotateSecs",
        "-F", "pcap",
        "-w", $outFile
    )
    Write-Log "Launching: tshark $($args -join ' ')"
    $exitCode = $null
    try {
        # Redirect tshark's stdout+stderr directly to the log file with
        # native redirection (*>>), NOT `2>&1 | ForEach-Object`. tshark
        # writes routine status messages (e.g. "Capturing on 'X'") to
        # stderr - piping stderr through `2>&1` turns each line into a
        # PowerShell ErrorRecord, and with $ErrorActionPreference="Stop"
        # that silently converts a harmless startup message into a
        # terminating error, killing and restarting tshark every few
        # seconds without ever actually capturing anything. Direct file
        # redirection bypasses PowerShell's error-object wrapping entirely.
        & $TsharkExe @args *>> $LogFile
        $exitCode = $LASTEXITCODE
    } catch {
        Write-Log "tshark launch failed: $_"
    }
    Write-Log "tshark exited (code $exitCode) - restarting in 5s"
    Start-Sleep -Seconds 5
}
