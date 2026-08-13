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
    # Use the plain `&` call operator - confirmed on the real capture
    # machine to actually work for live capture, unlike Start-Process
    # (which launched without error but silently produced no output
    # there - Npcap's driver access apparently doesn't transfer cleanly
    # to a Start-Process-launched child even when run interactively as
    # the same user). The problem was never `&` itself; it's that
    # PowerShell wraps a native command's stderr in its own error-record
    # machinery, and with $ErrorActionPreference="Stop" that can turn
    # routine stderr chatter (tshark's "Capturing on 'X'") into a
    # terminating exception - regardless of redirection syntax (2>&1 and
    # *>> both go through it). Fix: scope $ErrorActionPreference down to
    # SilentlyContinue for just this call (restored immediately after),
    # which suppresses both the exception AND the console noise a plain
    # "Continue" still leaves behind. Verified against the exact failure
    # shape (stderr write + non-zero exit, under
    # $PSNativeCommandUseErrorActionPreference=$true) before shipping.
    $prevEAP = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"
    try {
        & $TsharkExe @args *>> $LogFile
        $exitCode = $LASTEXITCODE
    } catch {
        Write-Log "tshark launch failed: $_"
    } finally {
        $ErrorActionPreference = $prevEAP
    }
    Write-Log "tshark exited (code $exitCode) - restarting in 5s"
    Start-Sleep -Seconds 5
}
