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
$TsharkStdErr = Join-Path $OutDir "tshark-stderr.log"   # tshark's own stderr (rolling, see below)
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
        # Start-Process + true OS-level redirection, NOT the `&` call
        # operator. PowerShell's `&` wraps a native command's stderr in
        # its own error-record machinery: with $ErrorActionPreference =
        # "Stop", ANY text tshark writes to stderr (even routine startup
        # chatter like "Capturing on 'X'") can get turned into a
        # terminating exception - and this isn't specific to `2>&1`;
        # *>> file redirection goes through the same PowerShell-level
        # stream handling and doesn't avoid it either (learned the hard
        # way - see git history). Start-Process's -RedirectStandardError
        # is a real OS-level redirect that never touches PowerShell's
        # stream machinery, so tshark's normal output can never
        # masquerade as a script-terminating error. Verified directly
        # against this exact failure shape (stderr write + non-zero
        # exit, under $ErrorActionPreference=Stop and
        # $PSNativeCommandUseErrorActionPreference=$true) before shipping.
        $proc = Start-Process -FilePath $TsharkExe -ArgumentList $args -NoNewWindow -Wait -PassThru `
            -RedirectStandardOutput (Join-Path $OutDir "tshark-stdout.log") `
            -RedirectStandardError $TsharkStdErr
        $exitCode = $proc.ExitCode
        if (Test-Path $TsharkStdErr) {
            Get-Content $TsharkStdErr -ErrorAction SilentlyContinue | ForEach-Object { Add-Content -Path $LogFile -Value "  tshark: $_" }
        }
    } catch {
        Write-Log "tshark launch failed: $_"
    }
    Write-Log "tshark exited (code $exitCode) - restarting in 5s"
    Start-Sleep -Seconds 5
}
