# Copy this file to upload-config.ps1 (gitignored, never committed) and
# fill in your real values. Used by watch-and-analyze.ps1 when
# $UploadToCloudShark = $true, to push pcaps WITH findings to a
# CloudShark-compatible receiver (github.com/cadence1/Meraki-Cloudshark-Receiver).
# Clean hours are never uploaded, regardless of this config.

$CloudSharkUrl   = "https://cloudshark.example.com:8443"   # no trailing slash
$CloudSharkToken = ""                                       # CLOUDSHARK_RECEIVER_TOKEN from that project's .env
