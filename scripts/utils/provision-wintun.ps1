[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$DestinationDirectory,

    [Parameter(Mandatory = $true)]
    [string]$EvidencePath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$WintunVersion = "0.14.1"
$ArchiveUri = "https://www.wintun.net/builds/wintun-$WintunVersion.zip"
$ExpectedArchiveSha256 = "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"
$ExpectedDllSha256 = "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce"
$TemporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) "quicfuscate-wintun-$([guid]::NewGuid())"
$ArchivePath = Join-Path $TemporaryRoot "wintun.zip"
$ExtractedRoot = Join-Path $TemporaryRoot "extracted"
$SourceDll = Join-Path $ExtractedRoot "wintun/bin/amd64/wintun.dll"
$DestinationDll = Join-Path $DestinationDirectory "wintun.dll"

try {
    New-Item -ItemType Directory -Path $TemporaryRoot | Out-Null
    Invoke-WebRequest -Uri $ArchiveUri -OutFile $ArchivePath -UseBasicParsing

    $ArchiveSha256 = (Get-FileHash -LiteralPath $ArchivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($ArchiveSha256 -ne $ExpectedArchiveSha256) {
        throw "Wintun archive SHA-256 mismatch: expected $ExpectedArchiveSha256, got $ArchiveSha256"
    }

    Expand-Archive -LiteralPath $ArchivePath -DestinationPath $ExtractedRoot
    if (-not (Test-Path -LiteralPath $SourceDll -PathType Leaf)) {
        throw "Verified Wintun archive does not contain wintun/bin/amd64/wintun.dll"
    }

    $DllSha256 = (Get-FileHash -LiteralPath $SourceDll -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($DllSha256 -ne $ExpectedDllSha256) {
        throw "Wintun DLL SHA-256 mismatch: expected $ExpectedDllSha256, got $DllSha256"
    }

    $Signature = Get-AuthenticodeSignature -LiteralPath $SourceDll
    if ($Signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
        throw "Wintun Authenticode signature is not valid: $($Signature.Status)"
    }

    New-Item -ItemType Directory -Path $DestinationDirectory -Force | Out-Null
    if (Test-Path -LiteralPath $DestinationDll) {
        $ExistingSha256 =
            (Get-FileHash -LiteralPath $DestinationDll -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($ExistingSha256 -ne $ExpectedDllSha256) {
            throw "Refusing to overwrite a different existing file at $DestinationDll"
        }
    }
    else {
        Copy-Item -LiteralPath $SourceDll -Destination $DestinationDll
    }

    $ProvisionedDllSha256 =
        (Get-FileHash -LiteralPath $DestinationDll -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($ProvisionedDllSha256 -ne $ExpectedDllSha256) {
        throw "Provisioned Wintun DLL SHA-256 mismatch: expected $ExpectedDllSha256, got $ProvisionedDllSha256"
    }

    $EvidenceDirectory = Split-Path -Parent $EvidencePath
    if ($EvidenceDirectory) {
        New-Item -ItemType Directory -Path $EvidenceDirectory -Force | Out-Null
    }
    [ordered]@{
        schema = "quicfuscate.wintun-provenance.v1"
        version = $WintunVersion
        source_url = $ArchiveUri
        archive_sha256 = $ArchiveSha256
        dll_architecture = "amd64"
        dll_sha256 = $ProvisionedDllSha256
        authenticode_status = [string]$Signature.Status
        authenticode_subject = $Signature.SignerCertificate.Subject
        destination = $DestinationDll
    } | ConvertTo-Json | Set-Content -LiteralPath $EvidencePath -Encoding utf8

    Write-Output "Provisioned verified Wintun $WintunVersion to $DestinationDll"
    Write-Output "Archive SHA-256: $ArchiveSha256"
    Write-Output "DLL SHA-256: $DllSha256"
    Write-Output "Authenticode subject: $($Signature.SignerCertificate.Subject)"
}
finally {
    if (Test-Path -LiteralPath $TemporaryRoot) {
        Remove-Item -LiteralPath $TemporaryRoot -Recurse -Force
    }
}
