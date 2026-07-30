[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$BinaryPath,

    [Parameter(Mandatory = $true)]
    [string]$EvidenceDirectory,

    [string]$AdapterName = "QuicFuscate-CI-Omega",
    [string]$ClientTunAddress = "10.252.0.2",
    [string]$ServerTunAddress = "10.252.0.1",
    [string]$ClientTunAddress6 = "fd00::2",
    [string]$ServerTunAddress6 = "fd00::1"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Endpoint = $env:QUICFUSCATE_WINDOWS_E2E_ENDPOINT
$QKey = $env:QUICFUSCATE_WINDOWS_E2E_QKEY
$CaPem = $env:QUICFUSCATE_WINDOWS_E2E_CA_PEM
$ClientProcess = $null
$CleanupRequired = $false
$TemporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) `
    "quicfuscate-wintun-omega-$([guid]::NewGuid())"
$CaPath = Join-Path $TemporaryRoot "ca.crt"
$StandardOutputPath = Join-Path $TemporaryRoot "client.stdout.log"
$StandardErrorPath = Join-Path $TemporaryRoot "client.stderr.log"

function Require-SecretValue {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [AllowEmptyString()]
        [string]$Value
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        throw "Required secret environment variable $Name is missing"
    }
}

function Read-SharedText {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $Stream = [System.IO.FileStream]::new(
        $Path,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::ReadWrite
    )
    try {
        $Reader = [System.IO.StreamReader]::new($Stream)
        try {
            return $Reader.ReadToEnd()
        }
        finally {
            $Reader.Dispose()
        }
    }
    finally {
        $Stream.Dispose()
    }
}

function Write-RedactedClientLogs {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Paths,

        [Parameter(Mandatory = $true)]
        [string]$DestinationDirectory,

        [Parameter(Mandatory = $true)]
        [string[]]$SensitiveValues
    )

    foreach ($Path in $Paths) {
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
            continue
        }
        $Content = Read-SharedText -Path $Path
        foreach ($SensitiveValue in $SensitiveValues) {
            if (-not [string]::IsNullOrWhiteSpace($SensitiveValue)) {
                $Content = $Content.Replace($SensitiveValue, "<redacted>")
            }
        }
        foreach ($SensitiveValue in $SensitiveValues) {
            if ((-not [string]::IsNullOrWhiteSpace($SensitiveValue)) -and
                $Content.Contains($SensitiveValue)) {
                throw "Redacted client evidence still contains a sensitive value"
            }
        }
        $Destination = Join-Path $DestinationDirectory `
            ([System.IO.Path]::GetFileName($Path))
        [System.IO.File]::WriteAllText($Destination, $Content)
    }
}

function Wait-ForLogPattern {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Paths,

        [Parameter(Mandatory = $true)]
        [string]$Pattern,

        [Parameter(Mandatory = $true)]
        [System.Diagnostics.Process]$Process,

        [int]$TimeoutSeconds = 60
    )

    $Deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while ([DateTime]::UtcNow -lt $Deadline) {
        $Process.Refresh()
        if ($Process.HasExited) {
            throw "QuicFuscate client exited before log pattern '$Pattern'"
        }
        foreach ($Path in $Paths) {
            if ((Test-Path -LiteralPath $Path -PathType Leaf) -and
                (Read-SharedText -Path $Path).Contains($Pattern)) {
                return
            }
        }
        Start-Sleep -Milliseconds 100
    }
    throw "Timed out waiting for QuicFuscate client log pattern '$Pattern'"
}

function Invoke-ExactFirewallCleanup {
    if (-not (Test-Path -LiteralPath $BinaryPath -PathType Leaf)) {
        return
    }
    & $BinaryPath client --remote $Endpoint --cleanup-firewall
    if ($LASTEXITCODE -ne 0) {
        throw "QuicFuscate stale firewall cleanup exited with $LASTEXITCODE"
    }
}

function Wait-ForAdapterAbsence {
    $Deadline = [DateTime]::UtcNow.AddSeconds(15)
    do {
        $Adapters = @(Get-NetAdapter -Name $AdapterName -IncludeHidden `
            -ErrorAction SilentlyContinue)
        if ($Adapters.Count -eq 0) {
            return
        }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $Deadline)

    throw "Wintun adapter '$AdapterName' remained after client process exit"
}

function Wait-ForTunnelAdapterReady {
    $Deadline = [DateTime]::UtcNow.AddSeconds(15)
    $LastDiagnostic = "adapter not observed"
    do {
        $Adapters = @(Get-NetAdapter -Name $AdapterName -IncludeHidden `
            -ErrorAction SilentlyContinue)
        if ($Adapters.Count -eq 1) {
            $Adapter = $Adapters[0]
            $Ipv4Addresses = @(Get-NetIPAddress -InterfaceIndex $Adapter.ifIndex `
                -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                Where-Object IPAddress -eq $ClientTunAddress)
            $Ipv6Addresses = @(Get-NetIPAddress -InterfaceIndex $Adapter.ifIndex `
                -AddressFamily IPv6 -ErrorAction SilentlyContinue |
                Where-Object IPAddress -eq $ClientTunAddress6)
            $Ipv4Interfaces = @(Get-NetIPInterface -InterfaceIndex $Adapter.ifIndex `
                -AddressFamily IPv4 -ErrorAction SilentlyContinue)
            $Ipv6Interfaces = @(Get-NetIPInterface -InterfaceIndex $Adapter.ifIndex `
                -AddressFamily IPv6 -ErrorAction SilentlyContinue)
            $LastDiagnostic = "status=$($Adapter.Status) ipv4=$($Ipv4Addresses.Count) " +
                "ipv6=$($Ipv6Addresses.Count) mtu4=$($Ipv4Interfaces.NlMtuBytes -join ',') " +
                "mtu6=$($Ipv6Interfaces.NlMtuBytes -join ',')"
            if (($Adapter.Status -eq "Up") -and
                ($Ipv4Addresses.Count -eq 1) -and
                ($Ipv6Addresses.Count -eq 1) -and
                ($Ipv4Interfaces.Count -eq 1) -and
                ($Ipv6Interfaces.Count -eq 1)) {
                return [ordered]@{
                    if_index = $Adapter.ifIndex
                    status = [string]$Adapter.Status
                    mtu_ipv4 = $Ipv4Interfaces[0].NlMtuBytes
                    mtu_ipv6 = $Ipv6Interfaces[0].NlMtuBytes
                }
            }
        }
        else {
            $LastDiagnostic = "adapter_count=$($Adapters.Count)"
        }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $Deadline)

    throw "Wintun adapter '$AdapterName' did not become dual-stack ready: $LastDiagnostic"
}

Require-SecretValue -Name "QUICFUSCATE_WINDOWS_E2E_ENDPOINT" -Value $Endpoint
Require-SecretValue -Name "QUICFUSCATE_WINDOWS_E2E_QKEY" -Value $QKey
Require-SecretValue -Name "QUICFUSCATE_WINDOWS_E2E_CA_PEM" -Value $CaPem

if (-not (Test-Path -LiteralPath $BinaryPath -PathType Leaf)) {
    throw "QuicFuscate binary does not exist: $BinaryPath"
}
$WintunPath = Join-Path (Split-Path -Parent $BinaryPath) "wintun.dll"
if (-not (Test-Path -LiteralPath $WintunPath -PathType Leaf)) {
    throw "Verified Wintun DLL is not beside the QuicFuscate binary: $WintunPath"
}

$Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = [Security.Principal.WindowsPrincipal]::new($Identity)
if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "The native Wintun Omega proof requires an elevated Windows runner"
}

$EndpointHost = $Endpoint
if ($EndpointHost.StartsWith("[")) {
    $ClosingBracket = $EndpointHost.IndexOf("]")
    if ($ClosingBracket -lt 2) {
        throw "Invalid bracketed endpoint: $Endpoint"
    }
    $EndpointHost = $EndpointHost.Substring(1, $ClosingBracket - 1)
}
elseif ($EndpointHost.Contains(":")) {
    $EndpointHost = $EndpointHost.Substring(0, $EndpointHost.LastIndexOf(":"))
}
if ([string]::IsNullOrWhiteSpace($EndpointHost)) {
    throw "Invalid endpoint host: $Endpoint"
}

New-Item -ItemType Directory -Path $TemporaryRoot | Out-Null
New-Item -ItemType Directory -Path $EvidenceDirectory -Force | Out-Null
[System.IO.File]::WriteAllText($CaPath, $CaPem)
[Environment]::SetEnvironmentVariable("QUICFUSCATE_WINDOWS_E2E_ENDPOINT", $null, "Process")
[Environment]::SetEnvironmentVariable("QUICFUSCATE_WINDOWS_E2E_QKEY", $null, "Process")
[Environment]::SetEnvironmentVariable("QUICFUSCATE_WINDOWS_E2E_CA_PEM", $null, "Process")
$CaPem = $null

try {
    Invoke-ExactFirewallCleanup

    $Arguments = @(
        "client",
        "--remote", $Endpoint,
        "--url", "https://$EndpointHost/",
        "--qkey", $QKey,
        "--ca-file", $CaPath,
        "--verify-peer",
        "--no-utls",
        "--tun",
        "--tun-name", $AdapterName,
        "--tun-ip", $ClientTunAddress,
        "--tun-netmask", "255.255.255.0",
        "--tun-ip6", $ClientTunAddress6,
        "--tun-prefix6", "64",
        "--kill-switch",
        "--heartbeat-timeout-ms", "15000",
        "-v"
    )
    $ClientProcess = Start-Process -FilePath $BinaryPath `
        -ArgumentList $Arguments `
        -NoNewWindow `
        -PassThru `
        -RedirectStandardOutput $StandardOutputPath `
        -RedirectStandardError $StandardErrorPath
    $Arguments[6] = "<cleared>"
    $CleanupRequired = $true

    Wait-ForLogPattern -Paths @($StandardOutputPath, $StandardErrorPath) `
        -Pattern "TLS handshake complete" `
        -Process $ClientProcess
    Wait-ForLogPattern -Paths @($StandardOutputPath, $StandardErrorPath) `
        -Pattern "Kill switch: VPN traffic allowed, non-VPN blocked" `
        -Process $ClientProcess

    $AdapterSnapshot = Wait-ForTunnelAdapterReady

    $PingSuccesses = 0
    for ($Attempt = 1; $Attempt -le 5; $Attempt++) {
        if (Test-Connection -TargetName $ServerTunAddress -IPv4 -Count 1 `
            -Quiet -TimeoutSeconds 3) {
            $PingSuccesses++
        }
    }
    if ($PingSuccesses -ne 5) {
        throw "Authenticated Wintun IPv4 tunnel ping passed $PingSuccesses/5 attempts"
    }

    $PingSuccesses6 = 0
    for ($Attempt = 1; $Attempt -le 5; $Attempt++) {
        if (Test-Connection -TargetName $ServerTunAddress6 -IPv6 -Count 1 `
            -Quiet -TimeoutSeconds 3) {
            $PingSuccesses6++
        }
    }
    if ($PingSuccesses6 -ne 5) {
        throw "Authenticated Wintun IPv6 tunnel ping passed $PingSuccesses6/5 attempts"
    }

    $ClientProcess.Refresh()
    if ($ClientProcess.HasExited) {
        throw "QuicFuscate client exited after authenticated tunnel ping"
    }

    $CombinedLog = ""
    foreach ($LogPath in @($StandardOutputPath, $StandardErrorPath)) {
        if (Test-Path -LiteralPath $LogPath -PathType Leaf) {
            $CombinedLog += Read-SharedText -Path $LogPath
        }
    }
    if ($CombinedLog.Contains($QKey)) {
        throw "QuicFuscate client log exposed the raw QKey"
    }

    Stop-Process -Id $ClientProcess.Id -Force
    Wait-Process -Id $ClientProcess.Id -Timeout 15
    $ClientProcess = $null

    Invoke-ExactFirewallCleanup
    $CleanupRequired = $false
    Wait-ForAdapterAbsence

    $Os = Get-CimInstance Win32_OperatingSystem
    $EndpointHash = [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData(
            [Text.Encoding]::UTF8.GetBytes($Endpoint)
        )
    ).ToLowerInvariant()
    $BinarySha256 =
        (Get-FileHash -LiteralPath $BinaryPath -Algorithm SHA256).Hash.ToLowerInvariant()
    [ordered]@{
        schema = "quicfuscate.wintun-omega-e2e.v1"
        git_sha = $env:GITHUB_SHA
        windows_caption = $Os.Caption
        windows_version = $Os.Version
        windows_build = $Os.BuildNumber
        binary_sha256 = $BinarySha256
        endpoint_sha256 = $EndpointHash
        adapter_name = $AdapterName
        adapter_if_index = $AdapterSnapshot.if_index
        adapter_status = $AdapterSnapshot.status
        adapter_mtu_ipv4 = $AdapterSnapshot.mtu_ipv4
        adapter_mtu_ipv6 = $AdapterSnapshot.mtu_ipv6
        client_tun_address = $ClientTunAddress
        server_tun_address = $ServerTunAddress
        client_tun_address_ipv6 = $ClientTunAddress6
        server_tun_address_ipv6 = $ServerTunAddress6
        tls_authenticated = $true
        connected_wfp_policy = $true
        tunnel_ping_attempts = 5
        tunnel_ping_successes = $PingSuccesses
        tunnel_ping_ipv6_attempts = 5
        tunnel_ping_ipv6_successes = $PingSuccesses6
        client_process_exit = "forced"
        stale_cleanup = $true
        adapter_residue = 0
        qkey_log_residue = 0
    } | ConvertTo-Json | Set-Content `
        -LiteralPath (Join-Path $EvidenceDirectory "windows-omega-e2e.json") `
        -Encoding utf8

    Write-Output "Native Windows-to-Omega tunnel proof passed: authenticated=true ipv4=5/5 ipv6=5/5 cleanup=true"
}
finally {
    try {
        if ($null -ne $ClientProcess) {
            $ClientProcess.Refresh()
            if (-not $ClientProcess.HasExited) {
                Stop-Process -Id $ClientProcess.Id -Force -ErrorAction SilentlyContinue
                Wait-Process -Id $ClientProcess.Id -Timeout 15 -ErrorAction SilentlyContinue
            }
        }
        Write-RedactedClientLogs `
            -Paths @($StandardOutputPath, $StandardErrorPath) `
            -DestinationDirectory $EvidenceDirectory `
            -SensitiveValues @($QKey, $Endpoint)
    }
    finally {
        if ($CleanupRequired) {
            Invoke-ExactFirewallCleanup
        }
        Wait-ForAdapterAbsence
        if (Test-Path -LiteralPath $TemporaryRoot) {
            Remove-Item -LiteralPath $TemporaryRoot -Recurse -Force
        }
        $QKey = $null
    }
}
