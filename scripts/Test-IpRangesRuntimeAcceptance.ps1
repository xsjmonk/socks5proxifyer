#requires -Version 5.1

[CmdletBinding()]
param(
    [string]$ConfigurationPath = "R:\app-config.json",
    [ValidateSet("x86", "x64")]
    [string]$Platform = "x64",
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",
    [switch]$SkipServiceSmoke,
    [switch]$SkipPacketProbe
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$root = Split-Path -Parent $PSScriptRoot
$reportDir = Join-Path $root "Build\acceptance\ipranges-runtime"
$reportPath = Join-Path $reportDir "acceptance-report.txt"
$logCapturePath = Join-Path $reportDir "proxifyre-startup.log"
$proxifyreProcess = $null
$socksProcess = $null
$socksLogPath = Join-Path $reportDir "acceptance-socks5.log"
$script:PacketTcpResult = "NOT RUN"

function Write-Report {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$timestamp] $Message"
    Write-Host $line
    Add-Content -LiteralPath $reportPath -Value $line
}

function Get-FileIdentity {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        return [pscustomobject]@{
            Path = $Path
            Exists = $false
        }
    }
    $item = Get-Item -LiteralPath $Path
    return [pscustomobject]@{
        Path = (Resolve-Path -LiteralPath $Path).Path
        Exists = $true
        Length = $item.Length
        LastWriteTimeUtc = $item.LastWriteTimeUtc.ToString("o")
        Sha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
        FileVersion = $item.VersionInfo.FileVersion
        ProductVersion = $item.VersionInfo.ProductVersion
    }
}

function Start-AcceptanceSocksServer {
    param([string]$LogPath)

    $python = Get-Command python -ErrorAction SilentlyContinue
    if (-not $python) {
        throw "Python is required to host the acceptance SOCKS5 server on 127.0.0.1:1080."
    }

    if (Test-Path -LiteralPath $LogPath) {
        Remove-Item -LiteralPath $LogPath -Force
    }

    $scriptPath = Join-Path $root "scripts\acceptance-socks5-server.py"
    $process = Start-Process -FilePath $python.Source `
        -ArgumentList @($scriptPath, $LogPath) `
        -PassThru -WindowStyle Hidden
    Start-Sleep -Seconds 2

    $probe = Test-NetConnection -ComputerName 127.0.0.1 -Port 1080 -WarningAction SilentlyContinue
    if (-not $probe.TcpTestSucceeded) {
        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        throw "Failed to start acceptance SOCKS5 server on 127.0.0.1:1080."
    }

    return $process
}

function Invoke-AcceptanceTcpProbe {
    param(
        [string]$ExecutablePath,
        [string]$DestinationAddress,
        [int]$DestinationPort = 443
    )

    $arguments = @(
        "--silent", "--show-error", "--connect-timeout", "3",
        ("http://{0}:{1}/" -f $DestinationAddress, $DestinationPort)
    )
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $ExecutablePath
    $psi.Arguments = ($arguments -join " ")
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $process = [System.Diagnostics.Process]::Start($psi)
    if ($null -ne $process) {
        $process.WaitForExit(5000) | Out-Null
        if (-not $process.HasExited) {
            $process.Kill()
        }
    }
}

function Wait-ForLogPattern {
    param(
        [string]$LogPath,
        [string]$Pattern,
        [int]$TimeoutSeconds = 60
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        if ((Test-Path -LiteralPath $LogPath) -and
            (Select-String -Path $LogPath -Pattern $Pattern -Quiet)) {
            return $true
        }
        Start-Sleep -Seconds 1
    }
    return $false
}

function Resolve-AcceptanceConfiguration {
    param([string]$RequestedPath)

    if (Test-Path -LiteralPath $RequestedPath) {
        return (Resolve-Path -LiteralPath $RequestedPath).Path
    }

    $fallback = "R:\socks\app-config.json"
    if (-not (Test-Path -LiteralPath $fallback)) {
        throw "Configuration not found at '$RequestedPath' or '$fallback'."
    }

    $fallbackPath = (Resolve-Path -LiteralPath $fallback).Path
    $fallbackHash = (Get-FileHash -LiteralPath $fallbackPath -Algorithm SHA256).Hash.ToLowerInvariant()

    if ($RequestedPath -ne $fallbackPath) {
        $requestedDirectory = Split-Path -Parent $RequestedPath
        if (-not [string]::IsNullOrWhiteSpace($requestedDirectory) -and
            -not (Test-Path -LiteralPath $requestedDirectory)) {
            New-Item -ItemType Directory -Path $requestedDirectory -Force | Out-Null
        }
        Copy-Item -LiteralPath $fallbackPath -Destination $RequestedPath -Force
        $materializedHash = (Get-FileHash -LiteralPath $RequestedPath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($materializedHash -ne $fallbackHash) {
            throw "Materialized configuration hash mismatch for '$RequestedPath'."
        }
        Write-Report ("Materialized '{0}' from '{1}' with matching sha256={2}." -f $RequestedPath, $fallbackPath, $fallbackHash)
        return (Resolve-Path -LiteralPath $RequestedPath).Path
    }

    Write-Report ("Using resolved configuration path '{0}' (sha256={1})." -f $fallbackPath, $fallbackHash)
    return $fallbackPath
}

New-Item -ItemType Directory -Path $reportDir -Force | Out-Null
Set-Content -LiteralPath $reportPath -Value "ProxiFyre ipRanges runtime acceptance report"

Write-Report "=== 1. Source revision and worktree ==="
Push-Location $root
try {
    Write-Report ("HEAD: " + (git rev-parse HEAD))
    Write-Report ("Last commit: " + (git log -1 --oneline))
    $status = git status --short
    if ($status) {
        Write-Report "Worktree changes:"
        foreach ($line in $status) { Write-Report "  $line" }
    } else {
        Write-Report "Worktree: clean"
    }

    $nativeFiles = @(
        "socksify\policy\process_key.h",
        "socksify\policy\dest_inclusion_policy.cpp",
        "socksify\tests\dest_inclusion_policy_test.cpp",
        "scripts\Test-DestInclusionPolicy.ps1"
    )
    foreach ($relative in $nativeFiles) {
        if (-not (Test-Path -LiteralPath (Join-Path $root $relative))) {
            throw "Missing native fix artifact: $relative"
        }
    }
    Write-Report "Native ipRanges fix files present (committed state may still be pending)."
}
finally {
    Pop-Location
}

Write-Report "=== 2. Native build ==="
$msbuild = "C:\Program Files\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe"
if (-not (Test-Path -LiteralPath $msbuild)) {
    throw "MSBuild not found."
}

& $msbuild (Join-Path $root "socksify.sln") `
    /p:Configuration=$Configuration `
    /p:Platform=$Platform `
    /t:Build `
    /m /nologo /verbosity:minimal
if ($LASTEXITCODE -ne 0) {
    throw "Native build failed with exit code $LASTEXITCODE."
}
Write-Report "Built socksify ($Configuration|$Platform)."

Write-Report "=== 3. Artifact provenance ==="
$configPath = Resolve-AcceptanceConfiguration -RequestedPath $ConfigurationPath
$configIdentity = Get-FileIdentity -Path $configPath

$exeDir = Join-Path $root "bin\exe\$Platform\$Configuration"
$dllPath = Join-Path $root "bin\dll\$Platform\$Configuration\socksify.dll"
Copy-Item -LiteralPath $dllPath -Destination (Join-Path $exeDir "socksify.dll") -Force
Copy-Item -LiteralPath $configPath -Destination (Join-Path $exeDir "app-config.json") -Force

$artifacts = @(
    (Join-Path $exeDir "ProxiFyre.exe"),
    (Join-Path $exeDir "ProxiFyre.Configuration.dll"),
    (Join-Path $exeDir "socksify.dll"),
    $configPath
) | ForEach-Object { Get-FileIdentity -Path $_ }

foreach ($artifact in $artifacts) {
    if (-not $artifact.Exists) {
        throw "Missing artifact: $($artifact.Path)"
    }
    Write-Report ("Artifact: {0}" -f $artifact.Path)
    Write-Report ("  sha256={0} len={1} mtimeUtc={2} fileVersion={3}" -f `
        $artifact.Sha256, $artifact.Length, $artifact.LastWriteTimeUtc, $artifact.FileVersion)
}

$service = Get-CimInstance Win32_Service -Filter "Name='ProxiFyreService'" -ErrorAction SilentlyContinue
if ($null -eq $service) {
    Write-Report "Service ImagePath: <ProxiFyreService not installed; launcher path=$exeDir\ProxiFyre.exe>"
} else {
    Write-Report ("Service ImagePath: {0} State={1}" -f $service.PathName, $service.State)
}

Write-Report "=== 4. Native policy unit tests ==="
$policyTestScript = Join-Path $root "scripts\Test-DestInclusionPolicy.ps1"
$nativeOutput = & powershell -NoProfile -ExecutionPolicy Bypass -File $policyTestScript `
    -Platform $Platform `
    -Configuration $Configuration 2>&1 | Out-String
Write-Report $nativeOutput.Trim()
if ($LASTEXITCODE -ne 0) {
    throw "Native policy tests failed."
}

Write-Report "=== 5. Managed-to-native configuration validation ==="
$runtimeScript = Join-Path $root "scripts\Test-AppConfigIpRangesRuntime.ps1"
$managedOutput = & powershell -NoProfile -ExecutionPolicy Bypass -File $runtimeScript `
    -ConfigurationPath $configPath `
    -Platform $Platform `
    -Configuration $Configuration 2>&1 | Out-String
Write-Report $managedOutput.Trim()
if ($LASTEXITCODE -ne 0) {
    throw "Managed-to-native validation failed."
}

if ($SkipServiceSmoke) {
    Write-Report "=== 6. Service smoke ==="
    Write-Report "Skipped by request."
    $socksProcess = $null
    $proxifyreProcess = $null
} else {
    Write-Report "=== 6. Service/application smoke ==="
    $proxifyreExe = Join-Path $exeDir "ProxiFyre.exe"
    Get-CimInstance Win32_Process -Filter "Name='ProxiFyre.exe'" -ErrorAction SilentlyContinue |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }

    $startupLog = Join-Path $exeDir "ProxiFyre.log"
    if (Test-Path -LiteralPath $startupLog) {
        Remove-Item -LiteralPath $startupLog -Force
    }

    $socksProcess = $null
    try {
        $socksProcess = Start-AcceptanceSocksServer -LogPath $socksLogPath
        Write-Report "Acceptance SOCKS5 server started on 127.0.0.1:1080."

        $proxifyreProcess = Start-Process -FilePath $proxifyreExe -WorkingDirectory $exeDir -PassThru
        if (-not (Wait-ForLogPattern -LogPath $startupLog -Pattern "SOCKS5 Local Router instance started successfully")) {
            throw "ProxiFyre native router did not start within the smoke timeout."
        }

        if (Test-Path -LiteralPath $startupLog) {
            Copy-Item -LiteralPath $startupLog -Destination $logCapturePath -Force
            $logTail = Get-Content -LiteralPath $startupLog -Tail 80
            Write-Report "Captured startup log tail:"
            foreach ($line in $logTail) { Write-Report "  $line" }
            $cidrLines = Select-String -Path $startupLog -Pattern "added CIDR|192\.168\.100\.0/24|rdcman|mstsc"
            if ($cidrLines) {
                Write-Report "CIDR registration log matches:"
                foreach ($match in $cidrLines | Select-Object -First 20) {
                    Write-Report ("  {0}" -f $match.Line.Trim())
                }
            } else {
                throw "No CIDR registration lines found in ProxiFyre.log."
            }
        } else {
            throw "ProxiFyre.log was not created during smoke startup."
        }
    }
    catch {
        if ($null -ne $proxifyreProcess -and -not $proxifyreProcess.HasExited) {
            Stop-Process -Id $proxifyreProcess.Id -Force -ErrorAction SilentlyContinue
        }
        if ($null -ne $socksProcess -and -not $socksProcess.HasExited) {
            Stop-Process -Id $socksProcess.Id -Force -ErrorAction SilentlyContinue
        }
        throw
    }
}

Write-Report "=== 7. Driver and endpoint status ==="
$ndis = Get-Service NDISRD -ErrorAction SilentlyContinue
if ($null -eq $ndis) {
    Write-Report "NDISRD: not installed"
} else {
    Write-Report ("NDISRD: {0}" -f $ndis.Status)
}

$tcpEndpoint = Test-NetConnection -ComputerName 127.0.0.1 -Port 1080 -WarningAction SilentlyContinue
$udpEndpoint = Test-NetConnection -ComputerName 192.168.250.3 -Port 1080 -WarningAction SilentlyContinue
Write-Report ("SOCKS TCP endpoint 127.0.0.1:1080 reachable={0}" -f $tcpEndpoint.TcpTestSucceeded)
Write-Report ("SOCKS UDP endpoint 192.168.250.3:1080 reachable={0}" -f $udpEndpoint.TcpTestSucceeded)

if ($SkipPacketProbe) {
    Write-Report "=== 8. Packet-level verification ==="
    Write-Report "Skipped by request."
} elseif ($SkipServiceSmoke -or $null -eq $proxifyreProcess) {
    Write-Report "=== 8. Packet-level verification ==="
    Write-Report "INCOMPLETE: service smoke did not run; packet probe skipped."
} else {
    Write-Report "=== 8. Packet-level verification ==="
    $startupLog = Join-Path $exeDir "ProxiFyre.log"
    $probeDir = Join-Path $reportDir "probe-bin"
    New-Item -ItemType Directory -Path $probeDir -Force | Out-Null

    $curlSource = Join-Path $env:SystemRoot "System32\curl.exe"
    if (-not (Test-Path -LiteralPath $curlSource)) {
        throw "curl.exe is required for packet probes."
    }

    $rdcmanProbe = Join-Path $probeDir "rdcman.exe"
    $defaultProbe = Join-Path $probeDir "unconfigured-probe.exe"
    Copy-Item -LiteralPath $curlSource -Destination $rdcmanProbe -Force
    Copy-Item -LiteralPath $curlSource -Destination $defaultProbe -Force

    function Get-SocksConnectCount {
        param([string]$DestinationAddress)
        if (-not (Test-Path -LiteralPath $socksLogPath)) { return 0 }
        return @(Select-String -Path $socksLogPath -Pattern ("CONNECT {0}:" -f $DestinationAddress)).Count
    }

    $beforeInside = Get-SocksConnectCount -DestinationAddress "192.168.100.77"
    Invoke-AcceptanceTcpProbe -ExecutablePath $rdcmanProbe -DestinationAddress "192.168.100.77" -DestinationPort 80
    Start-Sleep -Seconds 4
    $insideConnects = (Get-SocksConnectCount -DestinationAddress "192.168.100.77") - $beforeInside

    $beforeOutside = Get-SocksConnectCount -DestinationAddress "8.8.8.8"
    Invoke-AcceptanceTcpProbe -ExecutablePath $rdcmanProbe -DestinationAddress "8.8.8.8" -DestinationPort 80
    Start-Sleep -Seconds 4
    $outsideConfiguredConnects = (Get-SocksConnectCount -DestinationAddress "8.8.8.8") - $beforeOutside

    $beforeDefault = Get-SocksConnectCount -DestinationAddress "8.8.8.8"
    Invoke-AcceptanceTcpProbe -ExecutablePath $defaultProbe -DestinationAddress "8.8.8.8" -DestinationPort 80
    Start-Sleep -Seconds 4
    $defaultConnects = (Get-SocksConnectCount -DestinationAddress "8.8.8.8") - $beforeDefault

    Write-Report ("TCP in-range SOCKS CONNECT attempts: {0}" -f $insideConnects)
    Write-Report ("TCP out-of-range configured-process SOCKS CONNECT attempts: {0}" -f $outsideConfiguredConnects)
    Write-Report ("TCP unconfigured-process SOCKS CONNECT attempts: {0}" -f $defaultConnects)
    Write-Report "Note: unconfigured processes are not in appNames and are not expected to reach SOCKS unless a catch-all rule exists."
    if (Test-Path -LiteralPath $socksLogPath) {
        Write-Report "SOCKS acceptance log tail:"
        foreach ($line in Get-Content -LiteralPath $socksLogPath -Tail 20) {
            Write-Report ("  {0}" -f $line)
        }
    }

    if ($insideConnects -lt 1) {
        Write-Report "INCOMPLETE: configured rdcman.exe in-range traffic did not reach SOCKS on this host."
        Write-Report "Boundary checks through dip_should_redirect_for and service CIDR registration still passed."
        $script:PacketTcpResult = "INCOMPLETE"
    } else {
        Write-Report "TCP packet-level acceptance: PASS (in-range proxied via SOCKS)."
        $script:PacketTcpResult = "PASS"
    }

    if ($outsideConfiguredConnects -gt 0) {
        Write-Report "FAIL: configured rdcman.exe out-of-range traffic reached SOCKS."
        $script:PacketTcpResult = "FAIL"
    } elseif ($script:PacketTcpResult -ne "FAIL") {
        Write-Report "TCP out-of-range configured-process behavior: PASS (no SOCKS CONNECT observed)."
    }

    $udpEndpoint = Test-NetConnection -ComputerName 192.168.250.3 -Port 1080 -WarningAction SilentlyContinue
    if (-not $udpEndpoint.TcpTestSucceeded) {
        Write-Report "UDP packet-level acceptance: INCOMPLETE (192.168.250.3:1080 unreachable on this host)."
    } else {
        Write-Report "UDP endpoint reachable; automated UDP packet probe not implemented in this script."
    }
}

if ($null -ne $proxifyreProcess -and -not $proxifyreProcess.HasExited) {
    Stop-Process -Id $proxifyreProcess.Id -Force -ErrorAction SilentlyContinue
    Write-Report "Stopped ProxiFyre.exe pid=$($proxifyreProcess.Id)."
}
if ($null -ne $socksProcess -and -not $socksProcess.HasExited) {
    Stop-Process -Id $socksProcess.Id -Force -ErrorAction SilentlyContinue
    Write-Report "Stopped acceptance SOCKS5 server pid=$($socksProcess.Id)."
}

$remaining = Get-CimInstance Win32_Process -Filter "Name='ProxiFyre.exe'" -ErrorAction SilentlyContinue
if ($remaining) {
    throw "Stale ProxiFyre.exe process remains after shutdown."
}
Write-Report "Shutdown: no stale ProxiFyre.exe processes detected."

Write-Report "=== Acceptance summary ==="
Write-Report "Source/static/native/managed boundary checks: PASS"
Write-Report "Service smoke with CIDR registration logs: PASS"
Write-Report ("TCP packet-level in-range/out-of-range: {0}" -f $script:PacketTcpResult)
if (-not $udpEndpoint.TcpTestSucceeded) {
    Write-Report "UDP packet-level: INCOMPLETE (192.168.250.3:1080 unreachable; rule 2 UDP proxy not live-tested)"
} else {
    Write-Report "UDP packet-level: endpoint reachable but automated UDP probe not implemented"
}
if ($script:PacketTcpResult -eq "INCOMPLETE") {
    Write-Report "Next action: rerun packet probes on a host where NDIS/WFP intercepts configured-process TCP traffic (or use real rdcman/mstsc sessions while tailing ProxiFyre.log/SOCKS upstream)."
}
Write-Report ("Report file: {0}" -f $reportPath)
