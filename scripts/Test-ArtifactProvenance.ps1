[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$DeploymentDirectory,
    [ValidateSet("x86", "x64", "ARM64")]
    [string]$Platform = "x64",
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",
    [string]$ConfigurationPath
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path -LiteralPath $DeploymentDirectory).Path
$manifestPath = Join-Path $root "artifact-provenance.json"
if (-not (Test-Path -LiteralPath $manifestPath)) {
    throw "Missing artifact-provenance.json in $root."
}

function Get-PeMachine {
    param([string]$Path)
    $stream = [IO.File]::OpenRead($Path)
    try {
        $reader = [IO.BinaryReader]::new($stream)
        $stream.Position = 0x3c
        $peOffset = $reader.ReadInt32()
        $stream.Position = $peOffset + 4
        return ("0x{0:x4}" -f $reader.ReadUInt16())
    }
    finally {
        $stream.Dispose()
    }
}

$expectedMachine = @{
    x86 = "0x014c"
    x64 = "0x8664"
    ARM64 = "0xaa64"
}[$Platform]
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if ($manifest.Configuration -ne $Configuration -or $manifest.Platform -ne $Platform) {
    throw "Manifest identity does not match requested $Configuration/$Platform."
}

$required = @(
    @{ Name = "ProxiFyre.exe"; RelativePath = "ProxiFyre.exe" }
    @{ Name = "socksify.dll"; RelativePath = "socksify.dll" }
    @{ Name = "ProxiFyre.Configuration.dll"; RelativePath = "ProxiFyre.Configuration.dll" }
)
$records = @{}
foreach ($record in $manifest.Artifacts) {
    $records[$record.RelativePath] = $record
}
$manifestFiles = @{}
foreach ($record in $manifest.Artifacts) {
    $manifestPathValue = Join-Path $root $record.RelativePath
    if (-not (Test-Path -LiteralPath $manifestPathValue -PathType Leaf)) {
        throw "Manifest artifact is missing from the deployment: $($record.RelativePath)."
    }
    $manifestFiles[$record.RelativePath] =
        (Get-FileHash -LiteralPath $manifestPathValue -Algorithm SHA256).Hash.ToLowerInvariant()
}
$versions = [System.Collections.Generic.HashSet[string]]::new()
foreach ($entry in $required) {
    $path = Join-Path $root $entry.RelativePath
    if (-not (Test-Path -LiteralPath $path)) {
        throw "Missing required artifact: $($entry.RelativePath)."
    }

    $file = Get-Item -LiteralPath $path
    $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    $record = $records[$entry.RelativePath]
    if ($null -eq $record -or $record.Sha256 -ne $hash) {
        throw "Artifact hash differs from the provenance manifest: $($entry.RelativePath)."
    }
    if ((Get-PeMachine $path) -ne $expectedMachine) {
        throw "Artifact architecture differs from ${Platform}: $($entry.RelativePath)."
    }
    if (-not [string]::IsNullOrWhiteSpace($file.VersionInfo.FileVersion)) {
        [void]$versions.Add($file.VersionInfo.FileVersion)
    }
}

if ($versions.Count -gt 1) {
    throw "Managed/native artifact file versions do not match: $($versions -join ', ')."
}

if (-not [string]::IsNullOrWhiteSpace($ConfigurationPath)) {
    if (-not (Test-Path -LiteralPath $ConfigurationPath -PathType Leaf)) {
        throw "The selected configuration does not exist: $ConfigurationPath."
    }
    $expectedConfiguration = (Resolve-Path (Join-Path $root "app-config.json")).Path
    if ((Resolve-Path $ConfigurationPath).Path -ne $expectedConfiguration) {
        throw "The selected configuration is outside the verified artifact directory."
    }
    $configurationHash = (Get-FileHash -LiteralPath $expectedConfiguration -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($manifestFiles["app-config.json"] -ne $configurationHash) {
        throw "The selected configuration does not match the deployment manifest."
    }
}

$exeBytes = [IO.File]::ReadAllBytes((Join-Path $root "ProxiFyre.exe"))
$exeText = [Text.Encoding]::ASCII.GetString($exeBytes)
$exeUnicodeText = [Text.Encoding]::Unicode.GetString($exeBytes)
if ($exeText -notlike "*Required SOCKS5 proxy registration failed*" -and
    $exeUnicodeText -notlike "*Required SOCKS5 proxy registration failed*") {
    throw "ProxiFyre.exe does not contain the current required-failure guard."
}
if (($exeText -notlike "*Proxy rule*native proxy creation failed*") -and
    ($exeUnicodeText -notlike "*Proxy rule*native proxy creation failed*")) {
    throw "ProxiFyre.exe does not contain the current rule failure diagnostic."
}

Write-Host "Artifact provenance passed: $root ($Configuration/$Platform)"
Write-Host ("ArtifactProvenance path={0}; executable={1}; nativeDll={2}; configuration={3}." -f
    $root,
    (Join-Path $root "ProxiFyre.exe"),
    (Join-Path $root "socksify.dll"),
    (Join-Path $root "app-config.json"))
