[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$DeploymentDirectory,
    [Parameter(Mandatory = $true)]
    [ValidateSet("x86", "x64", "ARM64")]
    [string]$Platform,
    [Parameter(Mandatory = $true)]
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",
    [Parameter(Mandatory = $true)]
    [string]$ConfigurationPath,
    [string]$UiSelectedEnginePath
)

$ErrorActionPreference = "Stop"
$artifactDirectory = (Resolve-Path $DeploymentDirectory).Path
$executable = Join-Path $artifactDirectory "ProxiFyre.exe"

& (Join-Path $PSScriptRoot "Test-ArtifactProvenance.ps1") `
    -DeploymentDirectory $artifactDirectory `
    -Platform $Platform -Configuration $Configuration `
    -ConfigurationPath $ConfigurationPath

if (-not [string]::IsNullOrWhiteSpace($UiSelectedEnginePath) -and
    (Resolve-Path $UiSelectedEnginePath).Path -ne (Resolve-Path $executable).Path) {
    throw "The UI-selected engine path does not match the verified executable: $UiSelectedEnginePath"
}

$service = Get-CimInstance Win32_Service -Filter "Name='ProxiFyreService'" `
    -ErrorAction SilentlyContinue
if ($null -ne $service -and -not [string]::IsNullOrWhiteSpace($service.PathName)) {
    $registered = [Environment]::ExpandEnvironmentVariables($service.PathName).Trim()
    if ($registered.StartsWith('"')) {
        $registered = $registered.Substring(1, $registered.IndexOf('"', 1) - 1)
    } else {
        $registered = $registered.Split(' ')[0]
    }
    if (-not (Test-Path -LiteralPath $registered) -or
        (Resolve-Path $registered).Path -ne (Resolve-Path $executable).Path) {
        throw "ProxiFyreService points outside the selected artifact directory: $registered"
    }
}

if ($null -ne $service -and $service.State -ne "Stopped") {
    Stop-Service -Name ProxiFyreService -Force -ErrorAction Stop
}

Get-CimInstance Win32_Process -Filter "Name='ProxiFyre.exe'" |
    Where-Object { $_.ExecutablePath } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction Stop }

Start-Process -FilePath $executable -WorkingDirectory $artifactDirectory
Start-Sleep -Seconds 1
$targetPath = (Resolve-Path $executable).Path
$process = Get-CimInstance Win32_Process -Filter "Name='ProxiFyre.exe'" |
    Where-Object { $_.ExecutablePath -eq $targetPath } |
    Select-Object -First 1
if ($null -eq $process) {
    throw "The verified executable did not remain running: $targetPath"
}
Write-Host "Launched verified ProxiFyre artifact: path=$targetPath pid=$($process.ProcessId)"
