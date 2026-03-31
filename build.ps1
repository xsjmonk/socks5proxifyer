param(
    [string]$Configuration = "Release",
    [string]$Platform = "x64"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Write-Info {
    param([string]$Message)
    Write-Host "[build] $Message"
}

function Get-MSBuildPath {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vswhere) {
        $installPath = & $vswhere -latest -requires Microsoft.Component.MSBuild -property installationPath
        if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($installPath)) {
            $candidate = Join-Path $installPath "MSBuild\Current\Bin\MSBuild.exe"
            if (Test-Path $candidate) {
                return $candidate
            }
        }
    }

    $command = Get-Command msbuild.exe -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }

    throw "MSBuild.exe was not found. Install Visual Studio or Build Tools with MSBuild."
}

function Invoke-Build {
    param(
        [string]$MSBuildPath,
        [string]$SolutionPath,
        [string]$ConfigurationName,
        [string]$PlatformName
    )

    $arguments = @(
        $SolutionPath
        "/m"
        "/t:Build"
        "/p:Configuration=$ConfigurationName"
        "/p:Platform=$PlatformName"
        "/nologo"
        "/verbosity:minimal"
    )

    & $MSBuildPath @arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Build failed with exit code $LASTEXITCODE."
    }
}

function Copy-DirectoryContents {
    param(
        [string]$SourceDir,
        [string]$DestinationDir
    )

    if (-not (Test-Path $SourceDir)) {
        return
    }

    New-Item -ItemType Directory -Path $DestinationDir -Force | Out-Null
    Copy-Item -Path (Join-Path $SourceDir "*") -Destination $DestinationDir -Recurse -Force
}

function Remove-IfExists {
    param([string]$PathToRemove)

    if (Test-Path $PathToRemove) {
        Remove-Item -Path $PathToRemove -Recurse -Force
    }
}

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$solution = Join-Path $root "socksify.sln"
$buildDir = Join-Path $root "Build"

if (-not (Test-Path $solution)) {
    throw "Solution file not found: $solution"
}

$msbuild = Get-MSBuildPath
Write-Info "Using MSBuild: $msbuild"
Write-Info "Building $solution ($Configuration|$Platform)"

Invoke-Build -MSBuildPath $msbuild -SolutionPath $solution -ConfigurationName $Configuration -PlatformName $Platform

Write-Info "Refreshing Build folder"
Remove-IfExists $buildDir
New-Item -ItemType Directory -Path $buildDir -Force | Out-Null

$outputRoots = @(
    @{ Source = (Join-Path $root "bin\lib\$Platform\$Configuration"); Destination = (Join-Path $buildDir "lib") }
    @{ Source = (Join-Path $root "bin\dll\$Platform\$Configuration"); Destination = (Join-Path $buildDir "dll") }
    @{ Source = (Join-Path $root "bin\exe\$Platform\$Configuration"); Destination = (Join-Path $buildDir "exe") }
)

foreach ($entry in $outputRoots) {
    Copy-DirectoryContents -SourceDir $entry.Source -DestinationDir $entry.Destination
}

Write-Info "Removing intermediate and original output folders"
$cleanupTargets = @(
    (Join-Path $root "bin")
    (Join-Path $root "ProxiFyre\obj")
    (Join-Path $root "ndisapi.lib\$Platform")
    (Join-Path $root "socksify\$Platform")
)

foreach ($target in $cleanupTargets) {
    Remove-IfExists $target
}

Write-Info "Deleting PDB and EXP files from Build folder"
Get-ChildItem -Path $buildDir -Include *.pdb,*.exp -Recurse -File | Remove-Item -Force

Write-Info "Build completed successfully"
Write-Info "Artifacts: $buildDir"
