param(
    [string]$Configuration = "Release",
    [string]$Platform = "x64",
    [string]$ConfigurationPath
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

function Invoke-Restore {
    param(
        [string]$MSBuildPath,
        [string]$SolutionPath
    )

    Write-Info "Restoring NuGet packages required by native projects"
    $arguments = @(
        $SolutionPath
        "/t:Restore"
        "/p:RestoreConfigFile=$(Join-Path $root "NuGet.Installer.Config")"
        "/p:RestoreLockedMode=false"
        "/nologo"
        "/verbosity:minimal"
    )

    & $MSBuildPath @arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Package restore failed with exit code $LASTEXITCODE."
    }

    $nuget = Get-Command nuget.exe -ErrorAction SilentlyContinue
    if (-not $nuget) {
        throw "nuget.exe was not found. Install NuGet to restore packages.config dependencies."
    }

    Write-Info "Restoring packages.config dependencies from the solution"
    & $nuget.Source restore $SolutionPath `
        -ConfigFile (Join-Path $root "NuGet.Installer.Config") `
        -NonInteractive
    if ($LASTEXITCODE -ne 0) {
        throw "packages.config restore failed with exit code $LASTEXITCODE."
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

function Get-PeMachine {
    param([string]$FilePath)

    $stream = [System.IO.File]::OpenRead($FilePath)
    try {
        $reader = [System.IO.BinaryReader]::new($stream)
        if ($stream.Length -lt 64) {
            return ""
        }

        $dosSignature = $reader.ReadUInt16()
        if ($dosSignature -ne 0x5a4d) {
            return ""
        }

        $stream.Position = 0x3c
        $peOffset = $reader.ReadInt32()
        if ($peOffset -lt 0 -or $peOffset + 6 -gt $stream.Length) {
            return ""
        }

        $stream.Position = $peOffset + 4
        if ($reader.ReadUInt32() -ne 0x00004550) {
            return ""
        }

        return ("0x{0:x4}" -f $reader.ReadUInt16())
    }
    finally {
        $stream.Dispose()
    }
}

function Write-ArtifactManifest {
    param(
        [string]$DeploymentDirectory,
        [string]$ConfigurationName,
        [string]$PlatformName
    )

    $required = @(
        @{ Name = "ProxiFyre.exe"; RelativePath = "ProxiFyre.exe" }
        @{ Name = "socksify.dll"; RelativePath = "socksify.dll" }
        @{ Name = "ProxiFyre.Configuration.dll"; RelativePath = "ProxiFyre.Configuration.dll" }
    )
    foreach ($entry in $required) {
        $path = Join-Path $DeploymentDirectory $entry.RelativePath
        if (-not (Test-Path -LiteralPath $path)) {
            throw "The deployment unit is incomplete; missing $($entry.RelativePath)."
        }
    }

    $artifacts = foreach ($file in Get-ChildItem -LiteralPath $DeploymentDirectory -Recurse -File) {
        $relativePath = [IO.Path]::GetRelativePath($DeploymentDirectory, $file.FullName)
        [pscustomobject]@{
            Name = $file.Name
            RelativePath = $relativePath
            Sha256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            Length = $file.Length
            TimestampUtc = $file.LastWriteTimeUtc.ToString("O")
            FileVersion = $file.VersionInfo.FileVersion
            PEMachine = Get-PeMachine -FilePath $file.FullName
        }
    }

    $manifest = [pscustomobject]@{
        Schema = 1
        Configuration = $ConfigurationName
        Platform = $PlatformName
        CreatedUtc = [DateTime]::UtcNow.ToString("O")
        Artifacts = @($artifacts)
    }
    $manifest | ConvertTo-Json -Depth 4 |
        Set-Content -LiteralPath (Join-Path $DeploymentDirectory "artifact-provenance.json") -Encoding UTF8
}

function Remove-IfExists {
    param([string]$PathToRemove)

    if (Test-Path $PathToRemove) {
        Remove-Item -Path $PathToRemove -Recurse -Force
    }
}

function Assert-DirectoryCanBeReplaced {
    param([string]$DirectoryPath)

    if (-not (Test-Path -LiteralPath $DirectoryPath)) {
        return
    }

    $probePath = "$DirectoryPath.publish-probe-$([guid]::NewGuid().ToString('N'))"
    try {
        # A successful rename proves that no running application, antivirus
        # scanner, or other process is holding the artifact tree open. Restore
        # the original name immediately; publication happens only after the
        # complete staged artifact set has been built.
        Move-Item -LiteralPath $DirectoryPath -Destination $probePath -ErrorAction Stop
        Move-Item -LiteralPath $probePath -Destination $DirectoryPath -ErrorAction Stop
    }
    catch {
        if ((Test-Path -LiteralPath $probePath) -and
            -not (Test-Path -LiteralPath $DirectoryPath)) {
            try {
                Move-Item -LiteralPath $probePath -Destination $DirectoryPath -ErrorAction SilentlyContinue
            } catch { }
        }

        throw "Cannot replace '$DirectoryPath'. Stop the running application or release the folder lock, then rerun the build. No deployable artifact set was published. $($_.Exception.Message)"
    }
}

function Get-SolutionProjectDirectories {
    param([string]$SolutionPath)

    $lines = & dotnet sln $SolutionPath list
    if ($LASTEXITCODE -ne 0) {
        throw "Could not read projects from solution: $SolutionPath"
    }

    foreach ($line in $lines) {
        $relativeProjectPath = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($relativeProjectPath) -or
            $relativeProjectPath -eq "Project(s)" -or
            $relativeProjectPath -match "^-+$") {
            continue
        }

        $projectPath = Join-Path (Split-Path -Parent $SolutionPath) $relativeProjectPath
        if (Test-Path $projectPath) {
            Split-Path -Parent $projectPath
        }
    }
}

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$solution = Join-Path $root "socksify.sln"
$buildDir = Join-Path $root "Build"
$stagingDir = Join-Path $root "Build.staging"

if (-not (Test-Path $solution)) {
    throw "Solution file not found: $solution"
}

Assert-DirectoryCanBeReplaced -DirectoryPath $buildDir

$msbuild = Get-MSBuildPath
Write-Info "Using MSBuild: $msbuild"
Write-Info "Building $solution ($Configuration|$Platform)"

Invoke-Restore -MSBuildPath $msbuild -SolutionPath $solution
Invoke-Build -MSBuildPath $msbuild -SolutionPath $solution -ConfigurationName $Configuration -PlatformName $Platform

Write-Info "Refreshing Build folder"
Remove-IfExists $stagingDir
New-Item -ItemType Directory -Path $stagingDir -Force | Out-Null

$outputRoots = @(
    @{ Source = (Join-Path $root "bin\lib\$Platform\$Configuration"); Destination = (Join-Path $stagingDir "lib") }
    @{ Source = (Join-Path $root "bin\dll\$Platform\$Configuration"); Destination = (Join-Path $stagingDir "dll") }
    @{ Source = (Join-Path $root "bin\exe\$Platform\$Configuration"); Destination = (Join-Path $stagingDir "exe") }
)

foreach ($entry in $outputRoots) {
    Copy-DirectoryContents -SourceDir $entry.Source -DestinationDir $entry.Destination
}

Write-Info "Writing artifact provenance manifest"
# Build\exe is the single launch/deployment unit. Keep the diagnostic copy in
# Build\dll for inspection, but never require callers to mix trees manually.
Copy-Item -LiteralPath (Join-Path $stagingDir "dll\socksify.dll") `
    -Destination (Join-Path $stagingDir "exe\socksify.dll") -Force
if (-not [string]::IsNullOrWhiteSpace($ConfigurationPath)) {
    if (-not (Test-Path -LiteralPath $ConfigurationPath -PathType Leaf)) {
        throw "Configuration file not found: $ConfigurationPath"
    }
    Copy-Item -LiteralPath $ConfigurationPath `
        -Destination (Join-Path $stagingDir "exe\app-config.json") -Force
}
Write-ArtifactManifest -DeploymentDirectory (Join-Path $stagingDir "exe") `
    -ConfigurationName $Configuration -PlatformName $Platform

Write-Info "Removing intermediate and original output folders"
$cleanupTargets = [System.Collections.Generic.List[string]]::new()
$cleanupTargets.Add((Join-Path $root "bin"))

foreach ($projectDirectory in Get-SolutionProjectDirectories -SolutionPath $solution) {
    $cleanupTargets.Add((Join-Path $projectDirectory "obj"))
    $cleanupTargets.Add((Join-Path $projectDirectory $Platform))
}

foreach ($target in ($cleanupTargets | Select-Object -Unique)) {
    Remove-IfExists $target
}

Write-Info "Deleting PDB and EXP files from Build folder"
Get-ChildItem -Path $stagingDir -Include *.pdb,*.exp -Recurse -File | Remove-Item -Force

Write-Info "Publishing complete artifact set"
Remove-IfExists $buildDir
Move-Item -LiteralPath $stagingDir -Destination $buildDir

Write-Info "Build completed successfully"
Write-Info "Artifacts: $buildDir"
