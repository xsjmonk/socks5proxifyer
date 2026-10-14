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

function Test-RepositorySubpath {
    param(
        [string]$RepositoryRoot,
        [string]$CandidatePath
    )

    $rootFull = [IO.Path]::GetFullPath($RepositoryRoot)
    $candidateFull = [IO.Path]::GetFullPath($CandidatePath)
    if ($candidateFull.Equals($rootFull, [StringComparison]::OrdinalIgnoreCase)) {
        return $true
    }

    $prefix = $rootFull + [IO.Path]::DirectorySeparatorChar
    return $candidateFull.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)
}

function Get-SolutionPlatformNames {
    param([string]$SolutionPath)

    $platforms = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($line in Get-Content -LiteralPath $SolutionPath) {
        if ($line -match '^\s*(?:Debug|Release)\|([^=]+)\s*=') {
            $null = $platforms.Add($Matches[1].Trim())
        }
    }

    return @($platforms)
}

function Get-ProjectPlatformDirectoryNames {
    param([string]$SolutionPlatformName)

    if ($SolutionPlatformName -eq "x86") {
        return @("x86", "Win32")
    }

    return @($SolutionPlatformName)
}

function Get-RepositoryObjDirectories {
    param([string]$RepositoryRoot)

    $skipDirectoryNames = [System.Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase,
        @("Build", "Build.staging", "packages", ".git", "vcpkg_installed", "node_modules"))

    $objDirectories = [System.Collections.Generic.List[string]]::new()
    $pending = [System.Collections.Queue]::new()
    $pending.Enqueue([IO.Path]::GetFullPath($RepositoryRoot))

    while ($pending.Count -gt 0) {
        $currentDirectory = [string]$pending.Dequeue()
        foreach ($child in Get-ChildItem -LiteralPath $currentDirectory -Directory -ErrorAction SilentlyContinue) {
            if ($skipDirectoryNames.Contains($child.Name)) {
                continue
            }

            if ($child.Name -eq "obj") {
                $objDirectories.Add($child.FullName)
                continue
            }

            $pending.Enqueue($child.FullName)
        }
    }

    return $objDirectories
}

function Get-IntermediateCleanupTargets {
    param(
        [string]$RepositoryRoot,
        [string]$SolutionPath
    )

    $targets = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $null = $targets.Add((Join-Path $RepositoryRoot "bin"))

    foreach ($objDirectory in Get-RepositoryObjDirectories -RepositoryRoot $RepositoryRoot) {
        $null = $targets.Add($objDirectory)
    }

    $platformNames = Get-SolutionPlatformNames -SolutionPath $SolutionPath
    foreach ($projectDirectory in Get-SolutionProjectDirectories -SolutionPath $SolutionPath) {
        foreach ($platformName in $platformNames) {
            foreach ($directoryName in Get-ProjectPlatformDirectoryNames -SolutionPlatformName $platformName) {
                $null = $targets.Add((Join-Path $projectDirectory $directoryName))
            }
        }
    }

    return @($targets)
}

function Remove-IntermediateBuildOutputs {
    param(
        [string]$RepositoryRoot,
        [string]$SolutionPath
    )

    foreach ($target in Get-IntermediateCleanupTargets -RepositoryRoot $RepositoryRoot -SolutionPath $SolutionPath) {
        if (-not (Test-RepositorySubpath -RepositoryRoot $RepositoryRoot -CandidatePath $target)) {
            throw "Refusing to delete path outside the repository: $target"
        }

        Remove-IfExists $target
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

Write-Info "Deleting PDB and EXP files from Build folder"
Get-ChildItem -Path $stagingDir -Include *.pdb,*.exp -Recurse -File | Remove-Item -Force

Write-Info "Publishing complete artifact set"
Remove-IfExists $buildDir
Move-Item -LiteralPath $stagingDir -Destination $buildDir

Write-Info "Removing intermediate build outputs"
Remove-IntermediateBuildOutputs -RepositoryRoot $root -SolutionPath $solution

Write-Info "Build completed successfully"
Write-Info "Artifacts: $buildDir"
