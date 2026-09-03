[CmdletBinding()]
param(
    [string]$RepoRoot = (Join-Path $PSScriptRoot "..")
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path -LiteralPath $RepoRoot).Path
$failures = [System.Collections.Generic.List[string]]::new()

function Fail([string]$Message) {
    $failures.Add($Message)
    Write-Host "[FAIL] $Message" -ForegroundColor Red
}

function Pass([string]$Message) {
    Write-Host "[PASS] $Message" -ForegroundColor Green
}

$excludedDirectories = '\\(\.git|bin|obj|Build|packages)(\\|$)'
$sourceFiles = Get-ChildItem -LiteralPath $root -Recurse -File |
    Where-Object {
        $_.FullName -notmatch $excludedDirectories -and
        @(".cs", ".csproj", ".h", ".hpp", ".cpp", ".md", ".mdc", ".ps1", ".xml") -contains $_.Extension
    }

# Conflict markers are assembled to keep this checker from matching its own source.
$markerPattern = '^\s*(' + ("<" * 7) + "|" + ("=" * 7) + "|" + (">" * 7) + ')\s*$'
$markerFiles = @(
    $sourceFiles | Where-Object {
        Select-String -LiteralPath $_.FullName -Pattern $markerPattern -Quiet
    }
)
if ($markerFiles.Count -gt 0) {
    $markerFiles | ForEach-Object { Fail "Conflict marker found in $($_.FullName.Substring($root.Length + 1))" }
} else {
    Pass "No conflict markers"
}

$projectFiles = Get-ChildItem -LiteralPath $root -Recurse -Filter "*.csproj" -File |
    Where-Object { $_.FullName -notmatch $excludedDirectories }
foreach ($project in $projectFiles) {
    try {
        [xml]$xml = Get-Content -LiteralPath $project.FullName -Raw
    } catch {
        Fail "Cannot parse project file $($project.FullName.Substring($root.Length + 1)): $($_.Exception.Message)"
        continue
    }

    $compileIncludes = @($xml.Project.ItemGroup.Compile | ForEach-Object {
        [string]$_.Include
    } | Where-Object { $_ })
    $duplicates = $compileIncludes | Group-Object { $_.ToLowerInvariant() } |
        Where-Object Count -gt 1
    foreach ($duplicate in $duplicates) {
        Fail "Duplicate Compile Include '$($duplicate.Group[0])' in $($project.Name)"
    }

    foreach ($reference in @($xml.Project.ItemGroup.ProjectReference | ForEach-Object {
        [string]$_.Include
    } | Where-Object { $_ })) {
        if ($reference.Contains("%")) { continue }
        $referencePath = Join-Path $project.DirectoryName $reference
        if (-not (Test-Path -LiteralPath $referencePath)) {
            Fail "Stale ProjectReference '$reference' in $($project.Name)"
        }
    }

    foreach ($include in $compileIncludes) {
        if ($include.Contains("%") -or $include.Contains("*")) { continue }
        $includePath = Join-Path $project.DirectoryName $include
        if (-not (Test-Path -LiteralPath $includePath)) {
            Fail "Stale Compile Include '$include' in $($project.Name)"
        }
    }
}
if ($failures.Count -eq 0) { Pass "Project includes and references are consistent" }

$proxiFyreDirectory = Join-Path $root "ProxiFyre"
$proxiFyreSources = @(Get-ChildItem -LiteralPath $proxiFyreDirectory -Filter "*.cs" -File)
$typeMatches = @(
    $proxiFyreSources | Select-String -Pattern '\bclass\s+(Program|ProxiFyreService)\b'
)
foreach ($typeGroup in $typeMatches | Group-Object { $_.Matches[0].Groups[1].Value }) {
    if ($typeGroup.Count -gt 1) {
        Fail "Duplicate $($typeGroup.Name) type definition in ProxiFyre"
    }
}

$mainMatches = @(
    $proxiFyreSources | Select-String -Pattern '\bstatic\s+(?:int|void)\s+Main\s*\('
)
if ($mainMatches.Count -ne 1) {
    Fail "Expected exactly one ProxiFyre entry point; found $($mainMatches.Count)"
} else {
    Pass "Exactly one ProxiFyre entry point"
}

$serviceFile = Join-Path $proxiFyreDirectory "ProxiFyreService.cs"
$serviceText = if (Test-Path -LiteralPath $serviceFile) {
    Get-Content -LiteralPath $serviceFile -Raw
} else {
    ""
}
if ($serviceText -notmatch 'AddSocks5Proxy' -or
    $serviceText -notmatch 'handle\s*==\s*IntPtr\.Zero' -or
    $serviceText -notmatch 'continue;') {
    Fail "ProxiFyreService does not visibly guard native proxy handles before association"
} else {
    Pass "Native proxy handles are guarded before association"
}

$gitStatus = @(& git -c "safe.directory=*" status --short --untracked-files=all 2>$null)
if ($LASTEXITCODE -ne 0) {
    Fail "Unable to inspect git status for generated output"
}
foreach ($statusLine in @($gitStatus)) {
    if ($statusLine.Length -lt 4) { continue }
    $path = $statusLine.Substring(3)
    if ($path -match '(^|[\\/])(bin|obj|Build)([\\/]|$)') {
        Fail "Generated output is present in the worktree: $path"
    }
}
if ($failures.Count -eq 0) { Pass "No generated output changes detected" }

if ($failures.Count -gt 0) {
    Write-Host "$($failures.Count) merge-maintenance check(s) failed." -ForegroundColor Red
    exit 1
}

Write-Host "Merge-maintenance checks passed." -ForegroundColor Green
exit 0
