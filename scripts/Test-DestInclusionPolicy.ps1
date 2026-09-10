#requires -Version 5.1

[CmdletBinding()]
param(
    [ValidateSet("x86", "x64")]
    [string]$Platform = "x64",
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$root = Split-Path -Parent $PSScriptRoot
$msbuild = "C:\Program Files\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe"
if (-not (Test-Path -LiteralPath $msbuild)) {
    throw "MSBuild not found at $msbuild"
}

$testProject = Join-Path $root "socksify\tests\dest_inclusion_policy_test.vcxproj"
$testExe = Join-Path $root "bin\tests\$Platform\$Configuration\dest_inclusion_policy_test.exe"

Write-Host "[policy-test] Building $testProject ($Configuration|$Platform)"
& $msbuild $testProject /p:Configuration=$Configuration /p:Platform=$Platform /m /nologo /verbosity:minimal
if ($LASTEXITCODE -ne 0) {
    throw "Native policy test build failed with exit code $LASTEXITCODE."
}

Write-Host "[policy-test] Running $testExe"
& $testExe
if ($LASTEXITCODE -ne 0) {
    throw "Native policy test failed with exit code $LASTEXITCODE."
}

Write-Host "[policy-test] PASS"
