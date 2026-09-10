#requires -Version 5.1

[CmdletBinding()]
param(
    [string]$ConfigurationPath = "R:\socks\app-config.json",
    [string]$SocksifyDllPath,
    [ValidateSet("x86", "x64")]
    [string]$Platform = "x64",
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$root = Split-Path -Parent $PSScriptRoot
if (-not (Test-Path -LiteralPath $ConfigurationPath)) {
    throw "Configuration file not found: $ConfigurationPath"
}

if ([string]::IsNullOrWhiteSpace($SocksifyDllPath)) {
    $SocksifyDllPath = Join-Path $root "bin\dll\$Platform\$Configuration\socksify.dll"
}
$SocksifyDllPath = (Resolve-Path -LiteralPath $SocksifyDllPath).Path

$configAssembly = Join-Path $root "bin\exe\$Platform\$Configuration\ProxiFyre.Configuration.dll"
if (-not (Test-Path -LiteralPath $configAssembly)) {
    throw "ProxiFyre.Configuration.dll not found: $configAssembly"
}

$policyTestScript = Join-Path $root "scripts\Test-DestInclusionPolicy.ps1"
if (-not (Test-Path -LiteralPath $policyTestScript)) {
    throw "Native policy test script not found: $policyTestScript"
}

Write-Host "[runtime] Configuration: $ConfigurationPath"
Write-Host "[runtime] socksify.dll: $SocksifyDllPath"

$env:PROXIFYRE_SOCKSIFY_DLL = $SocksifyDllPath

Add-Type -Path $configAssembly
Add-Type -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.Net;
using System.Runtime.InteropServices;
using ProxiFyre.Configuration;

public sealed class AppConfigRuntimeValidationEngine : IProxyEngineBoundary
{
    private readonly List<string> _cidrCalls;
    private readonly IntPtr _handle = new IntPtr(1);

    public AppConfigRuntimeValidationEngine(List<string> cidrCalls)
    {
        _cidrCalls = cidrCalls;
    }

    public IntPtr AddSocks5Proxy(NativeProxyRuleSettings settings) { return _handle; }
    public bool AssociateProcessNameToProxy(string processName, IntPtr handle) { return true; }

    public bool IncludeProcessDestinationCidr(string processName, string cidr)
    {
        _cidrCalls.Add(processName + " -> " + cidr);
        return NativePolicyBridge.AddProcess(processName, cidr);
    }

    public bool ExcludeProcessName(string processName) { return true; }
}

public static class NativePolicyBridge
{
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int DipAddProcessDelegate(
        [MarshalAs(UnmanagedType.LPWStr)] string processName,
        [MarshalAs(UnmanagedType.LPStr)] string cidr);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int DipShouldRedirectDelegate(
        [MarshalAs(UnmanagedType.LPWStr)] string processName,
        IntPtr destination,
        int destinationLength);

    private static readonly DipAddProcessDelegate AddProcessImpl;
    private static readonly DipShouldRedirectDelegate ShouldRedirectImpl;

    static NativePolicyBridge()
    {
        var dllPath = Environment.GetEnvironmentVariable("PROXIFYRE_SOCKSIFY_DLL");
        if (string.IsNullOrWhiteSpace(dllPath))
            throw new InvalidOperationException("PROXIFYRE_SOCKSIFY_DLL is not set.");

        AddProcessImpl = Load<DipAddProcessDelegate>(dllPath, "dip_add_process");
        ShouldRedirectImpl = Load<DipShouldRedirectDelegate>(dllPath, "dip_should_redirect_for");
    }

    public static bool AddProcess(string processName, string cidr)
    {
        return AddProcessImpl(processName, cidr) == 1;
    }

    public static bool ShouldRedirect(string processName, IPAddress destination)
    {
        var bytes = destination.GetAddressBytes();
        if (bytes.Length != 4)
            throw new InvalidOperationException("Only IPv4 destinations are supported.");

        var sockAddr = new byte[16];
        sockAddr[0] = 2; // AF_INET
        sockAddr[1] = 0;
        sockAddr[2] = (byte)((443 >> 8) & 0xFF);
        sockAddr[3] = (byte)(443 & 0xFF);
        Buffer.BlockCopy(bytes, 0, sockAddr, 4, 4);

        var handle = GCHandle.Alloc(sockAddr, GCHandleType.Pinned);
        try
        {
            return ShouldRedirectImpl(processName, handle.AddrOfPinnedObject(), sockAddr.Length) == 1;
        }
        finally
        {
            handle.Free();
        }
    }

    private static T Load<T>(string dllPath, string exportName) where T : class
    {
        var module = NativeMethods.LoadLibrary(dllPath);
        if (module == IntPtr.Zero)
            throw new InvalidOperationException("LoadLibrary failed for " + dllPath);

        var address = NativeMethods.GetProcAddress(module, exportName);
        if (address == IntPtr.Zero)
            throw new InvalidOperationException("Missing export: " + exportName);

        return Marshal.GetDelegateForFunctionPointer<T>(address);
    }
}

internal static class NativeMethods
{
    [DllImport("kernel32", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr LoadLibrary(string lpFileName);

    [DllImport("kernel32", CharSet = CharSet.Ansi, SetLastError = true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
}
"@ -ReferencedAssemblies @($configAssembly) -Language CSharp

$json = [IO.File]::ReadAllText($ConfigurationPath)
$serializer = New-Object ProxiFyre.Configuration.ConfigurationSerializer
$model = $serializer.Deserialize($json)
$validation = (New-Object ProxiFyre.Configuration.ConfigurationValidator).Validate($model)
if (-not $validation.IsValid) {
    throw "Configuration validation failed: $($validation.Issues -join '; ')"
}

$normalized = (New-Object ProxiFyre.Configuration.ConfigurationNormalizer).Normalize($model)
Write-Host "[runtime] Managed validation/normalization: OK"

$managedCidrCalls = New-Object 'System.Collections.Generic.List[string]'
$coordinator = New-Object ProxiFyre.Configuration.ProxyRuleRegistrationCoordinator
$registrationEngine = [AppConfigRuntimeValidationEngine]::new($managedCidrCalls)
$registration = $coordinator.Register($normalized.Proxies, $registrationEngine, $null, $null, $null)
if (-not $registration.AllRequiredRulesRegistered) {
    throw "Managed registration reported failures."
}

Write-Host "[runtime] Managed/native CIDR registrations: $($managedCidrCalls.Count)"
foreach ($entry in $managedCidrCalls) {
    Write-Host "  $entry"
}

$checks = @(
    @{ Process = "rdcman.exe"; Destination = "192.168.100.1"; Expected = $true; Label = "rdcman.exe inside range redirects" },
    @{ Process = "RDCMAN"; Destination = "192.168.100.1"; Expected = $true; Label = "RDCMAN inside range redirects" },
    @{ Process = "C:\Windows\System32\mstsc.exe"; Destination = "192.168.100.50"; Expected = $true; Label = "mstsc path inside range redirects" },
    @{ Process = "rdcman"; Destination = "8.8.8.8"; Expected = $false; Label = "rdcman outside range passes" },
    @{ Process = "mstsc.exe"; Destination = "203.0.113.10"; Expected = $false; Label = "mstsc outside range passes" },
    @{ Process = "unconfigured-runtime-probe"; Destination = "8.8.8.8"; Expected = $true; Label = "unconfigured process default redirect" }
)

$failures = 0
foreach ($check in $checks) {
    $actual = [NativePolicyBridge]::ShouldRedirect($check.Process, [IPAddress]::Parse($check.Destination))
    if ($actual -ne $check.Expected) {
        Write-Host "FAIL: $($check.Label) expected $($check.Expected) got $actual"
        $failures++
    } else {
        Write-Host "PASS: $($check.Label)"
    }
}

Write-Host "[runtime] Running native policy unit tests..."
& powershell -NoProfile -ExecutionPolicy Bypass -File $policyTestScript `
    -Platform $Platform `
    -Configuration $Configuration
if ($LASTEXITCODE -ne 0) {
    throw "Native policy unit tests failed with exit code $LASTEXITCODE."
}

Write-Host "[runtime] TCP/UDP decider seam uses the same dip_should_redirect_for export (verified in native unit tests)."

if ($failures -gt 0) {
    throw "Native runtime policy checks failed: $failures"
}

Write-Host "[runtime] app-config.json -> managed registration -> native policy store -> redirect decision: OK"
