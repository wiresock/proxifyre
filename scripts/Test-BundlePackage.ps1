#requires -Version 7.0

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $BundlePath,
    [Parameter(Mandatory = $true)]
    [ValidateSet('x86', 'x64', 'arm64')]
    [string] $Architecture,
    [Parameter(Mandatory = $true)][string] $Version,
    [Parameter(Mandatory = $true)][string] $WindowsPacketFilterFileName,
    [Parameter(Mandatory = $true)][string] $WindowsPacketFilterDownloadUrl,
    [Parameter(Mandatory = $true)][Int64] $WindowsPacketFilterSize,
    [Parameter(Mandatory = $true)][string] $WindowsPacketFilterSha512,
    [Parameter(Mandatory = $true)][string] $WindowsPacketFilterProductCode,
    [Parameter(Mandatory = $true)][string] $VisualCppRedistributableFileName,
    [Parameter(Mandatory = $true)][string] $VisualCppRedistributableDownloadUrl,
    [Parameter(Mandatory = $true)][Int64] $VisualCppRedistributableSize,
    [Parameter(Mandatory = $true)][string] $VisualCppRedistributableSha512,
    [Parameter(Mandatory = $true)]
    [ValidateSet('x86', 'x64', 'arm64')]
    [string] $VisualCppRegistryArchitecture
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$resolvedBundle = (Get-Item -LiteralPath $BundlePath -Force).FullName
$globalPackagesFolder = if ([string]::IsNullOrWhiteSpace($env:NUGET_PACKAGES)) {
    Join-Path ([Environment]::GetFolderPath('UserProfile')) '.nuget\packages'
}
else {
    [IO.Path]::GetFullPath($env:NUGET_PACKAGES)
}
$wixToolsRoot = Join-Path $globalPackagesFolder 'wixtoolset.sdk\6.0.2\tools\net472'
$wixExecutable = @(
    Join-Path $wixToolsRoot 'x64\wix.exe'
    Join-Path $wixToolsRoot 'x86\wix.exe'
) | Where-Object { [IO.File]::Exists($_) } | Select-Object -First 1
if ([string]::IsNullOrWhiteSpace($wixExecutable)) {
    throw "WiX 6.0.2 executable was not found beneath '$wixToolsRoot'. Restore the locked installer packages first."
}

$temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) (
    'ProxiFyre.BundleValidation.' + [Guid]::NewGuid().ToString('N'))
$baDirectory = Join-Path $temporaryRoot 'ba'
$payloadDirectory = Join-Path $temporaryRoot 'payload'
try {
    [IO.Directory]::CreateDirectory($baDirectory) | Out-Null
    [IO.Directory]::CreateDirectory($payloadDirectory) | Out-Null
    & $wixExecutable burn extract -oba $baDirectory -o $payloadDirectory $resolvedBundle |
        Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "WiX could not extract the bundle manifest (exit code $LASTEXITCODE)."
    }

    $manifestPath = Join-Path $baDirectory 'manifest.xml'
    if (-not [IO.File]::Exists($manifestPath)) {
        throw 'The extracted bundle does not contain a Burn manifest.'
    }
    $bootstrapperDataPath = Join-Path $baDirectory 'BootstrapperApplicationData.xml'
    if (-not [IO.File]::Exists($bootstrapperDataPath)) {
        throw 'The extracted bundle does not contain bootstrapper application data.'
    }
    [xml]$manifest = [IO.File]::ReadAllText($manifestPath)
    $namespace = [Xml.XmlNamespaceManager]::new($manifest.NameTable)
    $namespace.AddNamespace('b', 'http://wixtoolset.org/schemas/v4/2008/Burn')
    [xml]$bootstrapperData = [IO.File]::ReadAllText($bootstrapperDataPath)
    $bootstrapperNamespace = [Xml.XmlNamespaceManager]::new(
        $bootstrapperData.NameTable)
    $bootstrapperNamespace.AddNamespace(
        'ba', 'http://wixtoolset.org/schemas/v4/BootstrapperApplicationData')
    $bundleConditions = @($bootstrapperData.SelectNodes(
        '/ba:BootstrapperApplicationData/ba:WixBalCondition',
        $bootstrapperNamespace))
    $bundleProperties = $bootstrapperData.SelectSingleNode(
        '/ba:BootstrapperApplicationData/ba:WixBundleProperties',
        $bootstrapperNamespace)

    $root = $manifest.SelectSingleNode('/b:BurnManifest', $namespace)
    $visualCppPayload = $manifest.SelectSingleNode(
        '/b:BurnManifest/b:Payload[@Id="VisualCppRuntime"]', $namespace)
    $visualCppPackage = $manifest.SelectSingleNode(
        '/b:BurnManifest/b:Chain/b:ExePackage[@Id="VisualCppRuntime"]', $namespace)
    $visualCppCommandLines = @($manifest.SelectNodes(
        '/b:BurnManifest/b:Chain/b:ExePackage[@Id="VisualCppRuntime"]/b:CommandLine',
        $namespace))
    $visualCppInstalledSearch = $manifest.SelectSingleNode(
        '/b:BurnManifest/b:RegistrySearch[@Id="VisualCppRuntimeInstalledSearch"]',
        $namespace)
    $visualCppMajorSearch = $manifest.SelectSingleNode(
        '/b:BurnManifest/b:RegistrySearch[@Id="VisualCppRuntimeMajorSearch"]',
        $namespace)
    $visualCppMinorSearch = $manifest.SelectSingleNode(
        '/b:BurnManifest/b:RegistrySearch[@Id="VisualCppRuntimeMinorSearch"]',
        $namespace)
    $visualCppBuildSearch = $manifest.SelectSingleNode(
        '/b:BurnManifest/b:RegistrySearch[@Id="VisualCppRuntimeBuildSearch"]',
        $namespace)
    $universalCrtSearch = $manifest.SelectSingleNode(
        '/b:BurnManifest/b:FileSearch[@Id="UniversalCrtVersionSearch"]',
        $namespace)
    $visualCppMsvcpSearch = $manifest.SelectSingleNode(
        '/b:BurnManifest/b:FileSearch[@Id="VisualCppMsvcp140VersionSearch"]',
        $namespace)
    $visualCppAtomicWaitSearch = $manifest.SelectSingleNode(
        '/b:BurnManifest/b:FileSearch[@Id="VisualCppAtomicWaitVersionSearch"]',
        $namespace)
    $visualCppVcruntimeSearch = $manifest.SelectSingleNode(
        '/b:BurnManifest/b:FileSearch[@Id="VisualCppVcruntime140VersionSearch"]',
        $namespace)
    $visualCppVcruntime1Search = $manifest.SelectSingleNode(
        '/b:BurnManifest/b:FileSearch[@Id="VisualCppVcruntime1401VersionSearch"]',
        $namespace)
    $wpfPayload = $manifest.SelectSingleNode(
        '/b:BurnManifest/b:Payload[@Id="WindowsPacketFilter"]', $namespace)
    $wpfPackage = $manifest.SelectSingleNode(
        '/b:BurnManifest/b:Chain/b:MsiPackage[@Id="WindowsPacketFilter"]', $namespace)
    $proxifyrePayload = $manifest.SelectSingleNode(
        '/b:BurnManifest/b:Payload[@Id="ProxiFyreMsi"]', $namespace)
    $proxifyrePackage = $manifest.SelectSingleNode(
        '/b:BurnManifest/b:Chain/b:MsiPackage[@Id="ProxiFyreMsi"]', $namespace)
    $proxifyreArpSuppression = $manifest.SelectSingleNode(
        '/b:BurnManifest/b:Chain/b:MsiPackage[@Id="ProxiFyreMsi"]/b:MsiProperty[@Id="ARPSYSTEMCOMPONENT"]',
        $namespace)
    $proxifyreBundleMarkers = @($manifest.SelectNodes(
        '/b:BurnManifest/b:Chain/b:MsiPackage[@Id="ProxiFyreMsi"]/b:MsiProperty[@Id="PROXIFYRE_SETUP_CHAIN"]',
        $namespace))
    $proxifyreBundleMarker = if ($proxifyreBundleMarkers.Count -eq 1) {
        $proxifyreBundleMarkers[0]
    }
    else { $null }
    $driverSearch = $manifest.SelectSingleNode(
        '/b:BurnManifest/b:FileSearch[@Id="WindowsPacketFilterDriverVersionSearch"]',
        $namespace)
    $serviceSearch = $manifest.SelectSingleNode(
        '/b:BurnManifest/b:RegistrySearch[@Id="WindowsPacketFilterServiceSearch"]',
        $namespace)

    foreach ($requiredNode in @($root, $visualCppPayload, $visualCppPackage,
            $visualCppInstalledSearch, $visualCppMajorSearch, $visualCppMinorSearch,
            $visualCppBuildSearch, $universalCrtSearch, $visualCppMsvcpSearch,
            $visualCppAtomicWaitSearch, $visualCppVcruntimeSearch,
            $visualCppVcruntime1Search, $wpfPayload, $wpfPackage, $proxifyrePayload,
            $proxifyrePackage, $proxifyreArpSuppression, $proxifyreBundleMarker,
            $driverSearch, $serviceSearch, $bundleProperties)) {
        if ($null -eq $requiredNode) {
            throw 'The bundle is missing required prerequisite, application, or detection authoring.'
        }
    }

    $expectedWin64 = $Architecture -ne 'x86'
    $actualWin64 = [string]$root.GetAttribute('Win64') -eq 'yes'
    if ($actualWin64 -ne $expectedWin64) {
        throw "Bundle engine architecture does not match $Architecture."
    }
    if ($bundleProperties.GetAttribute('DisplayName') -cne 'ProxiFyre') {
        throw 'The bundle display name must avoid the duplicated "Setup Setup" WixStdBA title.'
    }
    $expectedNativeArchitectureCondition = switch ($Architecture) {
        'x86' { '(NOT VersionNT64 AND NOT NativeMachine) OR NativeMachine = 332' }
        'x64' { '(VersionNT64 AND NOT NativeMachine) OR NativeMachine = 34404' }
        'arm64' { 'NativeMachine = 43620' }
    }
    $expectedSetupArchitectureLabel = if ($Architecture -eq 'arm64') {
        'ARM64'
    }
    else { $Architecture }
    $expectedWindowsArchitectureLabel = if ($Architecture -eq 'x86') {
        '32-bit'
    }
    else { $expectedSetupArchitectureLabel }
    $nativeArchitectureConditions = @($bundleConditions | Where-Object {
        $_.GetAttribute('Condition') -ceq $expectedNativeArchitectureCondition
    })
    if ($nativeArchitectureConditions.Count -ne 1 -or
        $nativeArchitectureConditions[0].GetAttribute('Message') -cne
            "This ProxiFyre $expectedSetupArchitectureLabel setup requires $expectedWindowsArchitectureLabel Windows. Download the setup that matches the native Windows architecture.") {
        throw 'The bundle must reject a native Windows architecture that does not match its WPF driver package.'
    }
    $minimumWindowsConditions = @($bundleConditions | Where-Object {
        $_.GetAttribute('Condition') -ceq
            'VersionNT > v6.1 OR (VersionNT = v6.1 AND ServicePackLevel >= 1)'
    })
    if ($bundleConditions.Count -ne 2 -or
        $minimumWindowsConditions.Count -ne 1 -or
        $minimumWindowsConditions[0].GetAttribute('Message') -cne
            'ProxiFyre requires Windows 7 SP1 or later. On Windows 7, install current servicing-stack and SHA-2 support updates, reboot, and run setup again.') {
        throw 'The bundle must reject Windows 7 RTM before acquiring prerequisites.'
    }
    if ($visualCppPayload.GetAttribute('FilePath') -cne
            $VisualCppRedistributableFileName -or
        $visualCppPayload.GetAttribute('DownloadUrl') -cne
            $VisualCppRedistributableDownloadUrl -or
        [Int64]$visualCppPayload.GetAttribute('FileSize') -ne
            $VisualCppRedistributableSize -or
        $visualCppPayload.GetAttribute('Hash') -cne
            $VisualCppRedistributableSha512.ToUpperInvariant() -or
        $visualCppPayload.GetAttribute('Packaging') -cne 'external') {
        throw 'The Visual C++ remote payload metadata differs from the pinned Microsoft asset.'
    }
    $expectedVisualCppCondition =
        'UniversalCrtVersion >= v10.0.10240.0 AND VisualCppMsvcp140Version >= v14.44.35211.0 AND VisualCppAtomicWaitVersion >= v14.44.35211.0 AND VisualCppVcruntime140Version >= v14.44.35211.0'
    if ($Architecture -eq 'x64') {
        $expectedVisualCppCondition +=
            ' AND VisualCppVcruntime1401Version >= v14.44.35211.0'
    }
    $expectedVisualCppRegistrationCondition =
        'VisualCppRuntimeInstalled = 1 AND (VisualCppRuntimeMajor > 14 OR (VisualCppRuntimeMajor = 14 AND (VisualCppRuntimeMinor > 44 OR (VisualCppRuntimeMinor = 44 AND VisualCppRuntimeBuild >= 35211))))'
    if ($visualCppPackage.GetAttribute('Permanent') -cne 'yes' -or
        $visualCppPackage.GetAttribute('Vital') -cne 'yes' -or
        $visualCppPackage.GetAttribute('PerMachine') -cne 'yes' -or
        $visualCppPackage.GetAttribute('Protocol') -cne 'burn' -or
        $visualCppPackage.GetAttribute('Bundle') -cne 'yes' -or
        $visualCppPackage.GetAttribute('InstallArguments') -cne '/quiet' -or
        $visualCppPackage.GetAttribute('DetectCondition') -cne
            $expectedVisualCppCondition) {
        throw 'The Visual C++ package lifecycle or detection metadata changed unexpectedly.'
    }
    $expectedVisualCppCommandLines = @{
        '/repair' = $expectedVisualCppRegistrationCondition
        '/install' = "NOT ($expectedVisualCppRegistrationCondition)"
    }
    if ($visualCppCommandLines.Count -ne $expectedVisualCppCommandLines.Count) {
        throw 'The Visual C++ runtime repair/install command-line selection changed unexpectedly.'
    }
    $seenVisualCppCommandLines = @{}
    foreach ($commandLine in $visualCppCommandLines) {
        $argument = $commandLine.GetAttribute('InstallArgument')
        if (-not $expectedVisualCppCommandLines.ContainsKey($argument) -or
            $seenVisualCppCommandLines.ContainsKey($argument) -or
            $commandLine.GetAttribute('Condition') -cne
                $expectedVisualCppCommandLines[$argument]) {
            throw 'The Visual C++ runtime repair/install command-line selection changed unexpectedly.'
        }
        $seenVisualCppCommandLines[$argument] = $true
    }
    $expectedSearchKey =
        "SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\$VisualCppRegistryArchitecture"
    $visualCppSearches = @(
        @($visualCppInstalledSearch, 'Installed', 'VisualCppRuntimeInstalled'),
        @($visualCppMajorSearch, 'Major', 'VisualCppRuntimeMajor'),
        @($visualCppMinorSearch, 'Minor', 'VisualCppRuntimeMinor'),
        @($visualCppBuildSearch, 'Bld', 'VisualCppRuntimeBuild')
    )
    foreach ($searchExpectation in $visualCppSearches) {
        $search = $searchExpectation[0]
        if ($search.GetAttribute('Root') -cne 'HKLM' -or
            $search.GetAttribute('Key') -cne $expectedSearchKey -or
            $search.GetAttribute('Value') -cne $searchExpectation[1] -or
            $search.GetAttribute('Variable') -cne $searchExpectation[2] -or
            $search.GetAttribute('Type') -cne 'value' -or
            -not [string]::IsNullOrEmpty($search.GetAttribute('Win64'))) {
            throw 'The Visual C++ runtime registry detection searches changed unexpectedly.'
        }
    }
    if ($universalCrtSearch.GetAttribute('Path') -cne
            '[WindowsFolder]System32\ucrtbase.dll' -or
        $universalCrtSearch.GetAttribute('Variable') -cne 'UniversalCrtVersion' -or
        $universalCrtSearch.GetAttribute('Type') -cne 'version' -or
        $universalCrtSearch.GetAttribute('DisableFileRedirection') -cne 'yes') {
        throw 'The Visual C++ Universal CRT detection search changed unexpectedly.'
    }
    $visualCppFileSearches = @(
        @($visualCppMsvcpSearch, 'msvcp140.dll', 'VisualCppMsvcp140Version'),
        @($visualCppAtomicWaitSearch, 'msvcp140_atomic_wait.dll',
            'VisualCppAtomicWaitVersion'),
        @($visualCppVcruntimeSearch, 'vcruntime140.dll',
            'VisualCppVcruntime140Version'),
        @($visualCppVcruntime1Search, 'vcruntime140_1.dll',
            'VisualCppVcruntime1401Version')
    )
    foreach ($searchExpectation in $visualCppFileSearches) {
        $search = $searchExpectation[0]
        if ($search.GetAttribute('Path') -cne
                "[WindowsFolder]System32\$($searchExpectation[1])" -or
            $search.GetAttribute('Variable') -cne $searchExpectation[2] -or
            $search.GetAttribute('Type') -cne 'version' -or
            $search.GetAttribute('DisableFileRedirection') -cne 'yes') {
            throw 'The Visual C++ native runtime file searches changed unexpectedly.'
        }
    }
    if ($wpfPayload.GetAttribute('FilePath') -cne $WindowsPacketFilterFileName -or
        $wpfPayload.GetAttribute('DownloadUrl') -cne $WindowsPacketFilterDownloadUrl -or
        [Int64]$wpfPayload.GetAttribute('FileSize') -ne $WindowsPacketFilterSize -or
        $wpfPayload.GetAttribute('Hash') -cne $WindowsPacketFilterSha512.ToUpperInvariant() -or
        $wpfPayload.GetAttribute('Packaging') -cne 'external') {
        throw 'The WPF remote payload metadata differs from the pinned official asset.'
    }
    if ($wpfPackage.GetAttribute('ProductCode') -cne $WindowsPacketFilterProductCode -or
        $wpfPackage.GetAttribute('Version') -cne '3.6.2.1' -or
        $wpfPackage.GetAttribute('Permanent') -cne 'yes' -or
        $wpfPackage.GetAttribute('Vital') -cne 'yes' -or
        $wpfPackage.GetAttribute('InstallCondition') -cne
            'NOT (WindowsPacketFilterServiceImagePath AND WindowsPacketFilterDriverVersion >= v3.6.1.0 AND WindowsPacketFilterDriverVersion < v4.0.0.0)') {
        throw 'The WPF package lifecycle or compatibility condition changed unexpectedly.'
    }
    if ($proxifyrePayload.GetAttribute('Packaging') -cne 'embedded' -or
        $proxifyrePackage.GetAttribute('Version') -cne $Version -or
        $proxifyrePackage.GetAttribute('Permanent') -cne 'no' -or
        $proxifyrePackage.GetAttribute('Vital') -cne 'yes' -or
        $proxifyreArpSuppression.GetAttribute('Value') -cne '1' -or
        $proxifyreBundleMarkers.Count -ne 1 -or
        $proxifyreBundleMarker.GetAttribute('Value') -cne '1' -or
        -not [string]::IsNullOrEmpty($proxifyreBundleMarker.GetAttribute('Condition'))) {
        throw 'The embedded ProxiFyre MSI lifecycle metadata changed unexpectedly.'
    }
    $chainIds = @($manifest.SelectNodes(
        '/b:BurnManifest/b:Chain/*[self::b:ExePackage or self::b:MsiPackage]',
        $namespace) | ForEach-Object { $_.GetAttribute('Id') })
    if ($chainIds.Count -ne 3 -or
        $chainIds[0] -cne 'VisualCppRuntime' -or
        $chainIds[1] -cne 'WindowsPacketFilter' -or
        $chainIds[2] -cne 'ProxiFyreMsi') {
        throw "The prerequisite/application chain order changed: $($chainIds -join ', ')."
    }
    $exitCodes = @($visualCppPackage.SelectNodes('b:ExitCode', $namespace))
    $expectedExitCodes = @{
        '0' = '1'
        '1641' = '4'
        '3010' = '5'
        '*' = '2'
    }
    if ($exitCodes.Count -ne $expectedExitCodes.Count) {
        throw 'The Visual C++ runtime exit-code mapping changed unexpectedly.'
    }
    foreach ($exitCode in $exitCodes) {
        $value = $exitCode.GetAttribute('Code')
        if (-not $expectedExitCodes.ContainsKey($value) -or
            $exitCode.GetAttribute('Type') -cne $expectedExitCodes[$value]) {
            throw 'The Visual C++ runtime exit-code mapping changed unexpectedly.'
        }
    }
    if ($driverSearch.GetAttribute('Path') -cne
            '[WindowsFolder]System32\drivers\ndisrd.sys' -or
        $driverSearch.GetAttribute('Type') -cne 'version' -or
        $driverSearch.GetAttribute('DisableFileRedirection') -cne 'yes' -or
        $serviceSearch.GetAttribute('Root') -cne 'HKLM' -or
        $serviceSearch.GetAttribute('Key') -cne
            'SYSTEM\CurrentControlSet\Services\NDISRD') {
        throw 'The WPF service/driver detection searches changed unexpectedly.'
    }
}
finally {
    if ([IO.Directory]::Exists($temporaryRoot)) {
        $resolvedTemporaryRoot = [IO.Path]::GetFullPath($temporaryRoot)
        $normalizedTempRoot = [IO.Path]::GetFullPath(
            [IO.Path]::GetTempPath()).TrimEnd('\', '/') + '\'
        $temporaryItem = Get-Item -LiteralPath $resolvedTemporaryRoot -Force
        if (-not $resolvedTemporaryRoot.StartsWith(
                $normalizedTempRoot, [StringComparison]::OrdinalIgnoreCase) -or
            -not (Split-Path -Leaf $resolvedTemporaryRoot).StartsWith(
                'ProxiFyre.BundleValidation.', [StringComparison]::Ordinal) -or
            ($temporaryItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Refusing to recursively clean unsafe validation path '$resolvedTemporaryRoot'."
        }
        [IO.Directory]::Delete($resolvedTemporaryRoot, $true)
    }
}

Write-Output "Validated ProxiFyre $Version $Architecture Burn prerequisites and package metadata."
