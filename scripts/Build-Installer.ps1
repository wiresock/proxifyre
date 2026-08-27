#requires -Version 7.0

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('x86', 'x64', 'ARM64', 'arm64')]
    [string] $Platform,

    [Parameter(Mandatory = $true)]
    [string] $Version,

    [string] $PayloadDirectory,
    [string] $OutputDirectory,
    [string] $BootstrapperFunctionsPath,
    [string] $BootstrapperExtensionPath,
    [string] $WindowsPacketFilterMsiPath,
    [string] $VisualCppRedistributablePath,
    [switch] $NoRestore,
    [switch] $Force
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$installerProject = Join-Path $repositoryRoot 'ProxiFyre.Installer\ProxiFyre.Installer.wixproj'
$bundleProject = Join-Path $repositoryRoot 'ProxiFyre.Bundle\ProxiFyre.Bundle.wixproj'
$normalizedArchitecture = $Platform.ToLowerInvariant()
if ($normalizedArchitecture -eq 'arm64') { $dotnetPlatform = 'ARM64' }
else { $dotnetPlatform = $normalizedArchitecture }

if ([string]::IsNullOrWhiteSpace($PayloadDirectory)) {
    $PayloadDirectory = Join-Path $repositoryRoot "bin\exe\$dotnetPlatform\Release"
}
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $repositoryRoot "bin\installer\$dotnetPlatform\Release"
}

$versionMatch = [regex]::Match($Version, '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$')
if (-not $versionMatch.Success) {
    throw "Version '$Version' must be a canonical three-part Windows Installer version."
}
if ([int]$versionMatch.Groups[1].Value -gt 255 -or
    [int]$versionMatch.Groups[2].Value -gt 255 -or
    [int]$versionMatch.Groups[3].Value -gt 65535) {
    throw "Version '$Version' exceeds Windows Installer limits (255.255.65535)."
}

$payloadPath = [IO.Path]::GetFullPath($PayloadDirectory)
$outputPath = [IO.Path]::GetFullPath($OutputDirectory)
if (-not [IO.Directory]::Exists($payloadPath)) {
    throw "Payload directory '$payloadPath' does not exist."
}
$payloadRoot = Get-Item -LiteralPath $payloadPath -Force
if (($payloadRoot.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "Payload directory '$payloadPath' must not be a reparse point."
}
if ([string]::IsNullOrWhiteSpace($BootstrapperFunctionsPath)) {
    $payloadConfiguration = Split-Path -Leaf $payloadPath
    $BootstrapperFunctionsPath = Join-Path $repositoryRoot (
        "bin\setup\$dotnetPlatform\$payloadConfiguration\ProxiFyreSetup.BAFunctions.dll")
}
$bootstrapperFunctions = [IO.Path]::GetFullPath($BootstrapperFunctionsPath)
if (-not [IO.File]::Exists($bootstrapperFunctions)) {
    throw "Setup BAFunctions DLL '$bootstrapperFunctions' does not exist. Build ProxiFyreSetupBootstrapper for $dotnetPlatform first or pass -BootstrapperFunctionsPath."
}
$bootstrapperFunctionsItem = Get-Item -LiteralPath $bootstrapperFunctions -Force
if (($bootstrapperFunctionsItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "Setup BAFunctions DLL '$bootstrapperFunctions' must not be a reparse point."
}
if ([string]::IsNullOrWhiteSpace($BootstrapperExtensionPath)) {
    $payloadConfiguration = Split-Path -Leaf $payloadPath
    $BootstrapperExtensionPath = Join-Path $repositoryRoot (
        "bin\setup\$dotnetPlatform\$payloadConfiguration\ProxiFyreSetup.EngineExtension.dll")
}
$bootstrapperExtension = [IO.Path]::GetFullPath($BootstrapperExtensionPath)
if (-not [IO.File]::Exists($bootstrapperExtension)) {
    throw "Setup engine extension '$bootstrapperExtension' does not exist. Build ProxiFyreSetupEngineExtension for $dotnetPlatform first or pass -BootstrapperExtensionPath."
}
$bootstrapperExtensionItem = Get-Item -LiteralPath $bootstrapperExtension -Force
if (($bootstrapperExtensionItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "Setup engine extension '$bootstrapperExtension' must not be a reparse point."
}

$runtimeFiles = @(
    'ProxiFyre.exe',
    'ProxiFyre.exe.config',
    'ProxiFyreUI.exe',
    'ProxiFyreUI.exe.config',
    'ProxiFyreUI.Managed.dll',
    'ProxiFyre.Configuration.dll',
    'socksify.dll',
    'Newtonsoft.Json.dll',
    'NLog.dll',
    'Topshelf.dll',
    'NLog.config',
    'app-config.sample.json'
)
foreach ($relativePath in $runtimeFiles) {
    $source = Join-Path $payloadPath $relativePath
    if (-not [IO.File]::Exists($source)) {
        throw "Required runtime file '$relativePath' is missing from '$payloadPath'."
    }
    $sourceItem = Get-Item -LiteralPath $source -Force
    if (($sourceItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Runtime file '$source' must not be a reparse point."
    }
}

function Get-PeArchitecture {
    param([Parameter(Mandatory = $true)][string] $Path)
    $stream = [IO.File]::OpenRead($Path)
    try {
        $reader = [IO.BinaryReader]::new($stream, [Text.Encoding]::UTF8, $true)
        try {
            if ($reader.ReadUInt16() -ne 0x5A4D) { throw "'$Path' is not a PE image." }
            $stream.Position = 0x3c
            $peOffset = $reader.ReadUInt32()
            $stream.Position = $peOffset
            if ($reader.ReadUInt32() -ne 0x00004550) { throw "'$Path' has no PE signature." }
            $machine = $reader.ReadUInt16()
            switch ($machine) {
                0x014c { 'x86' }
                0x8664 { 'x64' }
                0xaa64 { 'arm64' }
                default { throw "'$Path' has an unsupported PE machine type." }
            }
        }
        finally { $reader.Dispose() }
    }
    finally { $stream.Dispose() }
}

function Assert-ReleaseVersion {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][string] $DisplayName
    )

    $versionInfo = [Diagnostics.FileVersionInfo]::GetVersionInfo($Path)
    foreach ($propertyName in @('FileVersion', 'ProductVersion')) {
        $actualVersionText = [string] $versionInfo.$propertyName
        [Version] $actualVersion = $null
        if (-not [Version]::TryParse($actualVersionText, [ref] $actualVersion) -or
            $actualVersion.Major -ne [int] $versionMatch.Groups[1].Value -or
            $actualVersion.Minor -ne [int] $versionMatch.Groups[2].Value -or
            $actualVersion.Build -ne [int] $versionMatch.Groups[3].Value -or
            $actualVersion.Revision -notin @(-1, 0)) {
            throw "$DisplayName has $propertyName '$actualVersionText'; expected '$Version'. Rebuild the release payload with -p:Version=$Version."
        }
    }

    $expectedFixedVersion = "$Version.0"
    $actualFixedVersions = @{
        FileVersion = '{0}.{1}.{2}.{3}' -f $versionInfo.FileMajorPart,
            $versionInfo.FileMinorPart, $versionInfo.FileBuildPart,
            $versionInfo.FilePrivatePart
        ProductVersion = '{0}.{1}.{2}.{3}' -f $versionInfo.ProductMajorPart,
            $versionInfo.ProductMinorPart, $versionInfo.ProductBuildPart,
            $versionInfo.ProductPrivatePart
    }
    foreach ($fixedVersionName in $actualFixedVersions.Keys) {
        if ($actualFixedVersions[$fixedVersionName] -cne $expectedFixedVersion) {
            throw "$DisplayName has fixed $fixedVersionName '$($actualFixedVersions[$fixedVersionName])'; expected '$expectedFixedVersion'. Rebuild the release payload with -p:Version=$Version."
        }
    }
}

foreach ($architectureFile in @(
        'ProxiFyre.exe',
        'ProxiFyreUI.exe',
        'ProxiFyreUI.Managed.dll',
        'ProxiFyre.Configuration.dll',
        'socksify.dll')) {
    $architecturePath = Join-Path $payloadPath $architectureFile
    $actualArchitecture = Get-PeArchitecture -Path $architecturePath
    if ($actualArchitecture -cne $normalizedArchitecture) {
        throw "$architectureFile targets $actualArchitecture, not $normalizedArchitecture."
    }

    Assert-ReleaseVersion -Path $architecturePath -DisplayName $architectureFile
}
$bootstrapperFunctionsArchitecture = Get-PeArchitecture -Path $bootstrapperFunctions
if ($bootstrapperFunctionsArchitecture -cne $normalizedArchitecture) {
    throw "Setup BAFunctions DLL targets $bootstrapperFunctionsArchitecture, not $normalizedArchitecture."
}
$bootstrapperExtensionArchitecture = Get-PeArchitecture -Path $bootstrapperExtension
if ($bootstrapperExtensionArchitecture -cne $normalizedArchitecture) {
    throw "Setup engine extension targets $bootstrapperExtensionArchitecture, not $normalizedArchitecture."
}
Assert-ReleaseVersion -Path $bootstrapperFunctions `
    -DisplayName 'ProxiFyreSetup.BAFunctions.dll'
Assert-ReleaseVersion -Path $bootstrapperExtension `
    -DisplayName 'ProxiFyreSetup.EngineExtension.dll'

& (Join-Path $PSScriptRoot 'Test-SetupEngineExtensionSource.ps1') `
    -SourcePath (Join-Path $repositoryRoot `
        'ProxiFyreSetupEngineExtension\BootstrapperExtension.cpp') |
    Write-Host
& (Join-Path $PSScriptRoot 'Test-SetupBootstrapperFunctionsSource.ps1') `
    -SourcePath (Join-Path $repositoryRoot `
        'ProxiFyreSetupBootstrapper\BootstrapperFunctions.cpp') |
    Write-Host

$wpfPackages = @{
    x86 = @{
        FileName = 'Windows.Packet.Filter.3.6.2.1.x86.msi'
        Size = 786432L
        Sha256 = 'ff882c295f9bb0c4465b179e912ad2d2c41eadc053142bd2f125f49a85ee4e1f'
        Sha512 = 'f155bf8188d69a3cad35a6bbc2565a5042fb7949006a59dcaf053373730ca14bd90c13d0366bb0287c6b1d7257ce5ecf9050806ed1dd2ac4e15502486553296a'
        ProductCode = '{08C84C3C-9221-4640-BE54-B8DC23D29BD9}'
    }
    x64 = @{
        FileName = 'Windows.Packet.Filter.3.6.2.1.x64.msi'
        Size = 819200L
        Sha256 = '9c388c0b7f189f7fa98720bae2caecf7d64f30910838b80b438ecf8956b8502c'
        Sha512 = '2d79cb4e5ef769157510cae8823ffb255c9d194d09b53286dbfc600dd6fe9e2bafaaf765865a5aa3b581172b7b55c69bff26466f6b14f7725a6b0929aaa37263'
        ProductCode = '{4EC4289E-7F4B-424C-8EA9-B7AC9850FFBE}'
    }
    arm64 = @{
        FileName = 'Windows.Packet.Filter.3.6.2.1.ARM64.msi'
        Size = 745472L
        Sha256 = 'b13c6832c9e5c0c14948bbf5c17ccbe65dff55c0f6069df01494d97ebd1f3d69'
        Sha512 = '823f2828464c7e73613dce929c5d0ac29bfddb890406c9badedfa2f0a3410a4c072df9038d7c2c9cb785bc89960256cc83a42336e041628be898c28d7cccf23c'
        ProductCode = '{E59134C2-66A4-4F9C-AA5C-3D717B5BCFA5}'
    }
}
$wpf = $wpfPackages[$normalizedArchitecture]
$wpf['DownloadUrl'] = "https://github.com/wiresock/ndisapi/releases/download/v3.6.2/$($wpf.FileName)"

$visualCppPackages = @{
    x86 = @{
        FileName = 'VC_redist.x86.exe'
        Size = 13953392L
        Sha256 = '0c09f2611660441084ce0df425c51c11e147e6447963c3690f97e0b25c55ed64'
        Sha512 = 'd0a609f6b2f05939ab82aa5fde1bb0595206653a2ab2ce859a750f71596c4491a8074bb825484e365a4fbcdb820d5de0346e7209ea22214b090b4fe853098dce'
        DownloadUrl = 'https://download.visualstudio.microsoft.com/download/pr/0b44c2d1-8944-4834-a01a-c9a225f8088a/0C09F2611660441084CE0DF425C51C11E147E6447963C3690F97E0B25C55ED64/VC_redist.x86.exe'
        RegistryArchitecture = 'x86'
    }
    x64 = @{
        FileName = 'VC_redist.x64.exe'
        Size = 25635768L
        Sha256 = 'cc0ff0eb1dc3f5188ae6300faef32bf5beeba4bdd6e8e445a9184072096b713b'
        Sha512 = 'e131b93acde5ffc76c19eb0784183a1e94dfa9fe06111a7830eae3ad8583895575dd4dca66aa70efddb243c95735a0105efcd3042b4b5ca445d3d8e8c39d957e'
        DownloadUrl = 'https://download.visualstudio.microsoft.com/download/pr/0b44c2d1-8944-4834-a01a-c9a225f8088a/CC0FF0EB1DC3F5188AE6300FAEF32BF5BEEBA4BDD6E8E445A9184072096B713B/VC_redist.x64.exe'
        RegistryArchitecture = 'x64'
    }
    arm64 = @{
        FileName = 'VC_redist.arm64.exe'
        Size = 11722336L
        Sha256 = '5139e1440c3a20b92153a4db561c069a0175aaf76c276c3e5b6f56099edcf4b0'
        Sha512 = '0599cda3543551e56e3ca560a88278d8a293ed30c812515a730863faa7c224f5aa2cfe818d9083a26c755f0dab5651fa610b95aef0d25ae05f4af6414cb36d8d'
        DownloadUrl = 'https://download.visualstudio.microsoft.com/download/pr/d7450eb5-03e1-436d-9e7e-deb5fe4759b3/5139E1440C3A20B92153A4DB561C069A0175AAF76C276C3E5B6F56099EDCF4B0/VC_redist.arm64.exe'
        RegistryArchitecture = 'arm64'
    }
}
$visualCpp = $visualCppPackages[$normalizedArchitecture]
$visualCpp['Version'] = '14.44.35211.0'
$visualCppDownloadUri = [Uri]$visualCpp.DownloadUrl
$visualCppContentPath = "/$($visualCpp.Sha256.ToUpperInvariant())/$($visualCpp.FileName)"
if ($visualCppDownloadUri.Scheme -cne 'https' -or
    $visualCppDownloadUri.IdnHost -cne 'download.visualstudio.microsoft.com' -or
    -not $visualCppDownloadUri.IsDefaultPort -or
    -not [string]::IsNullOrEmpty($visualCppDownloadUri.UserInfo) -or
    -not [string]::IsNullOrEmpty($visualCppDownloadUri.Query) -or
    -not [string]::IsNullOrEmpty($visualCppDownloadUri.Fragment) -or
    -not $visualCppDownloadUri.AbsolutePath.StartsWith(
        '/download/pr/', [StringComparison]::Ordinal) -or
    -not $visualCppDownloadUri.AbsolutePath.EndsWith(
        $visualCppContentPath, [StringComparison]::Ordinal)) {
    throw 'The Visual C++ source must be an HTTPS Microsoft content-addressed URL whose path contains the pinned SHA-256 and filename.'
}

function Get-DeterministicGuid {
    param([Parameter(Mandatory = $true)][string] $Identity)
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha256.ComputeHash([Text.Encoding]::UTF8.GetBytes(
            "ProxiFyre.Installer|$Identity"))
    }
    finally { $sha256.Dispose() }
    $bytes = New-Object byte[] 16
    [Array]::Copy($hash, $bytes, 16)
    $bytes[7] = ($bytes[7] -band 0x0f) -bor 0x50
    $bytes[8] = ($bytes[8] -band 0x3f) -bor 0x80
    return ([Guid]::new($bytes)).ToString('B').ToUpperInvariant()
}

$temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) (
    'ProxiFyre.Installer.' + [Guid]::NewGuid().ToString('N'))
$stagedPayload = Join-Path $temporaryRoot 'payload'
$licenseRtf = Join-Path $temporaryRoot 'License.rtf'
$installerIntermediate = Join-Path $temporaryRoot 'installer-obj'
$bundleIntermediate = Join-Path $temporaryRoot 'bundle-obj'
$bundleOutput = Join-Path $temporaryRoot 'bundle-output'
$downloadedWpf = Join-Path $temporaryRoot $wpf.FileName
$downloadedVisualCpp = Join-Path $temporaryRoot $visualCpp.FileName

$msiName = "ProxiFyre-$Version-win-$normalizedArchitecture.msi"
$bundleName = "ProxiFyre-$Version-win-$normalizedArchitecture-setup.exe"
$msiPath = Join-Path $outputPath $msiName
$bundlePath = Join-Path $outputPath $bundleName
$builtBundlePath = Join-Path $bundleOutput $bundleName

foreach ($layoutPayloadName in @($wpf.FileName, $visualCpp.FileName)) {
    $unexpectedLayoutPayload = Join-Path $outputPath $layoutPayloadName
    if ([IO.File]::Exists($unexpectedLayoutPayload)) {
        throw "Output directory '$outputPath' contains external prerequisite '$layoutPayloadName'. Move or remove it before building so the published directory remains online-only."
    }
}

try {
    [IO.Directory]::CreateDirectory($temporaryRoot) | Out-Null
    [IO.Directory]::CreateDirectory($stagedPayload) | Out-Null
    [IO.Directory]::CreateDirectory($installerIntermediate) | Out-Null
    [IO.Directory]::CreateDirectory($bundleIntermediate) | Out-Null
    [IO.Directory]::CreateDirectory($bundleOutput) | Out-Null
    [IO.Directory]::CreateDirectory($outputPath) | Out-Null

    $licenseText = [IO.File]::ReadAllText((Join-Path $repositoryRoot 'LICENSE'))
    $normalizedLicense = $licenseText.Replace("`r`n", "`n").Replace("`r", "`n")
    $escapedLicense = $normalizedLicense.Replace('\', '\\').Replace(
        '{', '\{').Replace('}', '\}').Replace("`n", "\par`r`n")
    [IO.File]::WriteAllText(
        $licenseRtf,
        "{\rtf1\ansi\deff0{\fonttbl{\f0 Courier New;}}\viewkind4\uc1\pard\f0\fs18`r`n" +
        $escapedLicense + "\par`r`n}",
        [Text.ASCIIEncoding]::new())

    foreach ($artifact in @($msiPath, $bundlePath, "$msiPath.sha256", "$bundlePath.sha256")) {
        if ([IO.File]::Exists($artifact)) {
            if (-not $Force) {
                throw "Output '$artifact' already exists. Use -Force to replace the exact installer outputs."
            }
            [IO.File]::Delete($artifact)
        }
    }

    foreach ($relativePath in $runtimeFiles) {
        [IO.File]::Copy(
            (Join-Path $payloadPath $relativePath),
            (Join-Path $stagedPayload $relativePath),
            $false)
    }
    $firstPartyModules = @(
        'ProxiFyre.exe',
        'ProxiFyreUI.exe',
        'ProxiFyreUI.Managed.dll',
        'ProxiFyre.Configuration.dll',
        'socksify.dll'
    ) | ForEach-Object { Join-Path $stagedPayload $_ }
    # Third-party dependencies can retain signatures applied by their own
    # publishers. ProxiFyre does not create, replace, or require those signatures.
    & (Join-Path $PSScriptRoot 'Test-UnsignedArtifacts.ps1') -Path $firstPartyModules |
        Write-Host
    & (Join-Path $PSScriptRoot 'Test-UnsignedArtifacts.ps1') `
        -Path @($bootstrapperFunctions, $bootstrapperExtension) | Write-Host

    if ([string]::IsNullOrWhiteSpace($WindowsPacketFilterMsiPath)) {
        Write-Host "Downloading official Windows Packet Filter prerequisite metadata source from $($wpf.DownloadUrl)"
        Invoke-WebRequest -Uri $wpf.DownloadUrl -OutFile $downloadedWpf
        $resolvedWpfPath = $downloadedWpf
    }
    else {
        $resolvedWpfPath = (Get-Item -LiteralPath $WindowsPacketFilterMsiPath -Force).FullName
    }
    $wpfItem = Get-Item -LiteralPath $resolvedWpfPath -Force
    if (($wpfItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Windows Packet Filter MSI '$resolvedWpfPath' must not be a reparse point."
    }
    if ($wpfItem.Length -ne [Int64]$wpf.Size) {
        throw "Windows Packet Filter MSI has size $($wpfItem.Length); expected $($wpf.Size)."
    }
    $actualWpfHash = (Get-FileHash -LiteralPath $resolvedWpfPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualWpfHash -cne $wpf.Sha256) {
        throw "Windows Packet Filter MSI SHA-256 '$actualWpfHash' does not match the pinned official asset."
    }
    $actualWpfSha512 = (Get-FileHash -LiteralPath $resolvedWpfPath -Algorithm SHA512).Hash.ToLowerInvariant()
    if ($actualWpfSha512 -cne $wpf.Sha512) {
        throw "Windows Packet Filter MSI SHA-512 '$actualWpfSha512' does not match the pinned official asset."
    }
    $wpfSignature = Get-AuthenticodeSignature -LiteralPath $resolvedWpfPath
    if ($wpfSignature.Status -ne [Management.Automation.SignatureStatus]::Valid) {
        throw "The official Windows Packet Filter MSI signature is not valid: $($wpfSignature.Status)."
    }

    if ([string]::IsNullOrWhiteSpace($VisualCppRedistributablePath)) {
        Write-Host "Downloading the pinned official Microsoft Visual C++ runtime metadata source from $($visualCpp.DownloadUrl)"
        Invoke-WebRequest -Uri $visualCpp.DownloadUrl -OutFile $downloadedVisualCpp
        $resolvedVisualCppPath = $downloadedVisualCpp
    }
    else {
        $resolvedVisualCppPath = (Get-Item -LiteralPath $VisualCppRedistributablePath -Force).FullName
    }
    $visualCppItem = Get-Item -LiteralPath $resolvedVisualCppPath -Force
    if (($visualCppItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Visual C++ redistributable '$resolvedVisualCppPath' must not be a reparse point."
    }
    if ($visualCppItem.Length -ne [Int64]$visualCpp.Size) {
        throw "Visual C++ redistributable has size $($visualCppItem.Length); expected $($visualCpp.Size)."
    }
    $actualVisualCppHash = (Get-FileHash -LiteralPath $resolvedVisualCppPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualVisualCppHash -cne $visualCpp.Sha256) {
        throw "Visual C++ redistributable SHA-256 '$actualVisualCppHash' does not match the pinned Microsoft asset."
    }
    $actualVisualCppSha512 = (Get-FileHash -LiteralPath $resolvedVisualCppPath -Algorithm SHA512).Hash.ToLowerInvariant()
    if ($actualVisualCppSha512 -cne $visualCpp.Sha512) {
        throw "Visual C++ redistributable SHA-512 '$actualVisualCppSha512' does not match the pinned Microsoft asset."
    }
    if ([string]$visualCppItem.VersionInfo.FileVersion -cne $visualCpp.Version -or
        [string]$visualCppItem.VersionInfo.ProductVersion -cne $visualCpp.Version) {
        throw "Visual C++ redistributable version must be $($visualCpp.Version)."
    }
    $visualCppSignature = Get-AuthenticodeSignature -LiteralPath $resolvedVisualCppPath
    if ($visualCppSignature.Status -ne [Management.Automation.SignatureStatus]::Valid -or
        $null -eq $visualCppSignature.SignerCertificate -or
        [string]$visualCppSignature.SignerCertificate.Subject -notmatch '(^|,\s*)O=Microsoft Corporation(,|$)') {
        throw "The pinned Visual C++ redistributable does not have a valid Microsoft signature."
    }

    $productCode = Get-DeterministicGuid -Identity "Product|$normalizedArchitecture|$Version"
    $componentSeed = Get-DeterministicGuid -Identity "Components|$normalizedArchitecture"
    $directorySecurityGuid = Get-DeterministicGuid -Identity "DirectorySecurity|$normalizedArchitecture"
    $uiLauncherGuid = Get-DeterministicGuid -Identity "UiLauncher|$normalizedArchitecture"
    $startMenuGuid = Get-DeterministicGuid -Identity "StartMenuShortcut|$normalizedArchitecture"
    $desktopGuid = Get-DeterministicGuid -Identity "DesktopShortcut|$normalizedArchitecture"

    $installerArguments = @(
        'build', $installerProject,
        '--configuration', 'Release',
        "--property:Platform=$dotnetPlatform",
        "--property:InstallerPlatform=$normalizedArchitecture",
        "--property:ProductArchitecture=$normalizedArchitecture",
        "--property:ProductVersion=$Version",
        "--property:ProductCode=$productCode",
        "--property:ComponentGuidGenerationSeed=$componentSeed",
        "--property:DirectorySecurityComponentGuid=$directorySecurityGuid",
        "--property:UiLauncherComponentGuid=$uiLauncherGuid",
        "--property:StartMenuComponentGuid=$startMenuGuid",
        "--property:DesktopComponentGuid=$desktopGuid",
        "--property:LicenseRtfPath=$licenseRtf",
        "--property:PayloadDirectory=$stagedPayload",
        '--property:PackagingInputsValidated=true',
        "--property:OutputPath=$($outputPath.TrimEnd('\', '/'))\",
        "--property:IntermediateOutputPath=$($installerIntermediate.TrimEnd('\', '/'))\",
        "--property:OutputName=$([IO.Path]::GetFileNameWithoutExtension($msiName))",
        '--property:ContinuousIntegrationBuild=true'
    )
    if ($NoRestore) { $installerArguments += '--no-restore' }
    & dotnet @installerArguments
    if ($LASTEXITCODE -ne 0) { throw "WiX MSI build failed with exit code $LASTEXITCODE." }
    if (-not [IO.File]::Exists($msiPath)) { throw "WiX did not produce '$msiPath'." }

    & (Join-Path $PSScriptRoot 'Test-InstallerPackage.ps1') `
        -MsiPath $msiPath -Architecture $normalizedArchitecture -Version $Version |
        Write-Host

    $bundleArguments = @(
        'build', $bundleProject,
        '--configuration', 'Release',
        "--property:Platform=$dotnetPlatform",
        "--property:InstallerPlatform=$normalizedArchitecture",
        "--property:ProductArchitecture=$normalizedArchitecture",
        "--property:ProductVersion=$Version",
        "--property:ProxiFyreMsiPath=$msiPath",
        "--property:BootstrapperFunctionsPath=$bootstrapperFunctions",
        "--property:BootstrapperExtensionPath=$bootstrapperExtension",
        "--property:WindowsPacketFilterMsiPath=$resolvedWpfPath",
        "--property:WindowsPacketFilterDownloadUrl=$($wpf.DownloadUrl)",
        "--property:VisualCppRedistributablePath=$resolvedVisualCppPath",
        "--property:VisualCppRedistributableDownloadUrl=$($visualCpp.DownloadUrl)",
        "--property:VisualCppRedistRegistryArchitecture=$($visualCpp.RegistryArchitecture)",
        '--property:PackagingInputsValidated=true',
        "--property:OutputPath=$($bundleOutput.TrimEnd('\', '/'))\",
        "--property:IntermediateOutputPath=$($bundleIntermediate.TrimEnd('\', '/'))\",
        "--property:OutputName=$([IO.Path]::GetFileNameWithoutExtension($bundleName))",
        '--property:ContinuousIntegrationBuild=true'
    )
    if ($NoRestore) { $bundleArguments += '--no-restore' }
    & dotnet @bundleArguments
    if ($LASTEXITCODE -ne 0) { throw "WiX bundle build failed with exit code $LASTEXITCODE." }
    if (-not [IO.File]::Exists($builtBundlePath)) {
        throw "WiX did not produce '$builtBundlePath'."
    }

    & (Join-Path $PSScriptRoot 'Test-BundlePackage.ps1') `
        -BundlePath $builtBundlePath `
        -BootstrapperExtensionPath $bootstrapperExtension `
        -Architecture $normalizedArchitecture `
        -Version $Version `
        -WindowsPacketFilterFileName $wpf.FileName `
        -WindowsPacketFilterDownloadUrl $wpf.DownloadUrl `
        -WindowsPacketFilterSize $wpf.Size `
        -WindowsPacketFilterSha512 $wpf.Sha512 `
        -WindowsPacketFilterProductCode $wpf.ProductCode `
        -VisualCppRedistributableFileName $visualCpp.FileName `
        -VisualCppRedistributableDownloadUrl $visualCpp.DownloadUrl `
        -VisualCppRedistributableSize $visualCpp.Size `
        -VisualCppRedistributableSha256 $visualCpp.Sha256 `
        -VisualCppRedistributableSha512 $visualCpp.Sha512 `
        -VisualCppRegistryArchitecture $visualCpp.RegistryArchitecture |
        Write-Host

    # WiX materializes uncompressed remote-payload sources beside its bundle.
    # Keep that layout inside temporary staging so release/test output cannot
    # silently become an offline layout that bypasses the online acquisition path.
    [IO.File]::Copy($builtBundlePath, $bundlePath, $false)

    & (Join-Path $PSScriptRoot 'Test-UnsignedArtifacts.ps1') `
        -Path @($msiPath, $bundlePath) |
        Write-Host

    foreach ($artifact in @($msiPath, $bundlePath)) {
        $hash = (Get-FileHash -LiteralPath $artifact -Algorithm SHA256).Hash.ToLowerInvariant()
        [IO.File]::WriteAllText(
            "$artifact.sha256",
            "$hash  $([IO.Path]::GetFileName($artifact))`n",
            [Text.UTF8Encoding]::new($false))
    }

    Write-Output $msiPath
    Write-Output "$msiPath.sha256"
    Write-Output $bundlePath
    Write-Output "$bundlePath.sha256"
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
                'ProxiFyre.Installer.', [StringComparison]::Ordinal) -or
            ($temporaryItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Refusing to recursively clean unsafe staging path '$resolvedTemporaryRoot'."
        }
        [IO.Directory]::Delete($resolvedTemporaryRoot, $true)
    }
}
