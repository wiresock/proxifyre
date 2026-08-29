#requires -Version 7.0

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$configurationPath = Join-Path $repositoryRoot 'ProxiFyreUI\ProxiFyreUI.exe.config'
$manifestPath = Join-Path $repositoryRoot 'ProxiFyreUI\app.manifest'

[xml]$configuration = [IO.File]::ReadAllText($configurationPath)
$windowsFormsSection =
    $configuration.configuration.'System.Windows.Forms.ApplicationConfigurationSection'
if ($null -eq $windowsFormsSection) {
    throw 'The UI configuration must opt in through System.Windows.Forms.ApplicationConfigurationSection.'
}

$dpiSettings = @($windowsFormsSection.add | Where-Object {
    [string]$_.key -ceq 'DpiAwareness'
})
if ($dpiSettings.Count -ne 1 -or [string]$dpiSettings[0].value -cne 'PerMonitorV2') {
    throw 'The UI configuration must enable exactly one PerMonitorV2 DpiAwareness setting.'
}

$autoResizeSettings = @($windowsFormsSection.add | Where-Object {
    [string]$_.key -ceq 'EnableWindowsFormsHighDpiAutoResizing'
})
if ($autoResizeSettings.Count -ne 1 -or [string]$autoResizeSettings[0].value -cne 'true') {
    throw 'The UI configuration must enable Windows Forms high-DPI auto-resizing.'
}

$legacyDpiSettings = @($configuration.SelectNodes(
    '/configuration/appSettings/add[@key="DpiAwareness" or ' +
    '@key="EnableWindowsFormsHighDpiAutoResizing"]'))
if ($legacyDpiSettings.Count -ne 0) {
    throw 'High-DPI settings must not remain in the legacy appSettings section.'
}

[xml]$manifest = [IO.File]::ReadAllText($manifestPath)
$manifestDpiNodes = @($manifest.SelectNodes(
    '//*[local-name()="dpiAware" or local-name()="dpiAwareness"]'))
if ($manifestDpiNodes.Count -ne 0) {
    throw 'The application manifest must not override the .NET Framework DPI configuration.'
}

$windows10Compatibility = $manifest.SelectSingleNode(
    '//*[local-name()="supportedOS" and @Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"]')
if ($null -eq $windows10Compatibility) {
    throw 'The application manifest must continue to declare Windows 10 compatibility.'
}

$designerPaths = @(
    'ProxiFyreUI\Forms\InputDialog.Designer.cs',
    'ProxiFyreUI\Forms\MainForm.Designer.cs',
    'ProxiFyreUI\Forms\ProcessPickerForm.Designer.cs',
    'ProxiFyreUI\Forms\ProxyRuleEditorForm.Designer.cs'
)
foreach ($relativePath in $designerPaths) {
    $designerPath = Join-Path $repositoryRoot $relativePath
    $designerSource = [IO.File]::ReadAllText($designerPath)
    if ($designerSource -notmatch
        'AutoScaleDimensions\s*=\s*new System\.Drawing\.SizeF\(96F, 96F\)' -or
        $designerSource -notmatch
        'AutoScaleMode\s*=\s*System\.Windows\.Forms\.AutoScaleMode\.Dpi') {
        throw "Form '$relativePath' must use a 96-DPI design baseline and DPI autoscaling."
    }
}

$configurationHash = (Get-FileHash -LiteralPath $configurationPath -Algorithm SHA256).Hash
$managedIntegritySource = [IO.File]::ReadAllText((
    Join-Path $repositoryRoot 'ProxiFyreUI\Infrastructure\PayloadIntegrity.cs'))
if (-not $managedIntegritySource.Contains('"' + $configurationHash + '"',
        [StringComparison]::Ordinal)) {
    throw 'The managed UI configuration integrity pin does not match the configuration file.'
}

$nativeLauncherSource = [IO.File]::ReadAllText((
    Join-Path $repositoryRoot 'ProxiFyreUILauncher\Program.cpp'))
$nativeHashMatch = [regex]::Match($nativeLauncherSource,
    'kExpectedUiConfigurationSha256\s*=\s*\{(?<bytes>.*?)\};',
    [Text.RegularExpressions.RegexOptions]::Singleline)
if (-not $nativeHashMatch.Success) {
    throw 'The native UI configuration integrity pin was not found.'
}
$nativeConfigurationHash = (@([regex]::Matches(
    $nativeHashMatch.Groups['bytes'].Value, '0x(?<byte>[0-9A-Fa-f]{2})') |
    ForEach-Object { $_.Groups['byte'].Value.ToUpperInvariant() })) -join ''
if ($nativeConfigurationHash -cne $configurationHash) {
    throw 'The native UI configuration integrity pin does not match the configuration file.'
}

Write-Output 'Validated the UI high-DPI opt-in, form scaling, manifest, and integrity pins.'
