#requires -Version 7.0

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $SourcePath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$resolvedSource = (Get-Item -LiteralPath $SourcePath -Force).FullName
$source = [IO.File]::ReadAllText($resolvedSource)

$setOptionCalls = [regex]::Matches($source, '\bInternetSetOptionW\s*\(')
if ($setOptionCalls.Count -ne 1 -or
    $source -notmatch '(?s)\bInternetSetOptionW\s*\(\s*internet\s*,\s*INTERNET_OPTION_PER_CONNECTION_OPTION') {
    throw 'The engine extension must make exactly one process-scoped InternetSetOptionW call on its non-NULL WinINet root handle.'
}

if ($source -match '\bInternetSetOption[AW]?\s*\(\s*(?:nullptr|NULL|0)\b' -or
    $source -match '\bINTERNET_OPTION_(?:SETTINGS_CHANGED|REFRESH)\b') {
    throw 'The engine extension must not mutate or refresh global WinINet settings.'
}

$registryWritePattern =
    '\bReg(?:CreateKey|SetKey|SetValue|DeleteKey|DeleteValue|OverridePredefKey|ReplaceKey|RestoreKey|SaveKey)[A-Z0-9_]*\s*\('
if ($source -match $registryWritePattern) {
    throw 'The engine extension must keep all registry access read-only.'
}

foreach ($requiredGate in @(
        'INTERNET_PER_CONN_FLAGS_UI',
        'INTERNET_PER_CONN_FLAGS',
        'INTERNET_PER_CONN_PROXY_SERVER',
        'INTERNET_PER_CONN_AUTOCONFIG_URL',
        'ProxyEnable',
        'ProxySettingsPerUser',
        'AutoDetect',
        'DefaultConnectionSettings',
        'SavedLegacySettings',
        'ProxyServer',
        'AutoConfigURL',
        'QueryRawInternetSettingStringIsEmpty',
        'ParseLengthPrefixedBlobString',
        'kConnectionBlobMarkerLegacy',
        'kConnectionBlobMarkerCurrent',
        'kKnownProxyRouteFlags',
        'PROXY_TYPE_DIRECT')) {
    if ($source -notmatch [regex]::Escape($requiredGate)) {
        throw "The conservative WinINet gate is missing '$requiredGate'."
    }
}

if ($source -notmatch '(?s)perUser\s*==\s*1' -or
    $source -notmatch '(?s)marker\s*==\s*kConnectionBlobMarkerLegacy\s*\|\|\s*marker\s*==\s*kConnectionBlobMarkerCurrent') {
    throw 'The engine extension must accept only explicit per-user proxy policy and the two known connection-blob formats.'
}

if ($source -notmatch '(?s)rawFlags\s*&\s*~kKnownProxyRouteFlags' -or
    $source -notmatch '(?s)PROXY_TYPE_PROXY\s*\|\s*PROXY_TYPE_AUTO_PROXY_URL\s*\|\s*PROXY_TYPE_AUTO_DETECT' -or
    $source -notmatch '(?s)rawProxyEmpty\s*&&\s*rawAutoConfigUrlEmpty') {
    throw 'The raw connection-blob parser must reject unknown, proxy, PAC, WPAD, and nonempty embedded route settings.'
}

if ($source -notmatch '(?s)type\s*!=\s*REG_SZ' -or
    $source -notmatch '(?s)actualSize\s*!=\s*sizeof\(wchar_t\)' -or
    $source -notmatch "(?s)empty\s*=\s*value\s*==\s*L'\\0'") {
    throw 'Raw ProxyServer and AutoConfigURL values must be absent or an exact one-NUL REG_SZ.'
}

foreach ($rawRouteValue in @('ProxyServer', 'AutoConfigURL')) {
    $rawQueryPattern = '(?s)QueryRawInternetSettingStringIsEmpty\s*\(\s*L"' +
        [regex]::Escape($rawRouteValue) + '"'
    if ($source -notmatch $rawQueryPattern) {
        throw "The direct-route gate must independently inspect raw HKCU $rawRouteValue."
    }
}

$guardCalls = [regex]::Matches($source, '\bShouldApplyDirectWorkaround\s*\(\s*\)')
if ($guardCalls.Count -ne 3) {
    throw 'The complete direct-route guard must run both before and after opening the process-scoped WinINet root.'
}

Write-Output 'Validated the process-scoped, read-only WinINet compatibility implementation.'
