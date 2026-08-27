#requires -Version 7.0

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $SourcePath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$resolvedSource = (Get-Item -LiteralPath $SourcePath -Force).FullName
$source = [IO.File]::ReadAllText($resolvedSource)

$setDownloadSourceCalls = [regex]::Matches($source, '\bSetDownloadSource\s*\(')
if ($setDownloadSourceCalls.Count -ne 1 -or
    $source -notmatch '(?s)SetDownloadSource\s*\(\s*packageOrContainerId\s*,\s*payloadId\s*,\s*visualCppHttpFallbackUrl_\s*,\s*nullptr\s*,\s*nullptr\s*,\s*nullptr\s*\)') {
    throw 'The setup helper must make exactly one unauthenticated download-source override using the current package and payload identifiers.'
}

foreach ($requiredGuard in @(
        'IsWindows7()',
        'OSVERSIONINFOEXW',
        'VER_NT_WORKSTATION',
        'BOOTSTRAPPER_CACHE_OPERATION_DOWNLOAD',
        'ERROR_INTERNET_CANNOT_CONNECT',
        'BOOTSTRAPPER_CACHEACQUIRECOMPLETE_ACTION_NONE',
        'BOOTSTRAPPER_CACHEACQUIRECOMPLETE_ACTION_RETRY',
        'BOOTSTRAPPER_CACHEVERIFYCOMPLETE_ACTION_RETRYACQUISITION',
        'kVisualCppRuntimeId',
        'kVisualCppDownloadHttpsPrefix',
        'StartsWithOrdinalIgnoreCase')) {
    if ($source -notmatch [regex]::Escape($requiredGuard)) {
        throw "The Windows 7 Visual C++ transport guard is missing '$requiredGuard'."
    }
}

if ($source -notmatch '(?s)bool\s+IsWindows7\s*\(\s*\).*?OSVERSIONINFOEXW\s+version.*?dwMajorVersion\s*==\s*6.*?dwMinorVersion\s*==\s*1.*?wProductType\s*==\s*VER_NT_WORKSTATION') {
    throw 'The Windows 7 transport guard must exclude Windows Server 2008 R2.'
}

$httpLiterals = [regex]::Matches($source, 'L"http://[^"\r\n]+"')
if ($httpLiterals.Count -ne 1 -or
    $httpLiterals[0].Value -cne
        'L"http://download.visualstudio.microsoft.com/download/pr/"') {
    throw 'The only plaintext transport must be the pinned Microsoft Visual C++ content-addressed endpoint.'
}

$armMatch = [regex]::Match($source,
    '(?s)HRESULT\s+ArmVisualCppHttpFallbackForWindows7\s*\([^)]*\)\s*\{(.*?)\n\s*\}\s*\n\s*HRESULT\s+RetryVisualCppOverHttpForWindows7')
$retryMatch = [regex]::Match($source,
    '(?s)HRESULT\s+RetryVisualCppOverHttpForWindows7\s*\([^)]*\)\s*\{(.*?)\n\s*\}\s*\n\s*void\s+ResetVisualCppHttpFallback')
if (-not $armMatch.Success -or -not $retryMatch.Success) {
    throw 'The Windows 7 Visual C++ fallback functions could not be structurally inspected.'
}

$armSource = $armMatch.Groups[1].Value
$retrySource = $retryMatch.Groups[1].Value
$urlGuard = [regex]::Match($armSource,
    '(?s)if\s*\(\s*!StartsWithOrdinalIgnoreCase\s*\(\s*downloadUrl\s*,\s*kVisualCppDownloadHttpsPrefix\s*\)\s*\)')
$fallbackArmed = $armSource.IndexOf(
    'visualCppHttpFallbackArmed_ = true;', [StringComparison]::Ordinal)
if ($armSource -notmatch '(?s)!IsWindows7\(\).*?recommendation\s*!=\s*BOOTSTRAPPER_CACHE_OPERATION_DOWNLOAD.*?!IsSameOrdinalIgnoreCase\s*\(\s*packageOrContainerId\s*,\s*kVisualCppRuntimeId\s*\).*?!IsSameOrdinalIgnoreCase\s*\(\s*payloadId\s*,\s*kVisualCppRuntimeId\s*\)' -or
    -not $urlGuard.Success -or $fallbackArmed -lt 0 -or
    $urlGuard.Index -ge $fallbackArmed) {
    throw 'The fallback must be armed only for an exact Microsoft Visual C++ HTTPS download on Windows 7.'
}

$sourceOverride = $retrySource.IndexOf(
    'm_pEngine->SetDownloadSource(', [StringComparison]::Ordinal)
$retryAction = $retrySource.IndexOf(
    '*action = BOOTSTRAPPER_CACHEACQUIRECOMPLETE_ACTION_RETRY;',
    [StringComparison]::Ordinal)
$stockRetryGate = $retrySource.IndexOf(
    '*action == BOOTSTRAPPER_CACHEACQUIRECOMPLETE_ACTION_RETRY',
    [StringComparison]::Ordinal)
if ($retrySource -notmatch '(?s)!visualCppHttpFallbackArmed_.*?!IsSameOrdinalIgnoreCase\s*\(\s*packageOrContainerId\s*,\s*kVisualCppRuntimeId\s*\).*?!IsSameOrdinalIgnoreCase\s*\(\s*payloadId\s*,\s*kVisualCppRuntimeId\s*\)' -or
    $retrySource -notmatch '(?s)if\s*\(\s*visualCppHttpFallbackAttempted_\s*\)\s*\{\s*\*action\s*=\s*BOOTSTRAPPER_CACHEACQUIRECOMPLETE_ACTION_NONE\s*;\s*return\s+S_OK\s*;' -or
    $retrySource -notmatch '(?s)status\s*!=\s*HRESULT_FROM_WIN32\s*\(\s*ERROR_INTERNET_CANNOT_CONNECT\s*\).*?\*action\s*==\s*BOOTSTRAPPER_CACHEACQUIRECOMPLETE_ACTION_RETRY' -or
    $stockRetryGate -lt 0 -or $stockRetryGate -ge $sourceOverride -or
    $sourceOverride -lt 0 -or $retryAction -le $sourceOverride) {
    throw 'The HTTP source override must be one final attempt only after WixStdBA exhausts its normal HTTPS retries for the exact Windows 7 WinINet 12029 failure.'
}

if ($source -notmatch '(?s)OnCacheVerifyComplete\s*\([^)]*\).*?visualCppHttpFallbackAttempted_.*?FAILED\s*\(\s*status\s*\).*?\*action\s*==\s*BOOTSTRAPPER_CACHEVERIFYCOMPLETE_ACTION_RETRYACQUISITION.*?\*action\s*=\s*BOOTSTRAPPER_CACHEVERIFYCOMPLETE_ACTION_NONE') {
    throw 'A failed digest verification after the final HTTP attempt must not trigger another HTTP acquisition.'
}

if ($source -notmatch '(?s)if\s*\(\s*IsHttpsUrl\s*\(\s*downloadUrl\s*\)\s*\).*?EnableTls12ForWindows7\s*\(\s*\)') {
    throw 'All HTTPS acquisitions must retain the Windows 7 TLS 1.2 hook before any fallback is considered.'
}

if ($source -notmatch 'making one final attempt over Microsoft''s HTTP endpoint' -or
    $source -notmatch "Burn will verify the bundle's exact SHA-512 before execution") {
    throw 'The setup log must disclose the plaintext compatibility transport and Burn digest verification.'
}

Write-Output 'Validated the final-attempt Windows 7, hash-pinned Visual C++ compatibility fallback.'
