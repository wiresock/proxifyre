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
        'BOOTSTRAPPER_CACHE_RESOLVE_DOWNLOAD',
        'ERROR_INTERNET_CANNOT_CONNECT',
        'BOOTSTRAPPER_CACHEACQUIRECOMPLETE_ACTION_NONE',
        'BOOTSTRAPPER_CACHEACQUIRECOMPLETE_ACTION_RETRY',
        'BOOTSTRAPPER_CACHEVERIFYCOMPLETE_ACTION_RETRYACQUISITION',
        'kVisualCppRuntimeId',
        'kVisualCppDownloadHttpsPrefix',
        'visualCppHttpFallbackPrepared_',
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

$prepareMatch = [regex]::Match($source,
    '(?s)HRESULT\s+PrepareVisualCppHttpFallbackForWindows7\s*\([^)]*\)\s*\{(.*?)\n\s*\}\s*\n\s*HRESULT\s+ArmVisualCppHttpFallbackForWindows7')
$armMatch = [regex]::Match($source,
    '(?s)HRESULT\s+ArmVisualCppHttpFallbackForWindows7\s*\([^)]*\)\s*\{(.*?)\n\s*\}\s*\n\s*HRESULT\s+RetryVisualCppOverHttpForWindows7')
$retryMatch = [regex]::Match($source,
    '(?s)HRESULT\s+RetryVisualCppOverHttpForWindows7\s*\([^)]*\)\s*\{(.*?)\n\s*\}\s*\n\s*void\s+ResetVisualCppHttpFallback')
if (-not $prepareMatch.Success -or -not $armMatch.Success -or
    -not $retryMatch.Success) {
    throw 'The Windows 7 Visual C++ fallback functions could not be structurally inspected.'
}

$prepareSource = $prepareMatch.Groups[1].Value
$armSource = $armMatch.Groups[1].Value
$retrySource = $retryMatch.Groups[1].Value
$prepareReferences = [regex]::Matches(
    $source, '\bPrepareVisualCppHttpFallbackForWindows7\s*\(')
$armReferences = [regex]::Matches(
    $source, '\bArmVisualCppHttpFallbackForWindows7\s*\(')
if ($prepareReferences.Count -ne 2 -or $armReferences.Count -ne 2) {
    throw 'Each two-stage fallback helper must have exactly one declaration and one callback invocation.'
}

$acquireBeginMatch = [regex]::Match($source,
    '(?s)OnCacheAcquireBegin\s*\([^)]*\)\s*override\s*\{(.*?)\n\s*\}\s*\n\s*STDMETHODIMP\s+OnCacheAcquireResolving')
$acquireResolvingMatch = [regex]::Match($source,
    '(?s)OnCacheAcquireResolving\s*\([^)]*\)\s*override\s*\{(.*?)\n\s*\}\s*\n\s*STDMETHODIMP\s+OnCacheAcquireComplete')
if (-not $acquireBeginMatch.Success -or -not $acquireResolvingMatch.Success) {
    throw 'The setup helper acquisition callbacks could not be structurally inspected.'
}
$acquireBeginSource = $acquireBeginMatch.Groups[1].Value
$acquireResolvingSource = $acquireResolvingMatch.Groups[1].Value
if ($acquireBeginSource -notmatch
    '(?s)PrepareVisualCppHttpFallbackForWindows7\s*\(\s*packageOrContainerId\s*,\s*payloadId\s*,\s*downloadUrl\s*\).*?IsHttpsUrl\s*\(\s*downloadUrl\s*\)') {
    throw 'The exact Visual C++ URL must be captured during acquire begin before the TLS hook runs.'
}
if ($acquireBeginSource -match 'ArmVisualCppHttpFallbackForWindows7') {
    throw 'Acquire begin must retain the candidate without arming it before Burn resolves the source.'
}
if ($acquireResolvingSource -notmatch
    '(?s)__super::OnCacheAcquireResolving\s*\(.*?ArmVisualCppHttpFallbackForWindows7\s*\(\s*packageOrContainerId\s*,\s*payloadId\s*,\s*\*action\s*\)') {
    throw 'The stored fallback must be armed from WiX''s resolved acquisition action without relying on its missing resolver URL.'
}
if ($acquireResolvingSource -match 'PrepareVisualCppHttpFallbackForWindows7' -or
    ([regex]::Matches($acquireResolvingSource, '\bdownloadUrl\b')).Count -ne 1) {
    throw 'Source resolution may forward WiX''s URL to its base implementation but must not inspect or retain it.'
}
$urlGuard = [regex]::Match($prepareSource,
    '(?s)if\s*\(\s*!StartsWithOrdinalIgnoreCase\s*\(\s*downloadUrl\s*,\s*kVisualCppDownloadHttpsPrefix\s*\)\s*\)')
$fallbackPrepared = $prepareSource.IndexOf(
    'visualCppHttpFallbackPrepared_ = true;', [StringComparison]::Ordinal)
$attemptedGuard = $prepareSource.IndexOf(
    'if (visualCppHttpFallbackAttempted_)', [StringComparison]::Ordinal)
$prepareReset = $prepareSource.IndexOf(
    'ResetVisualCppHttpFallback();', [StringComparison]::Ordinal)
if ($prepareSource -notmatch '(?s)!IsWindows7\(\).*?!IsSameOrdinalIgnoreCase\s*\(\s*packageOrContainerId\s*,\s*kVisualCppRuntimeId\s*\).*?!IsSameOrdinalIgnoreCase\s*\(\s*payloadId\s*,\s*kVisualCppRuntimeId\s*\)' -or
    $prepareSource -match 'BOOTSTRAPPER_CACHE_RESOLVE_DOWNLOAD' -or
    $prepareSource -match 'visualCppHttpFallbackArmed_\s*=\s*true' -or
    $attemptedGuard -lt 0 -or $prepareReset -le $attemptedGuard -or
    -not $urlGuard.Success -or $fallbackPrepared -lt 0 -or
    $urlGuard.Index -ge $fallbackPrepared) {
    throw 'Acquire begin must retain only an exact Microsoft Visual C++ HTTPS fallback candidate on Windows 7.'
}
if ($armSource -match 'downloadUrl|StartsWithOrdinalIgnoreCase|StringCch|ResetVisualCppHttpFallback' -or
    $armSource -notmatch '(?s)!IsWindows7\(\).*?visualCppHttpFallbackAttempted_.*?!IsSameOrdinalIgnoreCase\s*\(\s*packageOrContainerId\s*,\s*kVisualCppRuntimeId\s*\).*?!IsSameOrdinalIgnoreCase\s*\(\s*payloadId\s*,\s*kVisualCppRuntimeId\s*\).*?visualCppHttpFallbackArmed_\s*=\s*visualCppHttpFallbackPrepared_\s*&&\s*operation\s*==\s*BOOTSTRAPPER_CACHE_RESOLVE_DOWNLOAD') {
    throw 'Source resolution must combine the retained candidate with DOWNLOAD without reading WiX 6.0.2''s null resolver URL.'
}

$resetMatch = [regex]::Match($source,
    '(?s)void\s+ResetVisualCppHttpFallback\s*\(\s*\)\s*\{(.*?)\n\s*\}\s*\n\s*HRESULT\s+EnableTls12ForWindows7')
if (-not $resetMatch.Success -or
    $resetMatch.Groups[1].Value -notmatch '(?s)visualCppHttpFallbackPrepared_\s*=\s*false.*?visualCppHttpFallbackArmed_\s*=\s*false.*?visualCppHttpFallbackAttempted_\s*=\s*false.*?visualCppHttpFallbackUrl_\s*\[\s*0\s*\]\s*=\s*L''\\0''') {
    throw 'Reset must clear every retained, armed, attempted, and URL state value.'
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

Write-Output 'Validated the two-stage, final-attempt Windows 7 Visual C++ compatibility fallback.'
