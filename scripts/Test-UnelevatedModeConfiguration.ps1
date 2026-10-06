#requires -Version 7.0

[CmdletBinding()]
param(
    [ValidateSet('x86', 'x64', 'ARM64')]
    [string]$Platform = 'x64',

    [switch]$RunCommandLineSmokeTest
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repositoryRoot = Split-Path -Parent $PSScriptRoot

function Read-RepositorySource([string]$RelativePath) {
    return [IO.File]::ReadAllText((Join-Path $repositoryRoot $RelativePath))
}

function Assert-ContainsOrdinal(
    [string]$Source,
    [string]$Fragment,
    [string]$Description) {
    if (-not $Source.Contains($Fragment, [StringComparison]::Ordinal)) {
        throw "$Description is missing '$Fragment'."
    }
}

function Test-ByteSequence([byte[]]$Bytes, [byte[]]$Sequence) {
    if ($Sequence.Length -eq 0 -or $Bytes.Length -lt $Sequence.Length) {
        return $false
    }

    for ($offset = 0; $offset -le $Bytes.Length - $Sequence.Length; $offset++) {
        if ($Bytes[$offset] -ne $Sequence[0]) {
            continue
        }

        $matches = $true
        for ($index = 1; $index -lt $Sequence.Length; $index++) {
            if ($Bytes[$offset + $index] -ne $Sequence[$index]) {
                $matches = $false
                break
            }
        }

        if ($matches) {
            return $true
        }
    }

    return $false
}

function Assert-PeContainsString(
    [byte[]]$Bytes,
    [string]$Value,
    [string]$Description) {
    $utf8 = [Text.Encoding]::UTF8.GetBytes($Value)
    $utf16 = [Text.Encoding]::Unicode.GetBytes($Value)
    if (-not (Test-ByteSequence $Bytes $utf8) -and
        -not (Test-ByteSequence $Bytes $utf16)) {
        throw "$Description does not contain '$Value'."
    }
}

$policySource = Read-RepositorySource 'ProxiFyre.Configuration\EngineCommandLinePolicy.cs'
$programSource = Read-RepositorySource 'ProxiFyre\Program.cs'
$processLookupSource = Read-RepositorySource 'netlib\src\iphelper\process_lookup.h'
$routingPolicySource = Read-RepositorySource 'netlib\src\proxy\process_routing_policy.h'
$routerSource = Read-RepositorySource 'netlib\src\proxy\socks_local_router.h'
$managedBridgeSource = Read-RepositorySource 'socksify\Socksifier.cpp'
$unmanagedBridgeSource = Read-RepositorySource 'socksify\socksify_unmanaged.cpp'

Assert-ContainsOrdinal $policySource `
    'public const string AllowNotAdministratorSwitch = "--allow-not-admin";' `
    'The managed command-line policy'
Assert-ContainsOrdinal $policySource `
    'StringComparison.Ordinal' `
    'The case-sensitive opt-in policy'
Assert-ContainsOrdinal $programSource `
    'x.ApplyCommandLine(BuildTopshelfCommandLine(arguments))' `
    'The sanitized Topshelf command-line application'
Assert-ContainsOrdinal $programSource `
    'EngineCommandLinePolicy.AllowNotAdministratorSwitch' `
    'The exact switch removal before Topshelf parsing'
Assert-ContainsOrdinal $programSource `
    'GetInstance(_logLevel, _useLimitedMode)' `
    'The managed limited-mode propagation'
Assert-ContainsOrdinal $managedBridgeSource `
    'bypassUnresolvedProcesses);' `
    'The C++/CLI limited-mode propagation'
Assert-ContainsOrdinal $managedBridgeSource `
    'instance_->bypass_unresolved_processes_ != bypassUnresolvedProcesses' `
    'The C++/CLI singleton policy mismatch guard'
Assert-ContainsOrdinal $unmanagedBridgeSource `
    'bypass_unresolved_processes' `
    'The unmanaged limited-mode propagation'
Assert-ContainsOrdinal $unmanagedBridgeSource `
    'inst.bypass_unresolved_processes_ != bypass_unresolved_processes' `
    'The unmanaged singleton policy mismatch guard'

if (-not [regex]::IsMatch($processLookupSource,
        'default_process_\s*=\s*std::make_shared<network_process>\(' +
        '\s*0,\s*L"SYSTEM",\s*L"SYSTEM",\s*false\s*\)',
        [Text.RegularExpressions.RegexOptions]::Singleline)) {
    throw 'The synthetic unresolved process must be constructed with resolved=false.'
}

foreach ($assertion in @(
    'static_assert(!should_bypass_unresolved_process(false, false)',
    'static_assert(!should_bypass_unresolved_process(false, true)',
    'static_assert(should_bypass_unresolved_process(true, false)',
    'static_assert(!should_bypass_unresolved_process(true, true)'
)) {
    Assert-ContainsOrdinal $routingPolicySource $assertion 'The native routing-policy truth table'
}

# Application matching lives in match_owner_to_app (process_routing_policy.h). Within that
# function, the unresolved-owner guard must return before the empty catch-all pattern matches.
$matchFunctionMatch = [regex]::Match($routingPolicySource,
    '\[\[nodiscard\]\]\s+inline\s+bool\s+match_owner_to_app\(.*?^    \}',
    [Text.RegularExpressions.RegexOptions]::Singleline -bor
        [Text.RegularExpressions.RegexOptions]::Multiline)
if (-not $matchFunctionMatch.Success) {
    throw 'The native application matching function match_owner_to_app was not found.'
}
$matchFunction = $matchFunctionMatch.Value
$guardMatch = [regex]::Match($matchFunction,
    'if\s*\(\s*should_bypass_unresolved_process\(\s*rules\.bypass_unresolved_processes,\s*' +
    'process\.resolved\s*\)\s*\)\s*return\s+false;')
$catchAllOffset = $matchFunction.IndexOf('if (app.empty())', [StringComparison]::Ordinal)
if (-not $guardMatch.Success -or $catchAllOffset -lt 0 -or $guardMatch.Index -ge $catchAllOffset) {
    throw 'The unresolved-owner fail-direct guard must run before catch-all application matching.'
}

# Proxy selection matches through that function, and the router routes through the selection
# with its own limited-mode flag in the rules (third member of owner_match_rules).
Assert-ContainsOrdinal $routingPolicySource `
    'if (match_owner_to_app(process_pattern, process, rules))' `
    'The native proxy selection'
if (-not [regex]::IsMatch($routingPolicySource,
        'struct\s+owner_match_rules\s*\{\s*' +
        'const\s+std::multimap<size_t,\s*std::wstring>&\s+proxy_to_names;[^\n]*\n\s*' +
        'const\s+std::vector<std::wstring>&\s+excluded_list;[^\n]*\n\s*' +
        'bool\s+bypass_unresolved_processes;')) {
    throw 'owner_match_rules must carry the limited-mode flag after the name and exclusion lists.'
}
if (-not [regex]::IsMatch($routerSource,
        'owner_match_rules\s+match_rules\(\)\s+const\s+noexcept\s*\{\s*' +
        'return\s*\{\s*proxy_to_names_,\s*excluded_list_,\s*bypass_unresolved_processes_,')) {
    throw 'The router must propagate its limited-mode flag into the application matching rules.'
}
Assert-ContainsOrdinal $routerSource `
    'select_proxy_port(match_rules(), *process,' `
    'The router proxy selection'
if ($routerSource.Contains('if (app.empty())', [StringComparison]::Ordinal)) {
    throw 'The router must not keep catch-all application matching outside match_owner_to_app.'
}

$enginePath = Join-Path $repositoryRoot "bin\exe\$Platform\Release\ProxiFyre.exe"
if (-not (Test-Path -LiteralPath $enginePath -PathType Leaf)) {
    throw "The built $Platform Release engine was not found at '$enginePath'."
}

$engineBytes = [IO.File]::ReadAllBytes($enginePath)
Assert-PeContainsString $engineBytes '--allow-not-admin' 'The built engine'
Assert-PeContainsString $engineBytes `
    'explicitly enabled non-administrator mode' `
    'The built engine safety warning'

if ($RunCommandLineSmokeTest) {
    if ($Platform -cne 'x64') {
        throw 'The command-line smoke test is supported only for the native x64 CI host.'
    }

    $helpOutput = & $enginePath '--allow-not-admin' '--help' 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) {
        throw "Topshelf rejected the opt-in help invocation with exit code $LASTEXITCODE. $helpOutput"
    }

    $customCommandOutput =
        & $enginePath '--allow-not-admin' 'command' '127' 2>&1 | Out-String
    if ($LASTEXITCODE -ne 87) {
        throw ('The opt-in switch reached Topshelf service control; expected ' +
            "ERROR_INVALID_PARAMETER (87), got $LASTEXITCODE. $customCommandOutput")
    }

    # Keep the executable smoke safe if this policy regresses: the unknown trailing option
    # makes Topshelf validation fail before ConsoleRunHost can start the packet engine.
    $conflictingOutput =
        & $enginePath 'run' 'stop' 'run' '--policy-regression-guard' 2>&1 | Out-String
    if ($LASTEXITCODE -ne 87) {
        throw ('Conflicting Topshelf verbs bypassed the privilege policy; expected ' +
            "ERROR_INVALID_PARAMETER (87), got $LASTEXITCODE. $conflictingOutput")
    }
    if (-not $conflictingOutput.Contains(
            'run, install, uninstall, start, stop, or command',
            [StringComparison]::Ordinal)) {
        throw "The conflicting-command diagnostic omits a supported verb. $conflictingOutput"
    }

    $invalidOutput = & $enginePath 'install' '--allow-not-admin' 2>&1 | Out-String
    if ($LASTEXITCODE -ne 87) {
        throw ('The opt-in switch reached a service lifecycle command; expected ' +
            "ERROR_INVALID_PARAMETER (87), got $LASTEXITCODE. $invalidOutput")
    }

    # GitHub Actions' PowerShell wrapper propagates a nonzero native LASTEXITCODE even
    # when it was the expected result under test.
    $global:LASTEXITCODE = 0
}

Write-Output (
    "Validated the $Platform limited-mode policy, native fail-direct routing guard, " +
    'managed/native propagation, and built engine metadata.')
