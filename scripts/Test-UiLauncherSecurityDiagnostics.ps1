#requires -Version 7.0

[CmdletBinding()]
param(
    [ValidateSet('x86', 'x64', 'ARM64')]
    [string]$Platform = 'x64'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$sourcePath = Join-Path $repositoryRoot 'ProxiFyreUILauncher\Program.cpp'
$launcherPath = Join-Path $repositoryRoot (
    "bin\exe\$Platform\Release\ProxiFyreUI.exe")

$source = [IO.File]::ReadAllText($sourcePath)
$requiredSourceFragments = @(
    'ConvertSidToStringSidW(identity, &value)',
    'Rejected path: ',
    'Trustee SID: ',
    'ACE mask: ',
    'Prohibited rights: ',
    'ACE origin: ',
    'FormatSid(identity)',
    'FormatAccessMask(mask & dangerousRights)',
    '(header->AceFlags & INHERITED_ACE) != 0',
    'ShowPayloadVerificationFailure(verificationFailure);'
)
foreach ($fragment in $requiredSourceFragments) {
    if (-not $source.Contains($fragment, [StringComparison]::Ordinal)) {
        throw "The native launcher security diagnostic is missing '$fragment'."
    }
}

$requiredPropagationPatterns = [ordered]@{
    'file ACL rejection detail' =
        'HasProtectedSecurity\(handle,\s*path,\s*kPayloadDangerousRights,\s*false,\s*failureReason\)'
    'directory ACL rejection detail' =
        'HasProtectedSecurity\(handle,\s*path,\s*dangerousRights,\s*isPayloadDirectory,\s*failureReason\)'
    'directory-chain rejection detail' =
        'leases\.OpenDirectoryChain\(directory,\s*failureReason\)'
    'launcher-file rejection detail' =
        'leases\.Open\(executablePath,\s*launcherHandle,\s*failureReason\)'
    'managed-file rejection detail' =
        'leases\.Open\(path,\s*handle,\s*failureReason\)'
    'configuration-file rejection detail' =
        'leases\.Open\(configuration,\s*configurationHandle,\s*failureReason\)'
    'final verification detail' =
        'VerifyAndLeasePayload\(executablePath,\s*directory,\s*leases,\s*managedAssembly,\s*verificationFailure\)'
}
foreach ($entry in $requiredPropagationPatterns.GetEnumerator()) {
    if (-not [regex]::IsMatch($source, $entry.Value,
            [Text.RegularExpressions.RegexOptions]::Singleline)) {
        throw "The native launcher no longer propagates $($entry.Key)."
    }
}

$dangerousAceMatch = [regex]::Match($source,
    'if\s*\(identity\s*!=\s*nullptr\s*&&\s*\(mask\s*&\s*dangerousRights\)\s*!=\s*0\s*&&' +
    '\s*!IsTrustedMachineIdentity\(identity\)\)\s*\{(?<body>.*?)\s*break;\s*\}',
    [Text.RegularExpressions.RegexOptions]::Singleline)
if (-not $dangerousAceMatch.Success) {
    throw 'The untrusted dangerous-ACE rejection block was not found.'
}
foreach ($fragment in @(
    'RejectedPathPrefix(path)',
    'Trustee SID: ',
    'FormatSid(identity)',
    'ACE mask: ',
    'FormatAccessMask(mask)',
    'Prohibited rights: ',
    'FormatAccessMask(mask & dangerousRights)',
    'ACE origin: ',
    'INHERITED_ACE'
)) {
    if (-not $dangerousAceMatch.Groups['body'].Value.Contains(
            $fragment, [StringComparison]::Ordinal)) {
        throw "The dangerous-ACE diagnostic block is missing '$fragment'."
    }
}

$ancestorPolicyMatch = [regex]::Match($source,
    'kAncestorDangerousRights\s*=\s*(?<expression>.*?);',
    [Text.RegularExpressions.RegexOptions]::Singleline)
if (-not $ancestorPolicyMatch.Success) {
    throw 'The native ancestor security policy was not found.'
}
$expectedAncestorRights = [ordered]@{
    GENERIC_ALL       = [uint32]0x10000000
    GENERIC_WRITE     = [uint32]0x40000000
    DELETE            = [uint32]0x00010000
    WRITE_DAC         = [uint32]0x00040000
    WRITE_OWNER       = [uint32]0x00080000
    FILE_DELETE_CHILD = [uint32]0x00000040
}
$ancestorDangerousRights = [uint32]0
foreach ($entry in $expectedAncestorRights.GetEnumerator()) {
    if ($ancestorPolicyMatch.Groups['expression'].Value -notmatch
        ('\b' + [regex]::Escape($entry.Key) + '\b')) {
        throw "The native ancestor security policy no longer includes $($entry.Key)."
    }
    $ancestorDangerousRights = $ancestorDangerousRights -bor $entry.Value
}

# Reproduce the effective Program Files ACE reported in issue #169. It applies to the
# directory itself (no inherit-only flag), is inherited, and intersects the launcher's
# ancestor policy only through DELETE.
$reportedSddl =
    'O:SYG:SYD:(A;OICIID;FA;;;BA)(A;OICIID;FA;;;SY)' +
    '(A;OICIID;0x1200a9;;;BU)(A;ID;0x1301bf;;;AU)' +
    '(A;OICIIOID;SDGXGWGR;;;AU)'
$descriptor = [Security.AccessControl.RawSecurityDescriptor]::new($reportedSddl)
$reportedAce = $null
for ($index = 0; $index -lt $descriptor.DiscretionaryAcl.Count; $index++) {
    $candidate = $descriptor.DiscretionaryAcl[$index]
    if ($candidate -is [Security.AccessControl.CommonAce] -and
        $candidate.AceQualifier -eq [Security.AccessControl.AceQualifier]::AccessAllowed -and
        $candidate.SecurityIdentifier.Value -ceq 'S-1-5-11' -and
        [uint32]$candidate.AccessMask -eq [uint32]0x001301bf -and
        ($candidate.AceFlags -band [Security.AccessControl.AceFlags]::InheritOnly) -eq 0) {
        $reportedAce = $candidate
        break
    }
}
if ($null -eq $reportedAce) {
    throw 'The issue #169 Authenticated Users ACE could not be reconstructed.'
}
if (($reportedAce.AceFlags -band [Security.AccessControl.AceFlags]::Inherited) -eq 0) {
    throw 'The issue #169 ACE must remain classified as inherited.'
}

$prohibitedRights = [uint32]$reportedAce.AccessMask -band $ancestorDangerousRights
if ($prohibitedRights -ne [uint32]0x00010000) {
    throw ('The issue #169 ACE must intersect the ancestor policy through DELETE only; ' +
        ('actual intersection: 0x{0:X8}.' -f $prohibitedRights))
}

if (-not (Test-Path -LiteralPath $launcherPath -PathType Leaf)) {
    throw "The built native launcher was not found at '$launcherPath'."
}
$launcherText = [Text.Encoding]::Unicode.GetString(
    [IO.File]::ReadAllBytes($launcherPath))
foreach ($label in @(
    'Rejected path:',
    'Trustee SID:',
    'ACE mask:',
    'Prohibited rights:',
    'ACE origin:',
    'DELETE',
    'inherited'
)) {
    if (-not $launcherText.Contains($label, [StringComparison]::Ordinal)) {
        throw "The built native launcher is missing diagnostic label '$label'."
    }
}

Write-Output (
    "Validated the $Platform Release launcher diagnostic for issue #169: " +
    'S-1-5-11, ACE 0x001301BF, prohibited 0x00010000 (DELETE), inherited.')
