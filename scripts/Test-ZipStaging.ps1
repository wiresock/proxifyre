#requires -Version 5.1
#requires -RunAsAdministrator

[CmdletBinding()]
param(
    [string]$PayloadDirectory
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($PSVersionTable.PSEdition -ne 'Desktop') {
    throw 'Run this integration test in elevated Windows PowerShell 5.1.'
}
if ([string]::IsNullOrWhiteSpace($PayloadDirectory)) {
    $PayloadDirectory = Join-Path $PSScriptRoot '..\bin\exe\x64\Release'
}
$user = [Security.Principal.WindowsIdentity]::GetCurrent().User
if ($user.Value -in @('S-1-5-18', 'S-1-5-32-544',
        'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')) {
    throw 'Run this test as an elevated individual administrator, not a trusted machine identity such as SYSTEM.'
}
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$documentation = [IO.File]::ReadAllText((Join-Path $repositoryRoot 'docs\zip-staging.md'))
$match = [regex]::Match($documentation,
    '(?s)<!-- zip-staging-script -->\s*```powershell\r?\n(?<script>.*?)\r?\n```')
if (-not $match.Success) { throw 'The documented staging script was not found.' }

# Parse trusted repository text in memory, before writing or loading any fixture.
$parseErrors = $null
$tokens = $null
$ast = [Management.Automation.Language.Parser]::ParseInput(
    $match.Groups['script'].Value, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -ne 0) { throw 'The documented recipe has syntax errors.' }
$preflight = $ast.Find({ param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Assert-ProxiFyreStagingParent'
}, $true)
if ($null -eq $preflight) { throw 'The documented parent preflight was not found.' }
. ([scriptblock]::Create($preflight.Extent.Text))
function New-ProtectedTestRoot([IO.DirectoryInfo]$Parent, [string]$Name,
        [Security.AccessControl.DirectorySecurity]$Security) {
    Assert-ProxiFyreStagingParent $Parent
    $path = Join-Path $Parent.FullName $Name
    if (Test-Path -LiteralPath $path) { throw "Test path already exists: $path" }
    [IO.Directory]::CreateDirectory($path, $Security) | Out-Null
}

$programFiles = [Environment]::GetFolderPath('ProgramFiles')
$testId = [Guid]::NewGuid().ToString('N')
$testRoot = Join-Path $programFiles "ProxiFyre-ZipTest-$testId"
$destinationName = "ProxiFyre-StagingTest-$testId"
$destination = Join-Path $programFiles $destinationName
$badDestinationName = "ProxiFyre-BadZipTest-$testId"
$badDestination = Join-Path $programFiles $badDestinationName
$duplicateDestinationName = "ProxiFyre-DuplicateZipTest-$testId"
$duplicateDestination = Join-Path $programFiles $duplicateDestinationName
$raceDestinationName = "ProxiFyre-RaceTest-$testId"
$raceDestination = Join-Path $programFiles $raceDestinationName
$cleanupPaths = @($destination, $badDestination, $duplicateDestination, $raceDestination, $testRoot)
foreach ($path in $cleanupPaths) {
    if (Test-Path -LiteralPath $path) { throw "Test path already exists: $path" }
}

$security = [Security.AccessControl.DirectorySecurity]::new()
$security.SetSecurityDescriptorSddlForm(
    'O:BAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)(A;OICI;RC;;;OW)')
New-ProtectedTestRoot ([IO.DirectoryInfo]::new($programFiles)) (Split-Path -Leaf $testRoot) $security
try {
    $recipe = Join-Path $testRoot 'Stage-ProxiFyreZip.ps1'
    [IO.File]::WriteAllText($recipe, $match.Groups['script'].Value)
    # Never reuse the deliberately exposed probe directory for files we later load.
    $probeParent = Join-Path $testRoot 'acl-probe'
    [IO.Directory]::CreateDirectory($probeParent, $security) | Out-Null
    Assert-ProxiFyreStagingParent ([IO.DirectoryInfo]::new($probeParent))
    $originalParentAcl = Get-Acl -LiteralPath $probeParent
    $unsafeParentAcl = Get-Acl -LiteralPath $probeParent
    $users = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
    $unsafeParentAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $users, ([Security.AccessControl.FileSystemRights]::CreateDirectories -bor
            [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles),
        [Security.AccessControl.AccessControlType]::Allow))
    Set-Acl -LiteralPath $probeParent -AclObject $unsafeParentAcl
    $rejected = $false
    try { New-ProtectedTestRoot ([IO.DirectoryInfo]::new($probeParent)) 'must-not-exist' $security }
    catch {
        if ($_.Exception.Message -notlike '*Untrusted parent mutation permission*') { throw }
        $rejected = $true
    }
    if (-not $rejected -or (Test-Path -LiteralPath (Join-Path $probeParent 'must-not-exist'))) {
        throw 'Unsafe parents must be rejected before any fixture directory or script is written.'
    }
    Set-Acl -LiteralPath $probeParent -AclObject $originalParentAcl
    Assert-ProxiFyreStagingParent ([IO.DirectoryInfo]::new($probeParent))

    $source = Join-Path $testRoot 'source'
    [IO.Directory]::CreateDirectory($source) | Out-Null
    $payloadNames = @(
        'ProxiFyre.exe', 'ProxiFyre.exe.config', 'ProxiFyreUI.exe',
        'ProxiFyreUI.exe.config', 'ProxiFyreUI.Managed.dll',
        'ProxiFyre.Configuration.dll', 'socksify.dll', 'Newtonsoft.Json.dll',
        'NLog.dll', 'Topshelf.dll', 'NLog.config', 'app-config.sample.json'
    )
    foreach ($name in $payloadNames) {
        Copy-Item -LiteralPath (Join-Path $PayloadDirectory $name) -Destination $source
    }
    # Include a nested non-executable file to check recursive ownership assignment.
    [IO.Directory]::CreateDirectory((Join-Path $source 'notes')) | Out-Null
    [IO.File]::WriteAllText((Join-Path $source 'notes\example.txt'), 'nested archive entry')
    Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
    $zip = Join-Path $testRoot 'payload.zip'
    [IO.Compression.ZipFile]::CreateFromDirectory($source, $zip)
    $hash = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash

    function Invoke-Recipe([string]$ArchivePath, [string]$ExpectedHash,
            [string]$Name, [string]$ExpectedFailure = '', [string]$ScriptPath = $recipe) {
        # Each execution starts with fresh assembly/type state, including failures.
        $savedPreference = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            $output = & "$PSHOME\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass `
                -File $ScriptPath -ZipPath $ArchivePath -ExpectedSha256 $ExpectedHash -DestinationName $Name 2>&1
            $exitCode = $LASTEXITCODE
        }
        finally { $ErrorActionPreference = $savedPreference }
        if ($ExpectedFailure) {
            if ($exitCode -eq 0 -or ($output | Out-String) -notlike "*$ExpectedFailure*") {
                throw "Expected '$ExpectedFailure', got exit ${exitCode}: $output"
            }
        }
        elseif ($exitCode -ne 0) { throw "Recipe failed with exit ${exitCode}: $output" }
        return ($output | Out-String)
    }
    Invoke-Recipe $zip ('0' * 64) $badDestinationName 'SHA-256 mismatch' | Out-Null
    if (Test-Path -LiteralPath $badDestination) {
        throw 'A checksum mismatch must fail before creating the destination.'
    }

    Invoke-Recipe $zip $hash $destinationName | Out-Null
    Add-Type -Path (Join-Path $PSScriptRoot 'ZipStagingOwnerProbe.cs')
    [ZipStagingOwnerProbe]::AssertProtected($destination)
    Write-Output 'PASS: same-user unprivileged file/directory mutations denied before owner normalization.'
    foreach ($entry in @((Get-Item -LiteralPath $destination)) +
            @(Get-ChildItem -LiteralPath $destination -Recurse -Force)) {
        $acl = Get-Acl -LiteralPath $entry.FullName
        if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne 'S-1-5-32-544') {
            throw "Untrusted staged owner: $($entry.FullName)"
        }
    }
    foreach ($name in $payloadNames) {
        if ((Get-FileHash -LiteralPath (Join-Path $destination $name)).Hash -ne
                (Get-FileHash -LiteralPath (Join-Path $source $name)).Hash) {
            throw "Staging changed payload bytes: $name"
        }
    }

    # Use a child so the CLR releases its assembly file handles before mutations/cleanup.
    $validator = Join-Path $testRoot 'Validate-Payload.ps1'
    [IO.File]::WriteAllText($validator, @'
param([string]$Directory, [string]$ValidationDirectory,
    [ValidateSet('None','Location','Integrity')][string]$Rejection = 'None')
$ErrorActionPreference = 'Stop'
# Load validation code only from the continuously protected source, never the
# payload whose ownership/ACLs this test deliberately makes unsafe.
Add-Type -Path (Join-Path $ValidationDirectory 'ProxiFyre.Configuration.dll')
$ui = [Reflection.Assembly]::LoadFrom((Join-Path $ValidationDirectory 'ProxiFyreUI.Managed.dll'))
$engine = Join-Path $Directory 'ProxiFyre.exe'
$reason = ''
$locationAccepted = [ProxiFyre.Configuration.ServiceInstallLocationPolicy]::IsProtected($engine, [ref]$reason)
$engineValidator = $ui.GetType('ProxiFyreUI.Infrastructure.EngineExecutableValidator', $true)
$integrityAccepted = $engineValidator.GetMethod('IsTrusted').Invoke($null, [object[]]@([string]$engine))
if ($Rejection -eq 'Location') {
    if ($locationAccepted) { throw 'The existing location policy accepted unsafe ownership/ACLs.' }
} elseif ($Rejection -eq 'Integrity') {
    if ($integrityAccepted) { throw 'The existing integrity policy accepted modified NLog.config.' }
} else {
    if (-not $locationAccepted) { throw "Location policy rejected the staged payload: $reason" }
    if (-not $integrityAccepted) { throw 'Engine integrity policy rejected the staged payload.' }
    $startup = $ui.GetType('ProxiFyreUI.Infrastructure.UiStartupPayload', $true)
    $lease = $startup.GetMethod('Acquire').Invoke($null,
        [object[]]@([string](Join-Path $Directory 'ProxiFyreUI.Managed.dll')))
    $lease.Dispose()
}
'@)
    function Assert-PayloadPolicy([string]$Rejection = 'None') {
        & "$PSHOME\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass `
            -File $validator -Directory $destination -ValidationDirectory $source -Rejection $Rejection
        if ($LASTEXITCODE -ne 0) { throw "Payload policy check failed ($Rejection)." }
    }
    Assert-PayloadPolicy

    $enginePath = Join-Path $destination 'ProxiFyre.exe'
    $originalFileAcl = Get-Acl -LiteralPath $enginePath
    $userOwned = Get-Acl -LiteralPath $enginePath
    $userOwned.SetOwner($user)
    Set-Acl -LiteralPath $enginePath -AclObject $userOwned
    Assert-PayloadPolicy -Rejection Location
    Set-Acl -LiteralPath $enginePath -AclObject $originalFileAcl

    $originalDirectoryAcl = Get-Acl -LiteralPath $destination
    $userWritable = Get-Acl -LiteralPath $destination
    $userWritable.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $users, [Security.AccessControl.FileSystemRights]::Write,
        [Security.AccessControl.AccessControlType]::Allow))
    Set-Acl -LiteralPath $destination -AclObject $userWritable
    Assert-PayloadPolicy -Rejection Location
    Set-Acl -LiteralPath $destination -AclObject $originalDirectoryAcl

    $loggingConfig = Join-Path $destination 'NLog.config'
    [IO.File]::AppendAllText($loggingConfig, '<!-- changed -->')
    Assert-PayloadPolicy -Rejection Integrity
    Copy-Item -LiteralPath (Join-Path $source 'NLog.config') -Destination $loggingConfig -Force
    Assert-PayloadPolicy

    $marker = Join-Path $destination 'existing-installation.txt'
    [IO.File]::WriteAllText($marker, 'do not replace')
    Invoke-Recipe $zip $hash $destinationName 'Destination already exists' | Out-Null
    if ([IO.File]::ReadAllText($marker) -ne 'do not replace') {
        throw 'An existing destination must be refused without overwriting it.'
    }

    $duplicateZip = Join-Path $testRoot 'duplicate.zip'
    $duplicateArchive = [IO.Compression.ZipFile]::Open($duplicateZip, [IO.Compression.ZipArchiveMode]::Create)
    try {
        $duplicateArchive.CreateEntry('duplicate.txt') | Out-Null
        $duplicateArchive.CreateEntry('duplicate.txt') | Out-Null
    }
    finally { $duplicateArchive.Dispose() }
    $duplicateOutput = Invoke-Recipe $duplicateZip (Get-FileHash -LiteralPath $duplicateZip).Hash `
        $duplicateDestinationName 'already exists'
    if ($duplicateOutput -notlike '*ExtractToDirectory*' -or
        $duplicateOutput -like '*Destination already exists*') {
        throw 'Duplicate entries must fail during extraction, not the destination preflight.'
    }
    if (Test-Path -LiteralPath $duplicateDestination) {
        throw 'Failed extraction must remove the partial destination.'
    }

    # Deterministically let another elevated run create the destination after
    # the existence check. Matching ACLs must not make its files ours to delete.
    $raceWrapper = Join-Path $testRoot 'Race-StageProxiFyreZip.ps1'
    [IO.File]::WriteAllText($raceWrapper, @'
param([string]$ZipPath, [string]$ExpectedSha256, [string]$DestinationName)
$ErrorActionPreference = 'Stop'
# Process-scoped state stays visible when the recipe invokes our hook from
# its own script scope. This wrapper always runs in an isolated child process.
$global:ProxiFyreRacePath = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) $DestinationName
$global:ProxiFyreRaceInjected = $false
function Test-Path([string]$LiteralPath) {
    $exists = Microsoft.PowerShell.Management\Test-Path -LiteralPath $LiteralPath
    if ($LiteralPath -eq $global:ProxiFyreRacePath -and -not $global:ProxiFyreRaceInjected) {
        if ($exists) { throw 'Race fixture must initially be absent.' }
        $security = [Security.AccessControl.DirectorySecurity]::new()
        $security.SetSecurityDescriptorSddlForm(
            'O:BAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)(A;OICI;RC;;;OW)')
        [IO.Directory]::CreateDirectory($LiteralPath, $security) | Out-Null
        [IO.File]::WriteAllText((Join-Path $LiteralPath 'other-run.txt'), 'preserve other run')
        $global:ProxiFyreRaceInjected = $true
    }
    return $exists
}
try {
    & (Join-Path $PSScriptRoot 'Stage-ProxiFyreZip.ps1') -ZipPath $ZipPath `
        -ExpectedSha256 $ExpectedSha256 -DestinationName $DestinationName
}
finally {
    if (-not $global:ProxiFyreRaceInjected) { throw 'The concurrent-creation hook did not run.' }
}
'@)
    $raceOutput = Invoke-Recipe $duplicateZip (Get-FileHash -LiteralPath $duplicateZip).Hash `
        $raceDestinationName 'already exists' $raceWrapper
    $raceMarker = Join-Path $raceDestination 'other-run.txt'
    if (-not (Test-Path -LiteralPath $raceMarker)) {
        throw 'A destination created by another run must survive failed staging.'
    }
    if ($raceOutput -notlike '*Destination already exists*' -or
        [IO.File]::ReadAllText($raceMarker) -ne 'preserve other run' -or
        @(Get-ChildItem -LiteralPath $raceDestination -Force).Count -ne 1) {
        throw 'A concurrent destination must be refused before extracting or changing its files.'
    }
    Write-Output 'PASS: concurrent destination with identical ACLs preserved without extraction.'
    Write-Output 'PASS: documented ZIP staging, recursive ownership, payload policies, checksum and overwrite rejection.'
}
catch {
    # Preserve the original failure in the transcript if cleanup also fails.
    Write-Output $_.Exception.ToString()
    throw
}
finally {
    foreach ($path in $cleanupPaths) {
        if (-not (Test-Path -LiteralPath $path)) { continue }
        $resolved = (Resolve-Path -LiteralPath $path).Path
        if ((Split-Path -Parent $resolved) -ne $programFiles -or
            (Split-Path -Leaf $resolved) -notmatch ('^ProxiFyre-(ZipTest|StagingTest|BadZipTest|DuplicateZipTest|RaceTest)-' + $testId + '$') -or
            ((Get-Item -LiteralPath $resolved).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw "Refusing to remove unexpected test path: $resolved"
        }
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}

# Expected negative cases leave a nonzero native exit code. Report success only
# after all assertions and cleanup finish; GitHub Actions propagates this code.
exit 0
