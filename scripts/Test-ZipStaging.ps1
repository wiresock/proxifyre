#requires -Version 5.1
#requires -RunAsAdministrator

[CmdletBinding()]
param(
    [string]$PayloadDirectory = (Join-Path $PSScriptRoot '..\bin\exe\x64\Release')
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($PSVersionTable.PSEdition -ne 'Desktop') {
    throw 'Run this integration test in elevated Windows PowerShell 5.1.'
}
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$documentation = [IO.File]::ReadAllText((Join-Path $repositoryRoot 'docs\zip-staging.md'))
$match = [regex]::Match($documentation,
    '(?s)<!-- zip-staging-script -->\s*```powershell\r?\n(?<script>.*?)\r?\n```')
if (-not $match.Success) { throw 'The documented staging script was not found.' }

$programFiles = [Environment]::GetFolderPath('ProgramFiles')
$testId = [Guid]::NewGuid().ToString('N')
$testRoot = Join-Path $programFiles "ProxiFyre-ZipTest-$testId"
$destinationName = "ProxiFyre-StagingTest-$testId"
$destination = Join-Path $programFiles $destinationName
$badDestinationName = "ProxiFyre-BadZipTest-$testId"
$badDestination = Join-Path $programFiles $badDestinationName
$cleanupPaths = @($destination, $badDestination, $testRoot)
foreach ($path in $cleanupPaths) {
    if (Test-Path -LiteralPath $path) { throw "Test path already exists: $path" }
}

$security = [Security.AccessControl.DirectorySecurity]::new()
$security.SetSecurityDescriptorSddlForm(
    'O:BAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)')
[IO.Directory]::CreateDirectory($testRoot, $security) | Out-Null
try {
    $recipe = Join-Path $testRoot 'Stage-ProxiFyreZip.ps1'
    [IO.File]::WriteAllText($recipe, $match.Groups['script'].Value)
    $parseErrors = $null
    $tokens = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile($recipe, [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors.Count -ne 0) { throw 'The documented recipe has syntax errors.' }
    $preflight = $ast.Find({ param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq 'Assert-ProxiFyreStagingParent'
    }, $true)
    if ($null -eq $preflight) { throw 'The documented parent preflight was not found.' }
    . ([scriptblock]::Create($preflight.Extent.Text))
    # Never reuse the deliberately exposed probe directory for files we later load.
    $probeParent = Join-Path $testRoot 'acl-probe'
    [IO.Directory]::CreateDirectory($probeParent, $security) | Out-Null
    Assert-ProxiFyreStagingParent ([IO.DirectoryInfo]::new($probeParent))
    $originalParentAcl = Get-Acl -LiteralPath $probeParent
    $unsafeParentAcl = Get-Acl -LiteralPath $probeParent
    $users = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
    $unsafeParentAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $users, [Security.AccessControl.FileSystemRights]::CreateDirectories,
        [Security.AccessControl.AccessControlType]::Allow))
    Set-Acl -LiteralPath $probeParent -AclObject $unsafeParentAcl
    $rejected = $false
    try { Assert-ProxiFyreStagingParent ([IO.DirectoryInfo]::new($probeParent)) }
    catch {
        if ($_.Exception.Message -notlike '*Untrusted parent mutation permission*') { throw }
        $rejected = $true
    }
    if (-not $rejected) { throw 'The recipe permitted users to race destination creation.' }
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
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = Join-Path $testRoot 'payload.zip'
    [IO.Compression.ZipFile]::CreateFromDirectory($source, $zip)
    $hash = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash

    $rejected = $false
    try {
        & $recipe -ZipPath $zip -ExpectedSha256 ('0' * 64) -DestinationName $badDestinationName
    }
    catch {
        if ($_.Exception.Message -notlike '*SHA-256 mismatch*') { throw }
        $rejected = $true
    }
    if (-not $rejected -or (Test-Path -LiteralPath $badDestination)) {
        throw 'A checksum mismatch must fail before creating the destination.'
    }

    & $recipe -ZipPath $zip -ExpectedSha256 $hash -DestinationName $destinationName
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
    $user = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $userOwned = Get-Acl -LiteralPath $enginePath
    $userOwned.SetOwner($user)
    Set-Acl -LiteralPath $enginePath -AclObject $userOwned
    Assert-PayloadPolicy -Rejection Location
    Set-Acl -LiteralPath $enginePath -AclObject $originalFileAcl

    $originalDirectoryAcl = Get-Acl -LiteralPath $destination
    $userWritable = Get-Acl -LiteralPath $destination
    $userWritable.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $user, [Security.AccessControl.FileSystemRights]::Write,
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
    $rejected = $false
    try { & $recipe -ZipPath $zip -ExpectedSha256 $hash -DestinationName $destinationName }
    catch {
        if ($_.Exception.Message -notlike '*Destination already exists*') { throw }
        $rejected = $true
    }
    if (-not $rejected -or [IO.File]::ReadAllText($marker) -ne 'do not replace') {
        throw 'An existing destination must be refused without overwriting it.'
    }
    Write-Output 'PASS: documented ZIP staging, recursive ownership, payload policies, checksum and overwrite rejection.'
}
finally {
    foreach ($path in $cleanupPaths) {
        if (-not (Test-Path -LiteralPath $path)) { continue }
        $resolved = (Resolve-Path -LiteralPath $path).Path
        if ((Split-Path -Parent $resolved) -ne $programFiles -or
            (Split-Path -Leaf $resolved) -notmatch ('^ProxiFyre-(ZipTest|StagingTest|BadZipTest)-' + $testId + '$') -or
            ((Get-Item -LiteralPath $resolved).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw "Refusing to remove unexpected test path: $resolved"
        }
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
