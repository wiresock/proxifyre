# Manually staging a Release ZIP

The ZIP contains the application payload. Install the architecture-matched .NET Framework, Visual C++ runtime, and Windows Packet Filter first; see the [installer prerequisites](installer.md). Setup remains the recommended deployment method. ZIP staging does not create shortcuts, firewall rules, or a service registration. After staging, open `ProxiFyreUI.exe`, configure the engine, and use **Install Service** if needed.

## Ownership and permissions

A Release GUI can run from a non-default directory on a directly mounted fixed local volume. The launcher checks the whole directory chain, including the volume root, and the required payload files. It rejects reparse points, user-controlled paths, unexpected executable modules, and modified pinned configuration files. A directory under `Program Files` is not automatically trusted.

Accepted owners are `SYSTEM` (`S-1-5-18`), the built-in **Administrators group** (`S-1-5-32-544`), and `TrustedInstaller` (`S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464`). An individual administrator's account SID is not an accepted owner. Elevating the launcher does not change file ownership. `icacls /reset` resets inherited permissions; it does not set the owner.

Use the same application-directory policy as the MSI: Administrators own the directory; SYSTEM and Administrators have full control; Users have read/execute access. The recipe also adds an inheritable **OWNER RIGHTS** read-control ACE. This suppresses the owner's implicit permission to change the DACL, protecting new files and subdirectories even when their initial owner is the extracting account. The final ownership pass then sets Administrators as owner throughout. Without that ACE, another unelevated process running as the extracting user could grant itself write access before ownership is changed. Files and subdirectories must satisfy both the permissions and trusted-owner checks. The parent chain must not grant other identities delete, delete-child, generic write/all, or permission/ownership-control access.

Always create a fresh protected destination **before** extracting. Do not move an existing user-owned extraction into place or tighten its permissions afterward: another process could retain a previously opened mutation handle. Do not recursively reset permissions or take ownership of `Program Files` or a drive root. If a parent fails validation, have its administrator restore the correct Windows or organizational baseline.

## Copyable staging procedure

Download the architecture-matched application ZIP and its `.sha256` sidecar from the same [official release](https://github.com/wiresock/proxifyre/releases). Obtain the expected 64-character hash from that sidecar and verify it before elevation. Keep the archive intact; the script checks the hash again while holding the archive open without write/delete sharing.

Save the following as `Stage-ProxiFyreZip.ps1`. Run it in **Windows PowerShell 5.1 as Administrator**, using the native architecture of Windows. It intentionally uses the .NET Framework directory-creation overload that applies ownership and a protected ACL when creating the directory. PowerShell 7 is not supported by this recipe.

The destination is a new direct child of the system Program Files folder, named `ProxiFyre-Portable` by default. Use `-DestinationName ProxiFyre-Manual` for another name. Other fixed-volume locations can satisfy the application policy, but require an equally protected parent chain; this recipe deliberately confines staging to Program Files.

<!-- zip-staging-script -->
```powershell
#requires -Version 5.1
#requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ZipPath,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[a-fA-F0-9]{64}$')]
    [string]$ExpectedSha256,
    [ValidatePattern('^ProxiFyre(?:-[A-Za-z0-9]+)*$')]
    [string]$DestinationName = 'ProxiFyre-Portable'
)
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSEdition -ne 'Desktop') {
    throw 'Use Windows PowerShell 5.1, not PowerShell 7.'
}

function Assert-ProxiFyreStagingParent([IO.DirectoryInfo]$Directory) {
    if ([IO.DriveInfo]::new($Directory.Root.FullName).DriveType -ne 'Fixed') {
        throw 'The staging parent must be on a fixed local volume.'
    }
    $trusted = @('S-1-5-18', 'S-1-5-32-544',
        'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    for ($ancestor = $Directory; $null -ne $ancestor; $ancestor = $ancestor.Parent) {
        if ($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "Reparse point in parent chain: $($ancestor.FullName)"
        }
        $acl = Get-Acl -LiteralPath $ancestor.FullName
        if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trusted) {
            throw "Untrusted parent owner: $($ancestor.FullName)"
        }
        $dangerousRights = 0x500D0040 # Generic all/write, delete/child, change ACL/owner.
        if ($ancestor.FullName -eq $Directory.FullName) {
            # Prevent a user from creating the destination between check and creation.
            # Directory.CreateDirectory would otherwise reuse an existing directory.
            $dangerousRights = $dangerousRights -bor 0x4 # CreateDirectories
        }
        foreach ($rule in $acl.GetAccessRules($true, $true,
                [Security.Principal.SecurityIdentifier])) {
            if ($rule.AccessControlType -eq 'Allow' -and
                -not ($rule.PropagationFlags -band
                    [Security.AccessControl.PropagationFlags]::InheritOnly) -and
                $rule.IdentityReference.Value -notin $trusted -and
                ([long]$rule.FileSystemRights -band $dangerousRights)) {
                throw "Untrusted parent mutation permission: $($ancestor.FullName)"
            }
        }
    }
}

$parent = [IO.DirectoryInfo]::new([Environment]::GetFolderPath('ProgramFiles'))
$destination = Join-Path $parent.FullName $DestinationName
if (Test-Path -LiteralPath $destination) {
    throw "Destination already exists: $destination. Use a fresh directory."
}
Assert-ProxiFyreStagingParent $parent

Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
$archiveStream = [IO.File]::Open((Resolve-Path -LiteralPath $ZipPath).Path,
    [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
$archive = $null
$createdDestination = $false
$sha = [Security.Cryptography.SHA256]::Create()
try {
    $actual = [BitConverter]::ToString($sha.ComputeHash($archiveStream)).Replace('-', '')
    if ($actual -ine $ExpectedSha256) { throw 'ZIP SHA-256 mismatch.' }
    $archiveStream.Position = 0
    $archive = [IO.Compression.ZipArchive]::new($archiveStream,
        [IO.Compression.ZipArchiveMode]::Read, $true)
    $security = [Security.AccessControl.DirectorySecurity]::new()
    $security.SetSecurityDescriptorSddlForm(
        'O:BAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)(A;OICI;RC;;;OW)')
    [IO.Directory]::CreateDirectory($destination, $security) | Out-Null
    $createdDestination = $true
    [IO.Compression.ZipFileExtensions]::ExtractToDirectory($archive, $destination)

    # Do not set the already trusted root owner again: Windows removes its
    # explicit OWNER RIGHTS ACE on ownership assignment. Keep it inheritable
    # throughout this pass so children remain protected until individually owned.
    & icacls.exe (Join-Path $destination '*') /setowner '*S-1-5-32-544' /T /Q
    if ($LASTEXITCODE -ne 0) { throw 'Setting payload ownership failed.' }
    Write-Output "Staged to $destination. Launch ProxiFyreUI.exe from this directory."
}
catch {
    $failure = $_
    if ($createdDestination) {
        try {
            $resolved = (Resolve-Path -LiteralPath $destination).Path
            if ((Split-Path -Parent $resolved) -ne $parent.FullName -or
                (Split-Path -Leaf $resolved) -ne $DestinationName -or
                ((Get-Item -LiteralPath $resolved).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                throw "Unexpected cleanup path: $resolved"
            }
            Remove-Item -LiteralPath $resolved -Recurse -Force
        }
        catch { Write-Warning "Could not remove partial staging directory: $destination. $($_.Exception.Message)" }
    }
    throw $failure
}
finally {
    if ($null -ne $archive) { $archive.Dispose() }
    $sha.Dispose()
    $archiveStream.Dispose()
}
```

For example, after substituting the release version, archive path, and published hash:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Stage-ProxiFyreZip.ps1 `
    -ZipPath 'C:\Downloads\ProxiFyre-v<version>-x64.zip' `
    -ExpectedSha256 '<64-character hash from the official .sha256 sidecar>'
```

The example sets execution policy for that process only so a locally reviewed script can run on clients whose default policy is Restricted. Organizational Group Policy can still prevent execution; follow your administrator's policy in that case.

If extraction or ownership assignment fails, the script attempts to remove only the new destination it created. If cleanup also fails, it reports the remaining path; do not launch that partial payload. Inspect the failure before retrying. The script does not change any parent ACL, replace an existing installation, or repair an existing extraction.

## Checking the result

Inspect the destination and file owners with `Get-Acl` and permissions with `icacls`. Open the staged `ProxiFyreUI.exe`; the Release launcher and service controls still perform their full security and integrity checks. Preserve the shipped `ProxiFyreUI.exe.config`, `ProxiFyre.exe.config`, and `NLog.config` bytes. Edit routing and log verbosity through `app-config.json` or the GUI.

If the launcher reports **owner SID ... is not a trusted machine identity**, use the exact rejected path to distinguish a payload ownership problem from a parent-chain problem. If it reports an untrusted allow ACE, inspect its trustee and prohibited rights. Changing the owner alone does not fix an unsafe ACL. Follow the [GUI troubleshooting guide](gui.md#troubleshooting) for other payload failures.

To upgrade a manual installation, stop its engine/service first, back up the live configuration, and stage the new release separately. Do not overlay a running payload. A service registered to the old directory must be removed and registered from the new directory; copying files does not update its image path. [Migration to MSI](installer.md#upgrade-repair-and-uninstall) has separate instructions.

## Recipe validation

Maintainers can run `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-ZipStaging.ps1` from an elevated individual administrator account after building Release x64; SYSTEM is not supported for this test. It executes the exact fenced script above in fresh Windows PowerShell 5.1 processes against a ZIP assembled from the built payload. It checks trusted ownership and the existing managed service/UI integrity policies, rejects a user-owned file and a user-writable directory, and verifies that a wrong checksum or existing destination cannot overwrite files. A duplicate-entry archive tests failed-extraction cleanup. The test validates ancestors before creating its fixtures and rejects an unsafe fixture parent before writing any executable files there.

An inert-file probe creates user-owned files and directories with the staged directory's inherited DACL, then attempts actual content writes, child creation, and DACL changes while impersonating the same user with Administrators disabled and privileges removed. This deterministically checks protection before trusted ownership is assigned; it does not attempt a concurrent extraction race. The test uses temporary dedicated directories beneath Program Files, removes only those test directories, and does not register/start a service or install a driver. Native GUI startup and prerequisite installation remain manual integration checks.
