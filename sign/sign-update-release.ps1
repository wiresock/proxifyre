<#
.SYNOPSIS
Signs and transactionally replaces the ProxiFyre release archives.

.PARAMETER VersionTag
Release version without the leading "v", for example "2.3.0".

.PARAMETER DryRun
Runs the complete local download, signing, repacking, and verification pipeline
without uploading or deleting any GitHub release assets.

.PARAMETER DryRunOutputDirectory
Optional directory for verified dry-run archives. When omitted, a unique
directory is created under the system temporary directory.

.EXAMPLE
.\sign-update-release.ps1 -VersionTag 2.3.0

Preflights the release, asks for confirmation, signs and verifies both shipped
binaries, uploads the signed archives, and then removes the unsigned archives.

.EXAMPLE
.\sign-update-release.ps1 -VersionTag 2.3.0 -WhatIf

Checks authentication and source assets without signing or changing the release.

.EXAMPLE
.\sign-update-release.ps1 -VersionTag 2.3.0 -DryRun -DryRunOutputDirectory .\signed-v2.3.0

Builds and verifies signed archives locally without changing the GitHub release.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "High")]
param (
    [Parameter(Mandatory = $true)]
    [ValidateScript({
        if ($_ -notmatch '^\d+\.\d+\.\d+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$') {
            throw "Use a version such as '2.3.0' without the leading 'v'."
        }
        $true
    })]
    [string]$VersionTag,

    [switch]$DryRun,

    [string]$DryRunOutputDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not [string]::IsNullOrWhiteSpace($DryRunOutputDirectory) -and -not $DryRun) {
    throw "-DryRunOutputDirectory can only be used together with -DryRun."
}

$owner = "wiresock"
$repository = "ProxiFyre"
$releaseTag = "v$VersionTag"
$certificateSubject = "The Anti-Cloud Corporation"
$architectures = @("ARM64", "x64", "x86")
$expectedFiles = @("ProxiFyre.exe", "socksify.dll", "app-config.sample.json")
$binariesToSign = @("ProxiFyre.exe", "socksify.dll")

function Assert-ExpectedFiles {
    param (
        [Parameter(Mandatory = $true)]
        [string]$RootPath,

        [Parameter(Mandatory = $true)]
        [string[]]$Names,

        [Parameter(Mandatory = $true)]
        [string]$Context
    )

    foreach ($name in $Names) {
        $path = Join-Path $RootPath $name
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Expected file '$name' not found in $Context ('$RootPath')."
        }
    }

    $pdbFiles = @(Get-ChildItem -LiteralPath $RootPath -Filter "*.pdb" -File -Recurse -Force)
    if ($pdbFiles.Count -gt 0) {
        throw "Unexpected PDB file '$($pdbFiles[0].FullName)' found in $Context."
    }
}

function Get-RelativeFileSet {
    param (
        [Parameter(Mandatory = $true)]
        [string]$RootPath
    )

    $root = [IO.Path]::GetFullPath($RootPath).TrimEnd([char[]]"\/")
    return @(
        Get-ChildItem -LiteralPath $root -File -Recurse -Force |
            ForEach-Object {
                $_.FullName.Substring($root.Length).TrimStart([char[]]"\/").Replace('\', '/')
            } |
            Sort-Object
    )
}

function Invoke-SignToolChecked {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Operation,

        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    & $script:signToolPath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "SignTool $Operation failed with exit code $LASTEXITCODE."
    }
}

function Get-CurrentReleaseAssets {
    return @(
        Get-GitHubReleaseAsset `
            -OwnerName $script:owner `
            -RepositoryName $script:repository `
            -ReleaseId $script:release.id
    )
}

function Remove-SigningWorkspace {
    param (
        [Parameter(Mandatory = $true)]
        [string]$WorkspacePath,

        [Parameter(Mandatory = $true)]
        [string]$TempRoot
    )

    if (-not (Test-Path -LiteralPath $WorkspacePath)) {
        return
    }

    $resolvedWorkspace = [IO.Path]::GetFullPath($WorkspacePath)
    $resolvedTempRoot = [IO.Path]::GetFullPath($TempRoot).TrimEnd([char[]]"\/") + [IO.Path]::DirectorySeparatorChar
    $workspaceName = Split-Path -Leaf $resolvedWorkspace

    if (-not $resolvedWorkspace.StartsWith($resolvedTempRoot, [StringComparison]::OrdinalIgnoreCase) -or
        -not $workspaceName.StartsWith("ProxiFyre-sign-", [StringComparison]::Ordinal)) {
        Write-Warning "Refusing to remove unexpected signing workspace '$resolvedWorkspace'."
        return
    }

    Remove-Item -LiteralPath $resolvedWorkspace -Recurse -Force
}

$signTool = Get-Command signtool.exe -ErrorAction SilentlyContinue
if (-not $signTool) {
    throw "signtool.exe was not found on PATH. Install the Windows SDK or add SignTool to PATH."
}
$signToolPath = $signTool.Source

if (-not (Get-Module -ListAvailable PowerShellForGitHub)) {
    throw "The PowerShellForGitHub module is not installed."
}
Import-Module PowerShellForGitHub -ErrorAction Stop
$webRequestSupportsBasicParsing = (Get-Command Invoke-WebRequest).Parameters.ContainsKey("UseBasicParsing")

# Resolve the release and all source assets before doing any signing work. This
# verifies GitHub authentication and prevents local work for an incomplete release.
$release = Get-GitHubRelease -OwnerName $owner -RepositoryName $repository -Tag $releaseTag
if (-not $release) {
    throw "GitHub release '$releaseTag' was not found in $owner/$repository."
}

$releaseAssets = Get-CurrentReleaseAssets
$artifacts = @()
foreach ($architecture in $architectures) {
    $originalName = "ProxiFyre-v$VersionTag-$architecture.zip"
    $signedName = "ProxiFyre-v$VersionTag-$architecture-signed.zip"
    $matches = @($releaseAssets | Where-Object { $_.name -eq $originalName })

    if ($matches.Count -ne 1) {
        throw "Expected exactly one release asset named '$originalName'; found $($matches.Count)."
    }
    if ([int64]$matches[0].size -le 0) {
        throw "Release asset '$originalName' is empty."
    }
    if ([string]::IsNullOrWhiteSpace([string]$matches[0].browser_download_url)) {
        throw "Release asset '$originalName' has no download URL."
    }

    $artifacts += [PSCustomObject]@{
        Architecture    = $architecture
        OriginalName   = $originalName
        OriginalAssetId = [int64]$matches[0].id
        OriginalLength  = [int64]$matches[0].size
        DownloadUrl     = [string]$matches[0].browser_download_url
        SignedName      = $signedName
        SignedPath      = $null
        SignedLength    = [int64]0
    }
}

$operation = if ($DryRun) {
    "download, sign, repack, and verify the three ZIP assets locally"
}
else {
    "sign, verify, and replace the three ZIP assets for $releaseTag"
}
$operationTarget = if ($DryRun) {
    "local dry-run workspace for $releaseTag"
}
else {
    "$owner/$repository release $releaseTag"
}

# WhatIf remains a lightweight authenticated preflight. DryRun intentionally
# continues through the complete local signing pipeline without remote mutation.
if ($WhatIfPreference) {
    [void]$PSCmdlet.ShouldProcess($operationTarget, $operation)
    return
}
if (-not $DryRun -and -not $PSCmdlet.ShouldProcess($operationTarget, $operation)) {
    return
}

$tempRoot = [IO.Path]::GetTempPath()
$workspace = Join-Path $tempRoot "ProxiFyre-sign-$VersionTag-$([guid]::NewGuid().ToString('N'))"
$dryRunOutputPath = $null
if ($DryRun) {
    if ([string]::IsNullOrWhiteSpace($DryRunOutputDirectory)) {
        $dryRunOutputPath = Join-Path $tempRoot "ProxiFyre-dry-run-$VersionTag-$([guid]::NewGuid().ToString('N'))"
    }
    else {
        $dryRunOutputPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath(
            $DryRunOutputDirectory
        )
    }
}
New-Item -ItemType Directory -Path $workspace | Out-Null

try {
    foreach ($artifact in $artifacts) {
        Write-Host "Preparing $($artifact.OriginalName)..."

        $downloadPath = Join-Path $workspace $artifact.OriginalName
        $extractPath = Join-Path $workspace ([IO.Path]::GetFileNameWithoutExtension($artifact.OriginalName))
        $verifyPath = Join-Path $workspace "$([IO.Path]::GetFileNameWithoutExtension($artifact.SignedName))-verify"
        $signedPath = Join-Path $workspace $artifact.SignedName

        $webRequestParameters = @{
            Uri     = $artifact.DownloadUrl
            OutFile = $downloadPath
        }
        if ($webRequestSupportsBasicParsing) {
            $webRequestParameters.UseBasicParsing = $true
        }
        Invoke-WebRequest @webRequestParameters
        if ([int64](Get-Item -LiteralPath $downloadPath).Length -ne $artifact.OriginalLength) {
            throw "Downloaded asset '$($artifact.OriginalName)' has an unexpected size."
        }
        Expand-Archive -LiteralPath $downloadPath -DestinationPath $extractPath -Force
        Assert-ExpectedFiles -RootPath $extractPath -Names $expectedFiles -Context $artifact.OriginalName

        foreach ($name in $binariesToSign) {
            $binaryPath = Join-Path $extractPath $name

            Invoke-SignToolChecked -Operation "SHA-1 signing of '$name'" -Arguments @(
                "sign", "/fd", "sha1", "/t", "http://timestamp.digicert.com",
                "/n", $certificateSubject, $binaryPath
            )
            Invoke-SignToolChecked -Operation "SHA-256 signing of '$name'" -Arguments @(
                "sign", "/as", "/td", "sha256", "/fd", "sha256",
                "/tr", "http://timestamp.digicert.com", "/n", $certificateSubject, $binaryPath
            )
            Invoke-SignToolChecked -Operation "verification of '$name'" -Arguments @(
                "verify", "/pa", "/all", "/v", $binaryPath
            )
        }

        $sourceFileSet = Get-RelativeFileSet -RootPath $extractPath
        $items = @(Get-ChildItem -LiteralPath $extractPath -Force)
        if ($items.Count -eq 0) {
            throw "No files were extracted from '$($artifact.OriginalName)'."
        }

        Compress-Archive `
            -LiteralPath @($items.FullName) `
            -DestinationPath $signedPath `
            -CompressionLevel Optimal `
            -Force

        Expand-Archive -LiteralPath $signedPath -DestinationPath $verifyPath -Force
        Assert-ExpectedFiles -RootPath $verifyPath -Names $expectedFiles -Context $artifact.SignedName

        $verifiedFileSet = Get-RelativeFileSet -RootPath $verifyPath
        $fileSetDifference = @(Compare-Object -ReferenceObject $sourceFileSet -DifferenceObject $verifiedFileSet)
        if ($fileSetDifference.Count -gt 0) {
            throw "Repacked archive '$($artifact.SignedName)' does not contain the same file set as its source."
        }

        foreach ($name in $binariesToSign) {
            Invoke-SignToolChecked -Operation "archive verification of '$name'" -Arguments @(
                "verify", "/pa", "/all", "/v", (Join-Path $verifyPath $name)
            )
        }

        $artifact.SignedPath = $signedPath
        $artifact.SignedLength = [int64](Get-Item -LiteralPath $signedPath).Length
    }

    if ($DryRun) {
        if (Test-Path -LiteralPath $dryRunOutputPath) {
            if (-not (Test-Path -LiteralPath $dryRunOutputPath -PathType Container)) {
                throw "Dry-run output path '$dryRunOutputPath' is not a directory."
            }
            if (@(Get-ChildItem -LiteralPath $dryRunOutputPath -Force).Count -ne 0) {
                throw "Dry-run output directory '$dryRunOutputPath' must be empty."
            }
        }
        else {
            New-Item -ItemType Directory -Path $dryRunOutputPath | Out-Null
        }

        foreach ($artifact in $artifacts) {
            $outputPath = Join-Path $dryRunOutputPath $artifact.SignedName
            Copy-Item -LiteralPath $artifact.SignedPath -Destination $outputPath

            $outputLength = [int64](Get-Item -LiteralPath $outputPath).Length
            $sourceHash = (Get-FileHash -LiteralPath $artifact.SignedPath -Algorithm SHA256).Hash
            $outputHash = (Get-FileHash -LiteralPath $outputPath -Algorithm SHA256).Hash
            if ($outputLength -ne $artifact.SignedLength -or $outputHash -ne $sourceHash) {
                throw "Dry-run output verification failed for '$($artifact.SignedName)'."
            }

            Write-Host "Verified dry-run archive: $outputPath (SHA256 $outputHash)"
        }

        Write-Host "Dry run completed without modifying GitHub release $releaseTag."
        Write-Host "Verified archives are available at '$dryRunOutputPath'."
        return
    }

    # Re-check source asset IDs after signing so a concurrent release edit cannot
    # cause this run to replace assets different from those it downloaded.
    $currentAssets = Get-CurrentReleaseAssets
    foreach ($artifact in $artifacts) {
        $currentOriginal = @($currentAssets | Where-Object { $_.name -eq $artifact.OriginalName })
        if ($currentOriginal.Count -ne 1 -or
            [int64]$currentOriginal[0].id -ne $artifact.OriginalAssetId -or
            [int64]$currentOriginal[0].size -ne $artifact.OriginalLength) {
            throw "Release asset '$($artifact.OriginalName)' changed while signing; no assets were replaced."
        }
    }

    # A failed prior attempt may have uploaded some signed assets. Remove only
    # those exact signed names while the original archives are still available.
    foreach ($artifact in $artifacts) {
        $staleSignedAssets = @($currentAssets | Where-Object { $_.name -eq $artifact.SignedName })
        foreach ($asset in $staleSignedAssets) {
            Write-Host "Removing stale signed asset $($asset.name)..."
            Remove-GitHubReleaseAsset `
                -OwnerName $owner `
                -RepositoryName $repository `
                -AssetId ([int64]$asset.id) `
                -Force
        }
    }

    foreach ($artifact in $artifacts) {
        Write-Host "Uploading $($artifact.SignedName)..."
        New-GitHubReleaseAsset `
            -OwnerName $owner `
            -RepositoryName $repository `
            -ReleaseId ([int64]$release.id) `
            -Path $artifact.SignedPath | Out-Null
    }

    # Verify every signed upload by exact name and byte length before removing
    # any original asset. An upload failure therefore leaves all originals live.
    $uploadedAssets = Get-CurrentReleaseAssets
    foreach ($artifact in $artifacts) {
        $uploaded = @($uploadedAssets | Where-Object { $_.name -eq $artifact.SignedName })
        if ($uploaded.Count -ne 1) {
            throw "Expected one uploaded asset '$($artifact.SignedName)'; found $($uploaded.Count). Original assets were retained."
        }
        if ([int64]$uploaded[0].size -ne $artifact.SignedLength) {
            throw "Uploaded asset '$($artifact.SignedName)' has an unexpected size. Original assets were retained."
        }
    }

    foreach ($artifact in $artifacts) {
        $original = @($uploadedAssets | Where-Object { [int64]$_.id -eq $artifact.OriginalAssetId })
        if ($original.Count -ne 1) {
            throw "Original asset '$($artifact.OriginalName)' disappeared before final replacement."
        }

        Write-Host "Removing unsigned asset $($artifact.OriginalName)..."
        Remove-GitHubReleaseAsset `
            -OwnerName $owner `
            -RepositoryName $repository `
            -AssetId $artifact.OriginalAssetId `
            -Force
    }

    $finalAssets = Get-CurrentReleaseAssets
    foreach ($artifact in $artifacts) {
        if (@($finalAssets | Where-Object { $_.name -eq $artifact.OriginalName }).Count -ne 0) {
            throw "Unsigned asset '$($artifact.OriginalName)' is still present after replacement."
        }

        $signed = @($finalAssets | Where-Object { $_.name -eq $artifact.SignedName })
        if ($signed.Count -ne 1 -or [int64]$signed[0].size -ne $artifact.SignedLength) {
            throw "Final verification failed for '$($artifact.SignedName)'."
        }
    }

    Write-Host "Release $releaseTag now contains the three verified signed archives."
}
finally {
    try {
        Remove-SigningWorkspace -WorkspacePath $workspace -TempRoot $tempRoot
    }
    catch {
        Write-Warning "Failed to clean signing workspace '$workspace': $($_.Exception.Message)"
    }
}
