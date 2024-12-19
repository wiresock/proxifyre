param (
    [string]$versionTag
)

# Import PowerShellForGitHub module
Import-Module PowerShellForGitHub

# Base URL for downloading files
$owner = "wiresock"
$repository = "ProxiFyre"
$baseURL = "https://github.com/$owner/$repository/releases/download/v$versionTag/"
$files = @("ProxiFyre-v$versionTag-ARM64.zip", "ProxiFyre-v$versionTag-x64.zip", "ProxiFyre-v$versionTag-x86.zip")

foreach ($file in $files) {
    $downloadURL = $baseURL + $file
    $downloadPath = "./" + $file
    Invoke-WebRequest -Uri $downloadURL -OutFile $downloadPath

    # Extract the ZIP file
    $extractPath = "./" + $file -replace ".zip", ""
    Expand-Archive -Path $downloadPath -DestinationPath $extractPath -Force

    # Sign the executable inside the extracted folder
    $exePath = $extractPath + "/ProxiFyre.exe"
    & signtool sign /fd sha1 /t http://timestamp.digicert.com /n "The Anti-Cloud Corporation" $exePath
    & signtool sign /as /td sha256 /fd sha256 /tr http://timestamp.digicert.com /n "The Anti-Cloud Corporation" $exePath

    # Change to the directory of the folder to be zipped
    Push-Location $extractPath

    # Get all items in the current directory (the extracted folder)
    $items = Get-ChildItem

    # Define the path for the new ZIP file
    $zipPath = "../" + $file -replace ".zip", "-signed.zip"
    Compress-Archive -Path $items -DestinationPath $zipPath -Force

    # Return to the original directory
    Pop-Location

    # Clean up: remove the original ZIP and extracted folder
    Remove-Item -Path $downloadPath -Force
    Remove-Item -Path $extractPath -Recurse -Force
}

# Getting the GitHub release
$release = Get-GitHubRelease -OwnerName $owner -RepositoryName $repository -Tag "v$versionTag"

# Removing existing ZIP files from the release
$assets = Get-GitHubReleaseAsset -OwnerName $owner -RepositoryName $repository -ReleaseId $release.id
foreach ($asset in $assets) {
    if ($asset.name -like "*.zip") {
        Remove-GitHubReleaseAsset -OwnerName $owner -RepositoryName $repository -AssetId $asset.id -Force
    }
}

# Uploading new signed ZIP files and deleting them after upload
foreach ($file in Get-ChildItem "./" -Filter "*-signed.zip") {
    $release | New-GitHubReleaseAsset -Path $file.Name
    Remove-Item -Path $file.Name -Force
}
