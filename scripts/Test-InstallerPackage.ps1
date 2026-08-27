#requires -Version 7.0

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $MsiPath,
    [Parameter(Mandatory = $true)]
    [ValidateSet('x86', 'x64', 'arm64')]
    [string] $Architecture,
    [Parameter(Mandatory = $true)][string] $Version
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$resolvedMsi = (Get-Item -LiteralPath $MsiPath -Force).FullName
if ((Get-AuthenticodeSignature -LiteralPath $resolvedMsi).Status -ne
    [Management.Automation.SignatureStatus]::NotSigned) {
    throw "MSI '$resolvedMsi' must be unsigned."
}

$installer = New-Object -ComObject WindowsInstaller.Installer
$database = $installer.OpenDatabase($resolvedMsi, 0)

function Get-Scalar {
    param([Parameter(Mandatory = $true)][string] $Sql)
    $view = $database.OpenView($Sql)
    try {
        $null = $view.Execute()
        $record = $view.Fetch()
        if ($null -eq $record) { return $null }
        return ([string]$record.StringData(1)).Trim()
    }
    finally {
        $null = $view.Close()
    }
}

function Get-Rows {
    param([Parameter(Mandatory = $true)][string] $Sql)
    $view = $database.OpenView($Sql)
    $rows = [Collections.Generic.List[object[]]]::new()
    try {
        $null = $view.Execute()
        while ($null -ne ($record = $view.Fetch())) {
            $fieldCount = [int]$record.FieldCount()
            $row = [object[]]::new($fieldCount)
            for ($index = 1; $index -le $fieldCount; $index++) {
                $row[$index - 1] = $record.StringData($index)
            }
            $rows.Add($row)
        }
    }
    finally {
        $null = $view.Close()
    }
    return $rows.ToArray()
}

try {
    $actualProductVersion = Get-Scalar "SELECT ``Value`` FROM ``Property`` WHERE ``Property``='ProductVersion'"
    if ([string]$actualProductVersion -cne $Version) {
        throw "MSI ProductVersion '$actualProductVersion' does not match requested version '$Version'."
    }
    $actualArchitecture = Get-Scalar "SELECT ``Value`` FROM ``Property`` WHERE ``Property``='PROXIFYREARCHITECTURE'"
    if ([string]$actualArchitecture -cne $Architecture) {
        throw "MSI architecture '$actualArchitecture' does not match requested architecture '$Architecture'."
    }
    if ([string](Get-Scalar "SELECT ``Value`` FROM ``Property`` WHERE ``Property``='UpgradeCode'") -cne
        '{309431B2-9478-43FE-8CB6-EB289306C64C}') {
        throw 'MSI UpgradeCode changed unexpectedly.'
    }

    $requiredFiles = @(
        'ProxiFyre.exe',
        'ProxiFyre.exe.config',
        'ProxiFyreUI.exe',
        'ProxiFyreUI.exe.config',
        'ProxiFyreUI.Managed.dll',
        'ProxiFyre.Configuration.dll',
        'socksify.dll',
        'Newtonsoft.Json.dll',
        'NLog.dll',
        'Topshelf.dll',
        'NLog.config',
        'app-config.sample.json'
    )
    $actualFiles = @(Get-Rows 'SELECT `FileName` FROM `File`' | ForEach-Object {
        ([string]$_[0] -split '\|')[-1]
    } | Sort-Object)
    $expectedFiles = @($requiredFiles | Sort-Object)
    if (Compare-Object -ReferenceObject $expectedFiles -DifferenceObject $actualFiles) {
        throw "MSI file table differs from the closed runtime allowlist: $($actualFiles -join ', ')."
    }
    if ($actualFiles -contains 'app-config.json') {
        throw 'The live app-config.json must remain user-owned and outside the MSI File table.'
    }

    $licenseRtf = Get-Scalar (
        "SELECT ``Text`` FROM ``Control`` WHERE ``Dialog_``='LicenseAgreementDlg' " +
        "AND ``Control``='LicenseText'")
    if ([string]::IsNullOrWhiteSpace($licenseRtf) -or
        $licenseRtf -notmatch 'GNU AFFERO GENERAL PUBLIC LICENSE' -or
        $licenseRtf -notmatch 'Remote Network Interaction' -or
        $licenseRtf -notmatch 'END OF TERMS AND CONDITIONS') {
        throw 'The MSI must embed the complete repository AGPL-3.0 license text.'
    }

    $serviceRow = @(Get-Rows "SELECT ``ServiceType``, ``StartType``, ``ErrorControl``, ``Dependencies``, ``StartName`` FROM ``ServiceInstall`` WHERE ``Name``='ProxiFyreService'")
    if ($serviceRow.Count -ne 1 -or [int]$serviceRow[0][0] -ne 16 -or
        [int]$serviceRow[0][1] -ne 3 -or [int]$serviceRow[0][2] -ne 32769 -or
        [string]$serviceRow[0][3] -notmatch 'NDISRD' -or
        [string]$serviceRow[0][4] -cne 'LocalSystem') {
        throw 'ProxiFyreService must be a vital, demand-start LocalSystem own-process service that depends on NDISRD.'
    }
    $serviceEvents = [int](Get-Scalar "SELECT ``Event`` FROM ``ServiceControl`` WHERE ``Name``='ProxiFyreService'")
    if ($serviceEvents -ne 162) {
        throw 'ProxiFyreService must stop for install/uninstall and be removed only during uninstall.'
    }

    $shortcuts = @(Get-Rows 'SELECT `Name`, `Target` FROM `Shortcut`')
    if ($shortcuts.Count -ne 2 -or @($shortcuts | Where-Object { $_[1] -notmatch 'ProxiFyreUI\.exe' }).Count -ne 0) {
        throw 'Both installer shortcuts must launch ProxiFyreUI.exe.'
    }

    $tableNames = @(Get-Rows 'SELECT `Name` FROM `_Tables`' | ForEach-Object { [string]$_[0] })
    $firewallTable = @($tableNames | Where-Object { $_ -match 'FirewallException$' })
    if ($firewallTable.Count -ne 1) {
        throw 'The MSI must contain exactly one WiX firewall-exception table.'
    }
    $firewallRows = @(Get-Rows (
        "SELECT ``Name``, ``RemoteAddresses``, ``Port``, ``Protocol``, ``Program``, " +
        "``Attributes``, ``Profile``, ``Direction``, ``EdgeTraversal``, ``RemotePort`` " +
        "FROM ``$($firewallTable[0])``"))
    $protocols = @($firewallRows | ForEach-Object { [int]$_[3] } | Sort-Object)
    $invalidFirewallRows = @($firewallRows | Where-Object {
        [string]$_[1] -cne '*' -or -not [string]::IsNullOrEmpty([string]$_[2]) -or
        [string]$_[4] -cne '[#ProxiFyreEngineFile]' -or [int]$_[5] -ne 0 -or
        [int]$_[6] -ne [int]::MaxValue -or [int]$_[7] -ne 1 -or
        [int]$_[8] -ne 0 -or -not [string]::IsNullOrEmpty([string]$_[9])
    })
    if ($firewallRows.Count -ne 2 -or $invalidFirewallRows.Count -ne 0 -or
        $protocols[0] -ne 6 -or $protocols[1] -ne 17) {
        throw 'The MSI must own exactly the program-scoped TCP and UDP inbound rules for ProxiFyre.exe.'
    }

    $launchConditions = @(Get-Rows 'SELECT `Condition`, `Description` FROM `LaunchCondition`')
    $launchText = @($launchConditions | ForEach-Object { $_ -join ' ' }) -join "`n"
    if ($launchText -notmatch 'Windows 7 SP1' -or
        $launchText -notmatch 'VersionNT > 601' -or
        $launchText -notmatch 'ServicePackLevel >= 1') {
        throw 'The standalone MSI must reject Windows 7 RTM with an actionable update message.'
    }
    if ($launchText -notmatch 'Windows Packet Filter' -or
        $launchText -notmatch 'WPF_SERVICE_IMAGE' -or
        $launchText -notmatch 'WPF_DRIVER64_COMPATIBLE' -or
        $launchText -notmatch 'WPF_DRIVER32_COMPATIBLE' -or
        $launchText -match 'WPF_PRODUCT_FOUND') {
        throw 'The standalone MSI does not expose its Windows Packet Filter prerequisite condition.'
    }

    $visualCppLaunchConditions = @($launchConditions | Where-Object {
        [string]$_[1] -match 'Microsoft Visual C\+\+'
    })
    $expectedVisualCppLaunchCondition =
        'Installed OR (BURNMSIINSTALL = 1 AND PROXIFYRE_SETUP_CHAIN = 1) OR (UCRT_BASE_COMPATIBLE AND VC_MSVCP140_COMPATIBLE AND VC_ATOMIC_WAIT_COMPATIBLE AND VC_VCRUNTIME140_COMPATIBLE'
    if ($Architecture -eq 'x64') {
        $expectedVisualCppLaunchCondition += ' AND VC_VCRUNTIME140_1_COMPATIBLE'
    }
    $expectedVisualCppLaunchCondition += ')'
    $routingMarkerLaunchConditions = @($launchConditions | Where-Object {
        [string]$_[0] -match 'BURNMSIINSTALL|PROXIFYRE_SETUP_CHAIN'
    })
    if ($visualCppLaunchConditions.Count -ne 1 -or
        [string]$visualCppLaunchConditions[0][0] -cne
            $expectedVisualCppLaunchCondition -or
        $routingMarkerLaunchConditions.Count -ne 1 -or
        [string]$routingMarkerLaunchConditions[0][0] -cne
            $expectedVisualCppLaunchCondition) {
        throw 'The standalone MSI does not enforce its architecture-specific Visual C++ runtime prerequisite.'
    }
    $authoredRoutingProperties = @(Get-Rows (
        "SELECT ``Property``, ``Value`` FROM ``Property`` WHERE ``Property``='BURNMSIINSTALL' OR ``Property``='PROXIFYRE_SETUP_CHAIN'"))
    if ($authoredRoutingProperties.Count -ne 0) {
        throw 'Bundle routing markers must not have defaults in the standalone MSI.'
    }

    $windowsPacketFilterSignatures = @(Get-Rows 'SELECT `FileName`, `MinVersion`, `MaxVersion` FROM `Signature`' |
        Where-Object { (([string]$_[0] -split '\|')[-1]) -ceq 'ndisrd.sys' })
    if ($windowsPacketFilterSignatures.Count -ne 2 -or
        @($windowsPacketFilterSignatures | Where-Object {
            [string]$_[1] -cne '3.6.0.65535' -or
            [string]$_[2] -cne '3.999.65535.65535'
        }).Count -ne 0) {
        throw 'The MSI Windows Packet Filter searches do not encode the supported 3.6.1-through-3.x range.'
    }

    $expectedVisualCppFiles = @('msvcp140.dll', 'msvcp140_atomic_wait.dll',
        'vcruntime140.dll')
    if ($Architecture -eq 'x64') { $expectedVisualCppFiles += 'vcruntime140_1.dll' }
    $visualCppSignatures = @(Get-Rows 'SELECT `FileName`, `MinVersion` FROM `Signature`' |
        Where-Object { $expectedVisualCppFiles -contains (([string]$_[0] -split '\|')[-1]) })
    if ($visualCppSignatures.Count -ne $expectedVisualCppFiles.Count -or
        @($visualCppSignatures | Where-Object {
            [string]$_[1] -cne '14.44.35210.65535'
        }).Count -ne 0) {
        throw 'The MSI Visual C++ runtime file/version searches differ from the native dependency floor.'
    }

    $universalCrtSignatures = @(Get-Rows 'SELECT `FileName`, `MinVersion` FROM `Signature`' |
        Where-Object { (([string]$_[0] -split '\|')[-1]) -ceq 'ucrtbase.dll' })
    if ($universalCrtSignatures.Count -ne 1 -or
        [string]$universalCrtSignatures[0][1] -cne '10.0.10239.65535') {
        throw 'The MSI Universal CRT search differs from the VC redistributable dependency floor.'
    }

    $expectedVisualCppDirectoryPath = if ($Architecture -eq 'x86') {
        '[SystemFolder]'
    }
    else { '[System64Folder]' }
    $expectedVisualCppDirectoryIds = @(
        'UniversalCrtDirectorySearch',
        'VisualCppMsvcp140DirectorySearch',
        'VisualCppAtomicWaitDirectorySearch',
        'VisualCppVcruntime140DirectorySearch'
    )
    if ($Architecture -eq 'x64') {
        $expectedVisualCppDirectoryIds += 'VisualCppVcruntime1401DirectorySearch'
    }
    $visualCppDirectoryRows = @(Get-Rows 'SELECT `Signature_`, `Path`, `Depth` FROM `DrLocator`' |
        Where-Object { $expectedVisualCppDirectoryIds -contains [string]$_[0] })
    if ($visualCppDirectoryRows.Count -ne $expectedVisualCppDirectoryIds.Count -or
        @($visualCppDirectoryRows | Where-Object {
            [string]$_[1] -cne $expectedVisualCppDirectoryPath -or
            [int]$_[2] -ne 0
        }).Count -ne 0) {
        throw "The MSI Visual C++ searches must target the native $Architecture system directory."
    }

    # Exercise the real AppSearch implementation when this x64 validation host
    # can satisfy the x86/x64 floor. The static table assertions above cover
    # cross-builds; this catches Windows Installer path/language behavior that
    # table inspection alone cannot prove.
    if (($Architecture -eq 'x86' -or $Architecture -eq 'x64') -and
        [Runtime.InteropServices.RuntimeInformation]::OSArchitecture -eq
            [Runtime.InteropServices.Architecture]::X64) {
        $systemFolder = if ($Architecture -eq 'x86') {
            [Environment+SpecialFolder]::SystemX86
        }
        else { [Environment+SpecialFolder]::System }
        $systemDirectory = [Environment]::GetFolderPath($systemFolder)
        $runtimeNames = @('ucrtbase.dll', 'msvcp140.dll', 'msvcp140_atomic_wait.dll',
            'vcruntime140.dll')
        $runtimeProperties = @('UCRT_BASE_COMPATIBLE', 'VC_MSVCP140_COMPATIBLE',
            'VC_ATOMIC_WAIT_COMPATIBLE', 'VC_VCRUNTIME140_COMPATIBLE')
        if ($Architecture -eq 'x64') {
            $runtimeNames += 'vcruntime140_1.dll'
            $runtimeProperties += 'VC_VCRUNTIME140_1_COMPATIBLE'
        }
        $hostHasRuntimeFloor = @($runtimeNames | Where-Object {
            $runtimePath = Join-Path $systemDirectory $_
            $minimumVersion = if ($_ -ceq 'ucrtbase.dll') {
                [Version]'10.0.10240.0'
            }
            else { [Version]'14.44.35211.0' }
            if (-not [IO.File]::Exists($runtimePath)) { return $true }
            $versionInfo = (Get-Item -LiteralPath $runtimePath).VersionInfo
            $actualVersion = [Version]::new(
                $versionInfo.FileMajorPart,
                $versionInfo.FileMinorPart,
                $versionInfo.FileBuildPart,
                $versionInfo.FilePrivatePart)
            $actualVersion -lt $minimumVersion
        }).Count -eq 0
        if ($hostHasRuntimeFloor) {
            $session = $installer.OpenPackage($resolvedMsi, 0)
            try {
                if ([int]$session.DoAction('AppSearch') -ne 1) {
                    throw 'Windows Installer AppSearch did not complete successfully.'
                }
                if (@($runtimeProperties | Where-Object {
                    [string]::IsNullOrWhiteSpace([string]$session.Property($_))
                }).Count -ne 0) {
                    throw "The $Architecture MSI did not recognize the compatible runtime installed on the validation host."
                }
            }
            finally {
                [Runtime.InteropServices.Marshal]::FinalReleaseComObject($session) |
                    Out-Null
            }
        }
    }

    $template = [string]$database.SummaryInformation(0).Property(7)
    $expectedTemplate = switch ($Architecture) {
        'x86' { 'Intel' }
        'x64' { 'x64' }
        'arm64' { 'Arm64' }
    }
    if (-not $template.StartsWith($expectedTemplate, [StringComparison]::OrdinalIgnoreCase)) {
        throw "MSI summary template '$template' does not identify $Architecture."
    }
}
finally {
    [Runtime.InteropServices.Marshal]::FinalReleaseComObject($database) | Out-Null
    [Runtime.InteropServices.Marshal]::FinalReleaseComObject($installer) | Out-Null
}

Write-Output "Validated ProxiFyre $Version $Architecture MSI authoring and unsigned state."
