
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function ConvertTo-BashLiteral {
    <#
      Bash-safe single-quote wrapper.
      Example: abc'def -> 'abc'"'"'def'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Text
    )

    return "'" + ($Text -replace "'", "'""'""'") + "'"
}

function Invoke-LinuxSshCommand {
    <#
    Runs a command on a remote Linux host using Windows built-in OpenSSH client (ssh.exe),
    captures stdout/stderr, and returns the remote exit code.

    Notes:
    - Uses BatchMode=yes so it won't prompt for passwords; use SSH keys.
    - Optionally DisableHostKeyChecking for lab/dev (not recommended for prod).
    - Automatically adds sudo prefix for non-root users when UseSudo is specified.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $HostName,
        [Parameter(Mandatory)] [string] $UserName,
        [Parameter(Mandatory)] [string] $Command,

        [int]    $Port = 22,
        [string] $KeyFilePath = (Join-Path $HOME ".ssh\id_rsa"),
        [int]    $ConnectTimeoutSec = 15,

        [switch] $DisableHostKeyChecking,
        [switch] $UseSudo
    )

    # Ensure ssh.exe exists
    $sshCmd = (Get-Command ssh.exe -ErrorAction Stop).Source

    # Build ssh args
    $sshArgs = @(
        '-p', $Port
        '-o', 'BatchMode=yes'
        '-o', "ConnectTimeout=$ConnectTimeoutSec"
        '-o', 'ServerAliveInterval=30'
        '-o', 'ServerAliveCountMax=3'
    )

    if ($KeyFilePath) {
        if (-not (Test-Path -LiteralPath $KeyFilePath)) {
            throw "KeyFilePath not found: $KeyFilePath"
        }
        $sshArgs += @('-i', $KeyFilePath)
    }

    if ($DisableHostKeyChecking) {
        # For automation on ephemeral hosts ONLY; weakens MITM protection.
        $sshArgs += @(
            '-o', 'StrictHostKeyChecking=no'
            '-o', 'UserKnownHostsFile=/dev/null'
        )
    }

    $target = "$UserName@$HostName"

    # Sentinel to recover remote exit code reliably
    $sentinel = 'REMOTE_EXIT_CODE'

    # Run command via bash -lc '<command>; rc=$?; echo REMOTE_EXIT_CODE:<rc>'
    # Add sudo prefix before bash -lc for non-root users if UseSudo is specified
    $remotePayload = "$Command; rc=`$?; echo ${sentinel}:`$rc"
    $bashCommand = "bash -lc " + (ConvertTo-BashLiteral -Text $remotePayload)
    
    if ($UseSudo -and $UserName -ne "root") {
        $remote = "sudo $bashCommand"
    }
    else {
        $remote = $bashCommand
    }

    # Create process
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $sshCmd
    $psi.Arguments = ($sshArgs + @($target, $remote)) -join ' '
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.UseShellExecute        = $false
    $psi.CreateNoWindow         = $true

    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $psi

    [void]$p.Start()
    $stdout = $p.StandardOutput.ReadToEnd()
    $stderr = $p.StandardError.ReadToEnd()
    $p.WaitForExit()

    # Parse remote exit code from stdout (if present)
    $remoteExit = $null
    $lines = $stdout -split "`r?`n"
    foreach ($line in $lines) {
        if ($line -match "^${sentinel}:(\d+)\s*$") {
            $remoteExit = [int]$Matches[1]
            break
        }
    }

    # Remove the sentinel line from stdout
    $cleanStdout = ($lines | Where-Object { $_ -notmatch "^${sentinel}:\d+\s*$" }) -join "`n"

    # Return a structured object
    [pscustomobject]@{
        HostName        = $HostName
        Port            = $Port
        UserName        = $UserName
        Command         = $Command
        SshClientExit   = $p.ExitCode
        RemoteExitCode  = $remoteExit
        StdOut          = $cleanStdout.TrimEnd()
        StdErr          = $stderr.TrimEnd()
    }
}


function Copy-ToLinuxViaScp {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $SourcePath,          # Local file or folder on Windows

        [Parameter(Mandatory)]
        [string] $HostName,            # Linux IP or DNS

        [Parameter(Mandatory)]
        [string] $UserName,            # Linux user

        [Parameter(Mandatory)]
        [string] $DestinationPath,     # Remote path (e.g. /home/user/data)

        [int] $Port = 22,

        [string] $KeyFilePath = (Join-Path $HOME ".ssh\id_rsa"),

        [switch] $Recursive,            # Needed for folders
        [switch] $DisableHostKeyChecking
    )

    if (-not (Test-Path -LiteralPath $SourcePath)) {
        throw "SourcePath does not exist: $SourcePath"
    }

    if ($KeyFilePath -and -not (Test-Path -LiteralPath $KeyFilePath)) {
        throw "SSH key not found: $KeyFilePath"
    }

    $scpExe = (Get-Command scp.exe -ErrorAction Stop).Source

    $scpArgs = @()

    if ($Recursive) {
        $scpArgs += "-r"
    }

    $scpArgs += @(
        "-P", $Port
        "-i", $KeyFilePath
        "-o", "BatchMode=yes"
        "-o", "ConnectTimeout=15"
    )

    if ($DisableHostKeyChecking) {
        # ⚠️ Use ONLY for lab / ephemeral hosts
        $scpArgs += @(
            "-o", "StrictHostKeyChecking=no"
            "-o", "UserKnownHostsFile=/dev/null"
        )
    }

    $remote = "$UserName@${HostName}:`"$DestinationPath`""

    $arguments = $scpArgs + @("`"$SourcePath`"", $remote)

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $scpExe
    $psi.Arguments = ($arguments -join ' ')
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.UseShellExecute        = $false
    $psi.CreateNoWindow         = $true

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $psi

    Write-Verbose "Running: scp $($psi.Arguments)"
    [void]$process.Start()

    $stdout = $process.StandardOutput.ReadToEnd()
    $stderr = $process.StandardError.ReadToEnd()
    $process.WaitForExit()

    if ($process.ExitCode -ne 0) {
        throw @"
SCP failed (exit code $($process.ExitCode))

STDOUT:
$stdout

STDERR:
$stderr
"@
    }

    [pscustomobject]@{
        Source          = $SourcePath
        Destination     = "$UserName@${HostName}:$DestinationPath"
        ExitCode        = $process.ExitCode
        StdOut          = $stdout.Trim()
        StdErr          = $stderr.Trim()
    }
}


function Copy-FromLinuxViaScp {
    <#
    .SYNOPSIS
    Copies files or folders from a remote Linux host to local Windows machine using SCP.
    
    .DESCRIPTION
    Uses scp.exe to copy files from a remote Linux host to the local Windows filesystem.
    Supports both files and directories (with -Recursive switch).
    
    .EXAMPLE
    Copy-FromLinuxViaScp -SourcePath "/var/log/app.log" -HostName "10.0.0.4" -UserName "root" -DestinationPath "C:\Logs\app.log"
    
    .EXAMPLE
    Copy-FromLinuxViaScp -SourcePath "/home/user/data" -HostName "server.example.com" -UserName "azureuser" -DestinationPath "C:\Data" -Recursive
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $SourcePath,          # Remote path on Linux (e.g. /var/log/app.log)

        [Parameter(Mandatory)]
        [string] $HostName,            # Linux IP or DNS

        [Parameter(Mandatory)]
        [string] $UserName,            # Linux user

        [Parameter(Mandatory)]
        [string] $DestinationPath,     # Local Windows path (e.g. C:\Temp\file.txt)

        [int] $Port = 22,

        [string] $KeyFilePath = (Join-Path $HOME ".ssh\id_rsa"),

        [switch] $Recursive,            # Needed for folders
        [switch] $DisableHostKeyChecking
    )

    if ($KeyFilePath -and -not (Test-Path -LiteralPath $KeyFilePath)) {
        throw "SSH key not found: $KeyFilePath"
    }

    # Ensure destination directory exists
    $destDir = Split-Path -Path $DestinationPath -Parent
    if ($destDir -and -not (Test-Path -LiteralPath $destDir)) {
        New-Item -ItemType Directory -Path $destDir -Force | Out-Null
        Write-Verbose "Created destination directory: $destDir"
    }

    $scpExe = (Get-Command scp.exe -ErrorAction Stop).Source

    $scpArgs = @()

    if ($Recursive) {
        $scpArgs += "-r"
    }

    $scpArgs += @(
        "-P", $Port
        "-i", $KeyFilePath
        "-o", "BatchMode=yes"
        "-o", "ConnectTimeout=15"
    )

    if ($DisableHostKeyChecking) {
        # ⚠️ Use ONLY for lab / ephemeral hosts
        $scpArgs += @(
            "-o", "StrictHostKeyChecking=no"
            "-o", "UserKnownHostsFile=/dev/null"
        )
    }

    $remote = "$UserName@${HostName}:`"$SourcePath`""

    $arguments = $scpArgs + @($remote, "`"$DestinationPath`"")

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $scpExe
    $psi.Arguments = ($arguments -join ' ')
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.UseShellExecute        = $false
    $psi.CreateNoWindow         = $true

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $psi

    Write-Verbose "Running: scp $($psi.Arguments)"
    [void]$process.Start()

    $stdout = $process.StandardOutput.ReadToEnd()
    $stderr = $process.StandardError.ReadToEnd()
    $process.WaitForExit()

    if ($process.ExitCode -ne 0) {
        throw @"
SCP failed (exit code $($process.ExitCode))

STDOUT:
$stdout

STDERR:
$stderr
"@
    }

    [pscustomobject]@{
        Source          = "$UserName@${HostName}:$SourcePath"
        Destination     = $DestinationPath
        ExitCode        = $process.ExitCode
        StdOut          = $stdout.Trim()
        StdErr          = $stderr.Trim()
    }
}



# -------------------------
# Examples
# -------------------------
# 1) Simple command
# $r = Invoke-LinuxSshCommand -HostName '10.0.0.4' -UserName 'azureuser' -Command 'uname -a'
# $r | Format-List

# 2) Multiple commands in one SSH session (bash -lc runs a single string)
# $cmd = @"
# hostname
# uptime
# df -h
# systemctl status ssh --no-pager
# "@
# $r = Invoke-LinuxSshCommand -HostName '10.0.0.4' -UserName 'azureuser' -Command $cmd
# $r.RemoteExitCode
# $r.StdOut
# $r.StdErr


#$r = Invoke-LinuxSshCommand -HostName '10.150.103.3' -UserName 'root' -Command '/usr/local/ASR/Vx/bin/AzureRcmCli --getagentconfiginput'
#$r | Format-List


# -------------------------
# Main Installation Script
# -------------------------

# Configuration parameters (paths)
$script:osDetailsScriptPath = "C:\Program Files\Microsoft Azure Push Install Agent\OS_details.sh"
$script:installerBaseFolder = "E:\Software\Agents"
$script:remoteBaseFolder = "/tmp/ASR"
$script:remoteBaseFolderNonRoot = "~/ASR"
$script:rcmProxyAgentPath = "C:\Program Files\Microsoft Azure RCM Proxy Agent\RcmProxyAgent.exe"


# -------------------------
# Helper Functions
# -------------------------

function Get-OsIdentifierFromDetails {
    <#
    .SYNOPSIS
    Parses the OS identifier from the OS details string.
    
    .DESCRIPTION
    Extracts the OS identifier (first field) from OS details output.
    The OS details string format is: "OSID: OS Description: ExitCode"
    Example: "RHEL8-64: Red Hat Enterprise Linux release 8.1 (Ootpa): 0"
    Returns: "RHEL8-64"
    
    .PARAMETER OsDetailsString
    The OS details string returned by Get-RemoteOsDetails.
    
    .EXAMPLE
    Get-OsIdentifierFromDetails -OsDetailsString "RHEL8-64: Red Hat Enterprise Linux release 8.1 (Ootpa): 0"
    # Returns: RHEL8-64
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $OsDetailsString
    )

    if ([string]::IsNullOrWhiteSpace($OsDetailsString)) {
        throw "OS details string is empty or null"
    }

    # Split by colon and get the first field
    $parts = $OsDetailsString -split ":"
    
    if ($parts.Count -lt 1) {
        throw "Invalid OS details format. Expected format: 'OSID: Description: ExitCode'. Got: $OsDetailsString"
    }

    $osIdentifier = $parts[0].Trim()

    if ([string]::IsNullOrWhiteSpace($osIdentifier)) {
        throw "Could not extract OS identifier from: $OsDetailsString"
    }

    return $osIdentifier
}


function Get-InstallerPathForOs {
    <#
    .SYNOPSIS
    Gets the installer file path for a given OS identifier.
    
    .DESCRIPTION
    Searches the installer base folder for a mobility agent installer file
    that matches the given OS identifier. Installer files follow the naming
    convention: Microsoft-ASR_UA_<version>_<OSID>_GA_<date>_release.tar.gz
    
    Example: Microsoft-ASR_UA_9.66.7567.1_RHEL8-64_GA_20Sep2025_release.tar.gz
    
    .PARAMETER OsIdentifier
    The OS identifier (e.g., RHEL8-64, UBUNTU-22.04-64, SLES15-64).
    
    .PARAMETER InstallerFolder
    The folder containing installer files. Defaults to $script:installerBaseFolder.
    
    .EXAMPLE
    Get-InstallerPathForOs -OsIdentifier "RHEL8-64"
    # Returns: E:\Software\Agents\Microsoft-ASR_UA_9.66.7567.1_RHEL8-64_GA_20Sep2025_release.tar.gz
    
    .EXAMPLE
    Get-InstallerPathForOs -OsIdentifier "UBUNTU-22.04-64" -InstallerFolder "D:\Installers"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $OsIdentifier,

        [string] $InstallerFolder = $script:installerBaseFolder
    )

    if (-not (Test-Path -LiteralPath $InstallerFolder -PathType Container)) {
        throw "Installer folder not found: $InstallerFolder"
    }

    # Search for installer file matching the OS identifier
    # Pattern: Microsoft-ASR_UA_*_<OSID>_*.tar.gz
    $searchPattern = "Microsoft-ASR_UA_*_${OsIdentifier}_*.tar.gz"
    
    $installerFiles = Get-ChildItem -Path $InstallerFolder -Filter $searchPattern -File

    if ($installerFiles.Count -eq 0) {
        throw "No installer found for OS identifier '$OsIdentifier' in folder '$InstallerFolder'. Expected pattern: $searchPattern"
    }

    if ($installerFiles.Count -gt 1) {
        # If multiple installers found, pick the most recent one (by name, which includes date)
        Write-Warning "Multiple installers found for OS '$OsIdentifier'. Using the most recent one."
        $installerFiles = $installerFiles | Sort-Object Name -Descending
    }

    $installerPath = $installerFiles[0].FullName
    
    Write-Verbose "Found installer for $OsIdentifier : $installerPath"
    
    return $installerPath
}


function Get-InstallerPathFromOsDetails {
    <#
    .SYNOPSIS
    Gets the installer file path from the OS details string.
    
    .DESCRIPTION
    Combines Get-OsIdentifierFromDetails and Get-InstallerPathForOs to
    directly get the installer path from the OS details output.
    
    .PARAMETER OsDetailsString
    The OS details string returned by Get-RemoteOsDetails.
    
    .PARAMETER InstallerFolder
    The folder containing installer files. Defaults to $script:installerBaseFolder.
    
    .EXAMPLE
    Get-InstallerPathFromOsDetails -OsDetailsString "RHEL8-64: Red Hat Enterprise Linux release 8.1 (Ootpa): 0"
    # Returns: E:\Software\Agents\Microsoft-ASR_UA_9.66.7567.1_RHEL8-64_GA_20Sep2025_release.tar.gz
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $OsDetailsString,

        [string] $InstallerFolder = $script:installerBaseFolder
    )

    $osIdentifier = Get-OsIdentifierFromDetails -OsDetailsString $OsDetailsString
    Write-Host "[Get Installer Path] OS Identifier: $osIdentifier" -ForegroundColor Cyan
    
    $installerPath = Get-InstallerPathForOs -OsIdentifier $osIdentifier -InstallerFolder $InstallerFolder
    Write-Host "[Get Installer Path] Installer: $installerPath" -ForegroundColor Cyan
    
    return $installerPath
}


function New-MobilityAgentConfigFile {
    <#
    .SYNOPSIS
    Creates a mobility agent config file from encoded config input.
    
    .DESCRIPTION
    Uses RcmProxyAgent.exe to create a mobility agent configuration file
    from the encoded config input obtained from the remote agent.
    
    .PARAMETER ConfigInput
    The encoded configuration input string obtained from Get-RemoteConfigInput.
    
    .PARAMETER OutputFolder
    Optional. The folder where the config file will be created.
    Defaults to the user's temp folder.
    
    .PARAMETER RcmProxyAgentPath
    Optional. Path to RcmProxyAgent.exe.
    Defaults to "C:\Program Files\Microsoft Azure RCM Proxy Agent\RcmProxyAgent.exe"
    
    .EXAMPLE
    $configInput = Get-RemoteConfigInput -HostName "10.150.103.3" -UserName "root"
    $configPath = New-MobilityAgentConfigFile -ConfigInput $configInput
    # Returns: C:\Users\<user>\AppData\Local\Temp\mobility_config_20260128_143025_a3b4c5d6.json
    
    .EXAMPLE
    New-MobilityAgentConfigFile -ConfigInput $configInput -OutputFolder "C:\Configs"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $ConfigInput,

        [string] $OutputFolder = $env:TEMP,

        [string] $RcmProxyAgentPath = "C:\Program Files\Microsoft Azure RCM Proxy Agent\RcmProxyAgent.exe"
    )

    # Validate RcmProxyAgent.exe exists
    if (-not (Test-Path -LiteralPath $RcmProxyAgentPath)) {
        throw "RcmProxyAgent.exe not found at: $RcmProxyAgentPath"
    }

    # Ensure output folder exists
    if (-not (Test-Path -LiteralPath $OutputFolder -PathType Container)) {
        New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
        Write-Verbose "Created output folder: $OutputFolder"
    }

    # Generate unique config file path
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $uniqueId = [guid]::NewGuid().ToString().Substring(0, 8)
    $configFileName = "mobility_config_${timestamp}_${uniqueId}.json"
    $configFilePath = Join-Path -Path $OutputFolder -ChildPath $configFileName

    # Generate unique GUIDs for request tracking
    $clientRequestId = [guid]::NewGuid().ToString()
    $activityId = [guid]::NewGuid().ToString()

    Write-Host "[Create Config] Creating mobility agent config file..." -ForegroundColor Yellow
    Write-Host "[Create Config] Output path: $configFilePath" -ForegroundColor Gray
    Write-Host "[Create Config] Client Request ID: $clientRequestId" -ForegroundColor Gray
    Write-Host "[Create Config] Activity ID: $activityId" -ForegroundColor Gray

    # Build arguments for RcmProxyAgent.exe
    $arguments = @(
        "-createmobilityagentconfigfile"
        "-encodedinput"
        $ConfigInput
        "-outputfilepath"
        "`"$configFilePath`""
        "-clientrequestid"
        $clientRequestId
        "-activityid"
        $activityId
    )

    try {
        # Execute RcmProxyAgent.exe
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $RcmProxyAgentPath
        $psi.Arguments = ($arguments -join ' ')
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError  = $true
        $psi.UseShellExecute        = $false
        $psi.CreateNoWindow         = $true

        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $psi

        Write-Verbose "Running: $($psi.FileName) $($psi.Arguments)"
        [void]$process.Start()

        $stdout = $process.StandardOutput.ReadToEnd()
        $stderr = $process.StandardError.ReadToEnd()
        $process.WaitForExit()

        if ($process.ExitCode -ne 0) {
            throw @"
RcmProxyAgent.exe failed (exit code $($process.ExitCode))

STDOUT:
$stdout

STDERR:
$stderr
"@
        }

        # Verify config file was created
        if (-not (Test-Path -LiteralPath $configFilePath)) {
            throw "Config file was not created at expected path: $configFilePath"
        }

        Write-Host "[Create Config] [OK] Config file created successfully" -ForegroundColor Green
        Write-Host ""

        return $configFilePath
    }
    catch {
        Write-Error "[Create Config] [FAILED] Failed to create config file: $_"
        throw
    }
}


# -------------------------
# Cleanup and Verification Functions
# -------------------------

function Remove-RemoteWorkFolder {
    <#
    .SYNOPSIS
    Cleans up the remote work folder created during installation.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $HostName,
        [Parameter(Mandatory)] [string] $UserName,
        [Parameter(Mandatory)] [string] $RemoteWorkFolder,
        [int] $Port = 22
    )

    try {
        Write-Host "[Cleanup] Removing remote work folder: $RemoteWorkFolder" -ForegroundColor Gray
        $cleanupCmd = "rm -rf $RemoteWorkFolder"
        
        $cleanupResult = Invoke-LinuxSshCommand `
            -HostName $HostName `
            -UserName $UserName `
            -Command $cleanupCmd `
            -Port $Port
        
        if ($cleanupResult.RemoteExitCode -eq 0) {
            Write-Host "[Cleanup] [OK] Remote work folder cleaned up" -ForegroundColor Green
        }
        else {
            Write-Warning "[Cleanup] Failed to remove remote work folder (exit code: $($cleanupResult.RemoteExitCode))"
        }
    }
    catch {
        Write-Warning "[Cleanup] Error during cleanup: $_"
    }
}


function Test-MobilityAgentInstallation {
    <#
    .SYNOPSIS
    Verifies that the Mobility Agent is installed and running.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $HostName,
        [Parameter(Mandatory)] [string] $UserName,
        [int] $Port = 22
    )

    Write-Host "[Verify] Verifying Mobility Agent installation..." -ForegroundColor Yellow
    
    # Check if agent binary exists
    $verifyCmd = "test -f /usr/local/ASR/Vx/bin/AzureRcmCli && echo 'INSTALLED' || echo 'NOT_INSTALLED'"
    
    $verifyResult = Invoke-LinuxSshCommand `
        -HostName $HostName `
        -UserName $UserName `
        -Command $verifyCmd `
        -Port $Port
    
    if ($verifyResult.StdOut -match 'INSTALLED') {
        Write-Host "[Verify] [OK] Mobility Agent binary found" -ForegroundColor Green
        
        # Check if service is running
        $serviceCmd = "systemctl is-active svagents 2>/dev/null || service svagents status 2>/dev/null | grep -i running"
        $serviceResult = Invoke-LinuxSshCommand `
            -HostName $HostName `
            -UserName $UserName `
            -Command $serviceCmd `
            -Port $Port
        
        if ($serviceResult.RemoteExitCode -eq 0 -or $serviceResult.StdOut -match 'active|running') {
            Write-Host "[Verify] [OK] Mobility Agent service is running" -ForegroundColor Green
            Write-Host ""
            return $true
        }
        else {
            Write-Warning "[Verify] Mobility Agent is installed but service may not be running"
            Write-Host ""
            return $true
        }
    }
    else {
        Write-Host "[Verify] [FAILED] Mobility Agent installation could not be verified" -ForegroundColor Red
        Write-Host ""
        return $false
    }
}


function Test-InstallationPrerequisites {
    <#
    .SYNOPSIS
    Validates all prerequisites before starting installation.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $HostName,
        [Parameter(Mandatory)] [string] $UserName,
        [int] $Port = 22,
        [string] $KeyFilePath = (Join-Path $HOME ".ssh\id_rsa"),
        [string] $InstallerFolder = $script:installerBaseFolder,
        [string] $OsDetailsScriptPath = $script:osDetailsScriptPath,
        [string] $RcmProxyAgentPath = $script:rcmProxyAgentPath
    )

    Write-Host "[Pre-flight] Running prerequisite checks..." -ForegroundColor Cyan
    Write-Host ""
    
    $allChecksPassed = $true
    
    # Check 1: SSH executable
    try {
        $sshExe = Get-Command ssh.exe -ErrorAction Stop
        Write-Host "[Pre-flight] [OK] SSH client found: $($sshExe.Source)" -ForegroundColor Green
    }
    catch {
        Write-Host "[Pre-flight] [FAILED] SSH client (ssh.exe) not found" -ForegroundColor Red
        $allChecksPassed = $false
    }
    
    # Check 2: SCP executable
    try {
        $scpExe = Get-Command scp.exe -ErrorAction Stop
        Write-Host "[Pre-flight] [OK] SCP client found: $($scpExe.Source)" -ForegroundColor Green
    }
    catch {
        Write-Host "[Pre-flight] [FAILED] SCP client (scp.exe) not found" -ForegroundColor Red
        $allChecksPassed = $false
    }
    
    # Check 3: SSH key file
    if (Test-Path -LiteralPath $KeyFilePath) {
        Write-Host "[Pre-flight] [OK] SSH key found: $KeyFilePath" -ForegroundColor Green
    }
    else {
        Write-Host "[Pre-flight] [FAILED] SSH key not found: $KeyFilePath" -ForegroundColor Red
        $allChecksPassed = $false
    }
    
    # Check 4: OS details script
    if (Test-Path -LiteralPath $OsDetailsScriptPath) {
        Write-Host "[Pre-flight] [OK] OS details script found: $OsDetailsScriptPath" -ForegroundColor Green
    }
    else {
        Write-Host "[Pre-flight] [FAILED] OS details script not found: $OsDetailsScriptPath" -ForegroundColor Red
        $allChecksPassed = $false
    }
    
    # Check 5: Installer folder
    if (Test-Path -LiteralPath $InstallerFolder -PathType Container) {
        $installerCount = (Get-ChildItem -Path $InstallerFolder -Filter "Microsoft-ASR_UA_*.tar.gz" -File).Count
        Write-Host "[Pre-flight] [OK] Installer folder found: $InstallerFolder ($installerCount installers)" -ForegroundColor Green
    }
    else {
        Write-Host "[Pre-flight] [FAILED] Installer folder not found: $InstallerFolder" -ForegroundColor Red
        $allChecksPassed = $false
    }
    
    # Check 6: RcmProxyAgent executable
    if (Test-Path -LiteralPath $RcmProxyAgentPath) {
        Write-Host "[Pre-flight] [OK] RcmProxyAgent found: $RcmProxyAgentPath" -ForegroundColor Green
    }
    else {
        Write-Host "[Pre-flight] [FAILED] RcmProxyAgent not found: $RcmProxyAgentPath" -ForegroundColor Red
        $allChecksPassed = $false
    }
    
    # Check 7: Remote connectivity
    try {
        Write-Host "[Pre-flight] Testing SSH connectivity to $HostName..." -ForegroundColor Gray
        $testCmd = "echo 'CONNECTION_OK'"
        $testResult = Invoke-LinuxSshCommand `
            -HostName $HostName `
            -UserName $UserName `
            -Command $testCmd `
            -Port $Port `
            -KeyFilePath $KeyFilePath
        
        if ($testResult.RemoteExitCode -eq 0 -and $testResult.StdOut -match 'CONNECTION_OK') {
            Write-Host "[Pre-flight] [OK] SSH connection successful to $UserName@$HostName" -ForegroundColor Green
        }
        else {
            Write-Host "[Pre-flight] [FAILED] SSH connection test failed" -ForegroundColor Red
            $allChecksPassed = $false
        }
    }
    catch {
        Write-Host "[Pre-flight] [FAILED] SSH connection failed: $_" -ForegroundColor Red
        $allChecksPassed = $false
    }
    
    # Check 8: Passwordless sudo for non-root users
    if ($UserName -ne "root") {
        try {
            Write-Host "[Pre-flight] Testing passwordless sudo access for non-root user..." -ForegroundColor Gray
            $sudoTestCmd = "echo 'SUDO_OK'"
            $sudoTestResult = Invoke-LinuxSshCommand `
                -HostName $HostName `
                -UserName $UserName `
                -Command $sudoTestCmd `
                -Port $Port `
                -KeyFilePath $KeyFilePath `
                -UseSudo
            
            if ($sudoTestResult.RemoteExitCode -eq 0 -and $sudoTestResult.StdOut -match 'SUDO_OK') {
                Write-Host "[Pre-flight] [OK] Passwordless sudo access confirmed for $UserName" -ForegroundColor Green
            }
            else {
                Write-Host "[Pre-flight] [FAILED] Passwordless sudo not available for $UserName" -ForegroundColor Red
                Write-Host "[Pre-flight]   Configure passwordless sudo by adding this line to /etc/sudoers:" -ForegroundColor Yellow
                Write-Host "[Pre-flight]   $UserName ALL=(ALL) NOPASSWD: ALL" -ForegroundColor Yellow
                $allChecksPassed = $false
            }
        }
        catch {
            Write-Host "[Pre-flight] [FAILED] Sudo access test failed: $_" -ForegroundColor Red
            Write-Host "[Pre-flight]   Mobility Agent installation requires passwordless sudo for non-root users" -ForegroundColor Yellow
            Write-Host "[Pre-flight]   Configure by adding this line to /etc/sudoers using 'visudo':" -ForegroundColor Yellow
            Write-Host "[Pre-flight]   $UserName ALL=(ALL) NOPASSWD: ALL" -ForegroundColor Yellow
            $allChecksPassed = $false
        }
    }
    
    Write-Host ""
    
    if (-not $allChecksPassed) {
        throw "Pre-flight checks failed. Please resolve the issues above before proceeding."
    }
    
    Write-Host "[Pre-flight] [OK] All prerequisite checks passed" -ForegroundColor Green
    Write-Host ""
}


# -------------------------
# Step Functions
# -------------------------

function Get-RemoteOsDetails {
    <#
    .SYNOPSIS
    Gets OS details from the remote Linux machine.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $HostName,
        [Parameter(Mandatory)] [string] $UserName,
        [Parameter(Mandatory)] [string] $RemoteWorkFolder,
        [int] $Port = 22
    )

    Write-Host "[Get OS Details] Getting OS details from remote machine..." -ForegroundColor Yellow
    Write-Host "[Get OS Details] Remote work folder: $RemoteWorkFolder" -ForegroundColor Gray
    
    $osDetailsRemotePath = "$RemoteWorkFolder/OS_details.sh"
    
    # Copy OS_details.sh script to remote machine
    Write-Host "[Get OS Details] Copying OS_details.sh to remote machine..." -ForegroundColor Gray
    $copyResult = Copy-ToLinuxViaScp `
        -SourcePath $script:osDetailsScriptPath `
        -HostName $HostName `
        -UserName $UserName `
        -DestinationPath $osDetailsRemotePath `
        -Port $Port
    Write-Verbose "Copy result: ExitCode=$($copyResult.ExitCode)"
    
    # Make script executable and run it
    $osDetailsCmd = "chmod +x $osDetailsRemotePath && $osDetailsRemotePath 1"
    
    $osDetailsResult = Invoke-LinuxSshCommand `
        -HostName $HostName `
        -UserName $UserName `
        -Command $osDetailsCmd `
        -Port $Port
    
    if ($osDetailsResult.RemoteExitCode -eq 0) {
        Write-Host "[Get OS Details] [OK] OS details retrieved successfully" -ForegroundColor Green
        Write-Host "OS Details:" -ForegroundColor Gray
        Write-Host $osDetailsResult.StdOut -ForegroundColor Gray
    }
    else {
        Write-Host "[Get OS Details] [FAILED] OS details script failed with exit code: $($osDetailsResult.RemoteExitCode)" -ForegroundColor Red
        Write-Host "STDERR: $($osDetailsResult.StdErr)" -ForegroundColor Red
        throw "OS details script failed with exit code $($osDetailsResult.RemoteExitCode). STDERR: $($osDetailsResult.StdErr)"
    }
    Write-Host ""
    
    return $osDetailsResult.StdOut
}


function Copy-InstallerToRemote {
    <#
    .SYNOPSIS
    Copies the installer to the remote machine.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $HostName,
        [Parameter(Mandatory)] [string] $UserName,
        [Parameter(Mandatory)] [string] $RemoteWorkFolder,
        [Parameter(Mandatory)] [string] $InstallerPath,
        [int] $Port = 22
    )

    Write-Host "[Copy Installer] Copying installer to remote machine..." -ForegroundColor Yellow
    Write-Host "[Copy Installer] Remote work folder: $RemoteWorkFolder" -ForegroundColor Gray
    Write-Host "[Copy Installer] Source: $InstallerPath" -ForegroundColor Gray
    
    $installerRemotePath = "$RemoteWorkFolder/installer.tar.gz"
    
    Copy-ToLinuxViaScp `
        -SourcePath $InstallerPath `
        -HostName $HostName `
        -UserName $UserName `
        -DestinationPath $installerRemotePath `
        -Port $Port | Out-Null
    
    Write-Host "[Copy Installer] [OK] Installer copied successfully" -ForegroundColor Green
    Write-Host ""
}


function Invoke-RemoteInstaller {
    <#
    .SYNOPSIS
    Runs the installer on the remote machine.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $HostName,
        [Parameter(Mandatory)] [string] $UserName,
        [Parameter(Mandatory)] [string] $RemoteWorkFolder,
        [int] $Port = 22
    )

    Write-Host "[Run Installer] Running installer on remote machine..." -ForegroundColor Yellow
    Write-Host "[Run Installer] Remote work folder: $RemoteWorkFolder" -ForegroundColor Gray
    
    # Step 1: Extract the installer (no sudo needed)
    Write-Host "[Run Installer] Extracting installer..." -ForegroundColor Gray
    $extractCmd = "cd $RemoteWorkFolder && tar -xzf installer.tar.gz"
    $extractCmd = $extractCmd -replace "\r", ""
    
    $extractResult = Invoke-LinuxSshCommand `
        -HostName $HostName `
        -UserName $UserName `
        -Command $extractCmd `
        -Port $Port
    
    if ($extractResult.RemoteExitCode -ne 0) {
        Write-Host "[Run Installer] [FAILED] Failed to extract installer (exit code: $($extractResult.RemoteExitCode))" -ForegroundColor Red
        Write-Host "STDERR: $($extractResult.StdErr)" -ForegroundColor Red
        throw "Failed to extract installer. Exit code: $($extractResult.RemoteExitCode). STDERR: $($extractResult.StdErr)"
    }
    
    Write-Host "[Run Installer] [OK] Installer extracted" -ForegroundColor Green
    
    # Step 2: Run the installer (with sudo for non-root users only)
    Write-Host "[Run Installer] Executing installer..." -ForegroundColor Gray
    $installCmd = "cd $RemoteWorkFolder && ./install -r MS -v VmWare -q -c CSPrime"
    $installCmd = $installCmd -replace "\r", ""
    
    $installResult = Invoke-LinuxSshCommand `
        -HostName $HostName `
        -UserName $UserName `
        -Command $installCmd `
        -Port $Port `
        -UseSudo
    
    # Exit code 0: Success
    # Exit code 98: Agent already installed (treated as success)
    if ($installResult.RemoteExitCode -eq 0 -or $installResult.RemoteExitCode -eq 98) {
        if ($installResult.RemoteExitCode -eq 98) {
            Write-Host "[Run Installer] [OK] Installer executed (exit code 98: Agent installed with warnings.)" -ForegroundColor Green
        }
        else {
            Write-Host "[Run Installer] [OK] Installer executed successfully" -ForegroundColor Green
        }
        Write-Host "STDOUT: $($installResult.StdOut)" -ForegroundColor Gray
    }
    else {
        Write-Host "[Run Installer] [FAILED] Installer failed with exit code: $($installResult.RemoteExitCode)" -ForegroundColor Red
        Write-Host "STDOUT: $($installResult.StdOut)" -ForegroundColor Gray
        Write-Host "STDERR: $($installResult.StdErr)" -ForegroundColor Red
        throw "Installer failed with exit code $($installResult.RemoteExitCode). STDERR: $($installResult.StdErr)"
    }
    Write-Host ""
    
    return $installResult
}


function Get-RemoteConfigInput {
    <#
    .SYNOPSIS
    Gets the source config input from the agent.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $HostName,
        [Parameter(Mandatory)] [string] $UserName,
        [int] $Port = 22
    )

    Write-Host "[Get Config Input] Getting source config input from agent..." -ForegroundColor Yellow
    
    $getConfigInputCmd = "/usr/local/ASR/Vx/bin/AzureRcmCli --getagentconfiginput"
    
    $configInputResult = Invoke-LinuxSshCommand `
        -HostName $HostName `
        -UserName $UserName `
        -Command $getConfigInputCmd `
        -Port $Port `
        -UseSudo
    
    if ($configInputResult.RemoteExitCode -eq 0) {
        # Parse the output to find the line starting with "getagentconfiginput"
        # Format: getagentconfiginput:ENCODED_STRING
        $lines = $configInputResult.StdOut -split "`r?`n"
        $configInput = $null
        
        foreach ($line in $lines) {
            $trimmedLine = $line.Trim()
            if ($trimmedLine -match '^getagentconfiginput:(.+)$') {
                $configInput = $Matches[1].Trim()
                break
            }
        }
        
        if ([string]::IsNullOrWhiteSpace($configInput)) {
            throw "Could not find 'getagentconfiginput:' line in command output. Output was:`n$($configInputResult.StdOut)"
        }
        
        Write-Host "[Get Config Input] [OK] Source config input retrieved successfully" -ForegroundColor Green
        Write-Host "Config Input (encoded):" -ForegroundColor Gray
        Write-Host $configInput -ForegroundColor Gray
    }
    else {
        Write-Warning "[Get Config Input] Failed to get config input (exit code: $($configInputResult.RemoteExitCode))"
        Write-Host "STDERR: $($configInputResult.StdErr)" -ForegroundColor Red
        throw "Failed to get config input from remote agent"
    }
    Write-Host ""
    
    return $configInput
}


function Test-LocalConfigFile {
    <#
    .SYNOPSIS
    Validates that the local config file exists.
    #>
    [CmdletBinding()]
    param(
        [string] $ConfigJsonPath = $script:configJsonLocalPath
    )

    Write-Host "[Validate Config] Validating source config..." -ForegroundColor Yellow
    Write-Host "[Validate Config] [INFO] Using pre-generated config file: $ConfigJsonPath" -ForegroundColor Cyan
    
    if (-not (Test-Path -LiteralPath $ConfigJsonPath)) {
        Write-Host "Please generate the config file using the Azure portal or CLI." -ForegroundColor Yellow
        throw "Config file not found: $ConfigJsonPath"
    }
    
    Write-Host "[Validate Config] [OK] Config file found" -ForegroundColor Green
    Write-Host ""
    
    return $true
}


function Copy-ConfigToRemote {
    <#
    .SYNOPSIS
    Copies the source config to the remote machine.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $HostName,
        [Parameter(Mandatory)] [string] $UserName,
        [Parameter(Mandatory)] [string] $RemoteWorkFolder,
        [Parameter(Mandatory)] [string] $ConfigJsonPath,
        [int] $Port = 22
    )

    Write-Host "[Copy Config] Copying source config to remote machine..." -ForegroundColor Yellow
    Write-Host "[Copy Config] Remote work folder: $RemoteWorkFolder" -ForegroundColor Gray
    
    $configJsonRemotePath = "$RemoteWorkFolder/config.json"
    
    Copy-ToLinuxViaScp `
        -SourcePath $ConfigJsonPath `
        -HostName $HostName `
        -UserName $UserName `
        -DestinationPath $configJsonRemotePath `
        -Port $Port | Out-Null
    
    Write-Host "[Copy Config] [OK] Config file copied successfully" -ForegroundColor Green
    Write-Host ""
}


function Invoke-RemoteConfiguration {
    <#
    .SYNOPSIS
    Applies the configuration on the remote machine.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $HostName,
        [Parameter(Mandatory)] [string] $UserName,
        [Parameter(Mandatory)] [string] $RemoteWorkFolder,
        [int] $Port = 22
    )

    Write-Host "[Apply Config] Applying configuration on remote machine..." -ForegroundColor Yellow
    Write-Host "[Apply Config] Remote work folder: $RemoteWorkFolder" -ForegroundColor Gray
    
    $configJsonRemotePath = "$RemoteWorkFolder/config.json"
    $applyConfigCmd = "/usr/local/ASR/Vx/bin/UnifiedAgentConfigurator.sh -q -c CSPrime -D -S $configJsonRemotePath"
    
    $configResult = Invoke-LinuxSshCommand `
        -HostName $HostName `
        -UserName $UserName `
        -Command $applyConfigCmd `
        -Port $Port `
        -UseSudo
    
    if ($configResult.RemoteExitCode -eq 0) {
        Write-Host "[Apply Config] [OK] Configuration applied successfully" -ForegroundColor Green
        Write-Host "STDOUT: $($configResult.StdOut)" -ForegroundColor Gray
    }
    else {
        Write-Host "[Apply Config] [FAILED] Configuration failed with exit code: $($configResult.RemoteExitCode)" -ForegroundColor Red
        Write-Host "STDOUT: $($configResult.StdOut)" -ForegroundColor Gray
        Write-Host "STDERR: $($configResult.StdErr)" -ForegroundColor Red
        throw "Configuration failed with exit code $($configResult.RemoteExitCode). STDERR: $($configResult.StdErr)"
    }
    Write-Host ""
    
    return $configResult
}


# -------------------------
# Main Installation Function
# -------------------------

function Install-MobilityAgent {
    <#
    .SYNOPSIS
    Installs and configures the Mobility Agent on a remote Linux machine.
    
    .DESCRIPTION
    Performs the complete Mobility Agent installation workflow:
    - Get OS Details: Gets OS details from remote machine
    - Copy Installer: Copies the installer to remote machine
    - Run Installer: Runs installer on remote machine
    - Get Config Input: Gets source config input
    - Generate Config: Generates config file from remote agent input
    - Copy Config: Copies the config to remote machine
    - Apply Config: Applies configuration on remote machine
    
    .PARAMETER HostName
    The IP address or hostname of the remote Linux machine.
    
    .PARAMETER UserName
    The username for SSH authentication on the remote machine.
    
    .PARAMETER Port
    The SSH port number. Default is 22.
    
    .PARAMETER InstallerPath
    Optional. Override the auto-detected installer path. If not specified,
    the installer is automatically selected based on the remote OS.
    
    .PARAMETER InstallerFolder
    Optional. Override the folder containing installer files. Default is E:\Software\Agents.
    
    .PARAMETER ConfigOutputFolder
    Optional. Folder where generated config files will be saved. Defaults to temp folder.
    
    .EXAMPLE
    Install-MobilityAgent -HostName "10.150.103.3" -UserName "root"
    
    .EXAMPLE
    Install-MobilityAgent -HostName "192.168.1.100" -UserName "azureuser" -Port 2222
    
    .EXAMPLE
    # Install on multiple machines
    $machines = @(
        @{ HostName = "10.150.103.3"; UserName = "root" },
        @{ HostName = "10.150.103.4"; UserName = "root" },
        @{ HostName = "10.150.103.5"; UserName = "azureuser" }
    )
    foreach ($machine in $machines) {
        Install-MobilityAgent -HostName $machine.HostName -UserName $machine.UserName
    }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $HostName,

        [Parameter(Mandatory)]
        [string] $UserName,

        [int] $Port = 22,

        [string] $InstallerPath,

        [string] $InstallerFolder = $script:installerBaseFolder,

        [string] $ConfigOutputFolder = $env:TEMP
    )

    $result = [pscustomobject]@{
        HostName       = $HostName
        UserName       = $UserName
        Success        = $false
        OsDetails      = $null
        OsIdentifier   = $null
        InstallerPath  = $null
        ConfigInput    = $null
        ConfigJsonPath = $null
        ErrorStep      = $null
        ErrorMessage   = $null
    }

    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Mobility Agent Installation Script" -ForegroundColor Cyan
    Write-Host "Target: $UserName@$HostName" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    # Pre-flight checks
    try {
        Test-InstallationPrerequisites -HostName $HostName -UserName $UserName -Port $Port -InstallerFolder $InstallerFolder
    }
    catch {
        $result.ErrorStep = "Pre-flight Checks"
        $result.ErrorMessage = $_.Exception.Message
        Write-Error "[Pre-flight] [FAILED] $_"
        return $result
    }

    # Create unique remote work folder for this installation run
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $uniqueId = [guid]::NewGuid().ToString().Substring(0, 8)
    
    # Use different base folder based on user type
    # Root user: /tmp/ASR, Non-root user: Resolve ~/ASR to actual path
    if ($UserName -eq "root") {
        $remoteBaseFolder = $script:remoteBaseFolder
    }
    else {
        # Resolve ~/ASR to actual absolute path on remote machine
        Write-Host "[Setup] Resolving remote base folder path for user $UserName..." -ForegroundColor Gray
        $resolveCmd = "eval echo $script:remoteBaseFolderNonRoot"
        $resolveResult = Invoke-LinuxSshCommand `
            -HostName $HostName `
            -UserName $UserName `
            -Command $resolveCmd `
            -Port $Port
        
        if ($resolveResult.RemoteExitCode -eq 0 -and -not [string]::IsNullOrWhiteSpace($resolveResult.StdOut)) {
            $remoteBaseFolder = $resolveResult.StdOut.Trim()
            Write-Host "[Setup] [OK] Resolved to: $remoteBaseFolder" -ForegroundColor Green
        }
        else {
            throw "Failed to resolve remote base folder path"
        }
    }
    
    $remoteWorkFolder = "${remoteBaseFolder}/install_${timestamp}_${uniqueId}"
    
    Write-Host "[Setup] Creating remote work folder: $remoteWorkFolder" -ForegroundColor Cyan
    
    # Create the remote work folder
    try {
        $createFolderCmd = "mkdir -p $remoteWorkFolder"
        
        # Only use sudo for root user (creating in /tmp)
        # Non-root users can create folders in their own home directory without sudo
        if ($UserName -eq "root") {
            $createResult = Invoke-LinuxSshCommand `
                -HostName $HostName `
                -UserName $UserName `
                -Command $createFolderCmd `
                -Port $Port `
                -UseSudo
        }
        else {
            $createResult = Invoke-LinuxSshCommand `
                -HostName $HostName `
                -UserName $UserName `
                -Command $createFolderCmd `
                -Port $Port
        }
        
        if ($createResult.RemoteExitCode -ne 0) {
            throw "Failed to create remote work folder. Exit code: $($createResult.RemoteExitCode)"
        }
        
        Write-Host "[Setup] [OK] Remote work folder created" -ForegroundColor Green
        Write-Host ""
    }
    catch {
        $result.ErrorStep = "Setup"
        $result.ErrorMessage = $_.Exception.Message
        Write-Error "[Setup] [FAILED] Failed to create remote work folder: $_"
        return $result
    }

    # Get OS details
    try {
        $result.OsDetails = Get-RemoteOsDetails -HostName $HostName -UserName $UserName -RemoteWorkFolder $remoteWorkFolder -Port $Port
    }
    catch {
        $result.ErrorStep = "Get OS Details"
        $result.ErrorMessage = $_.Exception.Message
        Write-Error "[Get OS Details] [FAILED] Failed to get OS details: $_"
        return $result
    }

    # Determine installer path (auto-detect from OS if not specified)
    try {
        if ([string]::IsNullOrWhiteSpace($InstallerPath)) {
            Write-Host "[Detect Installer] Auto-detecting installer based on OS..." -ForegroundColor Yellow
            $result.OsIdentifier = Get-OsIdentifierFromDetails -OsDetailsString $result.OsDetails
            Write-Host "[Detect Installer] OS Identifier: $($result.OsIdentifier)" -ForegroundColor Cyan
            $result.InstallerPath = Get-InstallerPathForOs -OsIdentifier $result.OsIdentifier -InstallerFolder $InstallerFolder
            Write-Host "[Detect Installer] [OK] Found installer: $($result.InstallerPath)" -ForegroundColor Green
            Write-Host ""
        }
        else {
            $result.InstallerPath = $InstallerPath
            Write-Host "[Detect Installer] Using specified installer: $InstallerPath" -ForegroundColor Cyan
            Write-Host ""
        }
    }
    catch {
        $result.ErrorStep = "Detect Installer"
        $result.ErrorMessage = $_.Exception.Message
        Write-Error "[Detect Installer] [FAILED] Failed to detect installer: $_"
        return $result
    }

    # Copy installer
    try {
        Copy-InstallerToRemote -HostName $HostName -UserName $UserName -RemoteWorkFolder $remoteWorkFolder -InstallerPath $result.InstallerPath -Port $Port
    }
    catch {
        $result.ErrorStep = "Copy Installer"
        $result.ErrorMessage = $_.Exception.Message
        Write-Error "[Copy Installer] [FAILED] Failed to copy installer: $_"
        return $result
    }

    # Run installer
    try {
        Invoke-RemoteInstaller -HostName $HostName -UserName $UserName -RemoteWorkFolder $remoteWorkFolder -Port $Port | Out-Null
    }
    catch {
        $result.ErrorStep = "Run Installer"
        $result.ErrorMessage = $_.Exception.Message
        Write-Error "[Run Installer] [FAILED] Failed to run installer: $_"
        return $result
    }

    # Get config input
    try {
        $result.ConfigInput = Get-RemoteConfigInput -HostName $HostName -UserName $UserName -Port $Port
    }
    catch {
        $result.ErrorStep = "Get Config Input"
        $result.ErrorMessage = $_.Exception.Message
        Write-Error "[Get Config Input] [FAILED] Failed to get source config input: $_"
        return $result
    }

    # Generate config file
    try {
        Write-Host "[Generate Config] Generating config file from remote agent input..." -ForegroundColor Yellow
        $result.ConfigJsonPath = New-MobilityAgentConfigFile -ConfigInput $result.ConfigInput -OutputFolder $ConfigOutputFolder
        Write-Host "[Generate Config] [OK] Config file generated: $($result.ConfigJsonPath)" -ForegroundColor Green
        Write-Host ""
    }
    catch {
        $result.ErrorStep = "Generate Config"
        $result.ErrorMessage = $_.Exception.Message
        Write-Error "[Generate Config] [FAILED] $_"
        return $result
    }

    # Copy config
    try {
        Copy-ConfigToRemote -HostName $HostName -UserName $UserName -RemoteWorkFolder $remoteWorkFolder -ConfigJsonPath $result.ConfigJsonPath -Port $Port
    }
    catch {
        $result.ErrorStep = "Copy Config"
        $result.ErrorMessage = $_.Exception.Message
        Write-Error "[Copy Config] [FAILED] Failed to copy config file: $_"
        return $result
    }

    # Apply configuration
    try {
        Invoke-RemoteConfiguration -HostName $HostName -UserName $UserName -RemoteWorkFolder $remoteWorkFolder -Port $Port | Out-Null
    }
    catch {
        $result.ErrorStep = "Apply Config"
        $result.ErrorMessage = $_.Exception.Message
        Write-Error "[Apply Config] [FAILED] Failed to apply configuration: $_"
        return $result
    }

    # Verify installation
    try {
        $verificationPassed = Test-MobilityAgentInstallation -HostName $HostName -UserName $UserName -Port $Port
        if (-not $verificationPassed) {
            Write-Warning "Installation completed but verification failed. Agent may not be properly configured."
        }
    }
    catch {
        Write-Warning "[Verify] Could not verify installation: $_"
    }

    # Cleanup remote work folder
    # Remove-RemoteWorkFolder -HostName $HostName -UserName $UserName -RemoteWorkFolder $remoteWorkFolder -Port $Port

    # Cleanup generated config file
    if ($result.ConfigJsonPath) {
        try {
            if (Test-Path -LiteralPath $result.ConfigJsonPath) {
                Remove-Item -LiteralPath $result.ConfigJsonPath -Force
                Write-Host "[Cleanup] [OK] Temporary config file removed" -ForegroundColor Green
            }
        }
        catch {
            Write-Warning "[Cleanup] Could not remove temporary config file: $_"
        }
    }

    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Installation Complete for $HostName!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    $result.Success = $true
    return $result
}


function Install-MobilityAgentFromFile {
    <#
    .SYNOPSIS
    Installs Mobility Agent on multiple machines by reading host entries from a file.
    
    .DESCRIPTION
    Reads a text file containing HostName and UserName pairs (one entry per line),
    and calls Install-MobilityAgent for each entry iteratively.
    
    File format (comma, tab, or space separated):
        HostName,UserName
        10.150.103.3,root
        10.150.103.4,root
        192.168.1.100,azureuser
    
    Or with optional Port:
        HostName,UserName,Port
        10.150.103.3,root,22
        10.150.103.4,root,2222
    
    Lines starting with # are treated as comments and skipped.
    Empty lines are also skipped.
    
    .PARAMETER FilePath
    Path to the text file containing the list of machines.
    
    .PARAMETER Delimiter
    The delimiter used in the file. Default is comma (,).
    Supports: comma, tab, space, semicolon.
    
    .PARAMETER InstallerPath
    Optional. Override the default local installer path for all machines.
    
    .PARAMETER StopOnError
    If specified, stops processing remaining machines when an error occurs.
    
    .EXAMPLE
    Install-MobilityAgentFromFile -FilePath "C:\machines.txt"
    
    .EXAMPLE
    Install-MobilityAgentFromFile -FilePath "C:\machines.csv" -Delimiter "," -StopOnError
    
    .EXAMPLE
    # machines.txt content:
    # HostName,UserName
    # 10.150.103.3,root
    # 10.150.103.4,azureuser
    Install-MobilityAgentFromFile -FilePath "C:\machines.txt"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $FilePath,

        [ValidateSet(",", "`t", " ", ";")]
        [string] $Delimiter = ",",

        [string] $InstallerPath,

        [switch] $StopOnError
    )

    if (-not (Test-Path -LiteralPath $FilePath)) {
        throw "File not found: $FilePath"
    }

    $lines = Get-Content -Path $FilePath -Encoding UTF8

    $results = @()
    $machineCount = 0
    $successCount = 0
    $failureCount = 0

    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Batch Installation from File" -ForegroundColor Cyan
    Write-Host "File: $FilePath" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    foreach ($line in $lines) {
        # Skip empty lines and comments
        $trimmedLine = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($trimmedLine) -or $trimmedLine.StartsWith("#")) {
            continue
        }

        # Skip header line if present
        if ($trimmedLine -match "^HostName" -or $trimmedLine -match "^Host" -or $trimmedLine -match "^IP") {
            continue
        }

        # Parse the line
        $parts = $trimmedLine -split [regex]::Escape($Delimiter)
        
        if ($parts.Count -lt 2) {
            Write-Warning "Invalid line format (expected at least HostName and UserName): $trimmedLine"
            continue
        }

        $hostName = $parts[0].Trim()
        $userName = $parts[1].Trim()
        $port = 22

        if ($parts.Count -ge 3 -and $parts[2].Trim() -match '^\d+$') {
            $port = [int]$parts[2].Trim()
        }

        if ([string]::IsNullOrWhiteSpace($hostName) -or [string]::IsNullOrWhiteSpace($userName)) {
            Write-Warning "Invalid entry (empty HostName or UserName): $trimmedLine"
            continue
        }

        $machineCount++

        Write-Host "----------------------------------------" -ForegroundColor Magenta
        Write-Host "Processing machine $machineCount : $userName@$hostName" -ForegroundColor Magenta
        Write-Host "----------------------------------------" -ForegroundColor Magenta
        Write-Host ""

        # Build parameters
        $installParams = @{
            HostName = $hostName
            UserName = $userName
            Port     = $port
        }

        if ($InstallerPath) {
            $installParams['InstallerPath'] = $InstallerPath
        }

        # Call Install-MobilityAgent
        $result = Install-MobilityAgent @installParams
        $results += $result

        if ($result.Success) {
            $successCount++
        }
        else {
            $failureCount++
            if ($StopOnError) {
                Write-Warning "StopOnError is set. Stopping further processing."
                break
            }
        }
    }

    # Summary
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Batch Installation Summary" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Total Machines : $machineCount" -ForegroundColor White
    Write-Host "Successful     : $successCount" -ForegroundColor Green
    Write-Host "Failed         : $failureCount" -ForegroundColor $(if ($failureCount -gt 0) { "Red" } else { "Green" })
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    # Return all results
    return $results
}


# -------------------------
# Example Usage
# -------------------------

# Single machine installation
# Install-MobilityAgent -HostName "10.150.103.3" -UserName "root"

# Multiple machine installation from file
# Install-MobilityAgentFromFile -FilePath "C:\machines.txt"

# Multiple machine installation (inline)
# $machines = @(
#     @{ HostName = "10.150.103.3"; UserName = "root" },
#     @{ HostName = "10.150.103.4"; UserName = "root" },
#     @{ HostName = "10.150.103.5"; UserName = "azureuser" }
# )
# $results = foreach ($machine in $machines) {
#     Install-MobilityAgent -HostName $machine.HostName -UserName $machine.UserName
# }
# $results | Format-Table HostName, UserName, Success, ErrorStep



Install-MobilityAgent -HostName "10.150.103.3" -UserName "azureuser"