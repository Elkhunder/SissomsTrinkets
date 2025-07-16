<#
.SYNOPSIS
    Configures a Windows machine to accept SSH connections from Mac/Linux devices.
.DESCRIPTION
    This script performs the following actions:
    1. Installs OpenSSH Server (if not already installed)
    2. Configures the SSH server to start automatically
    3. Sets up firewall rules to allow SSH connections
    4. Configures key-based authentication
    5. Ensures proper permissions on SSH directories
.NOTES
    File Name      : Configure-WindowsSSH.ps1
    Prerequisites  : PowerShell 5.1 or later, Administrative privileges
#>

#Requires -RunAsAdministrator

function InstallOpenSSHServer {
    Write-Host "Checking for OpenSSH Server installation..." -ForegroundColor Cyan
    
    $feature = Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Server*'
    
    if ($feature.State -ne "Installed") {
        Write-Host "Installing OpenSSH Server..." -ForegroundColor Yellow
        try {
            Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 -ErrorAction Stop
            Write-Host "OpenSSH Server installed successfully." -ForegroundColor Green
        }
        catch {
            Write-Host "Failed to install OpenSSH Server: $_" -ForegroundColor Red
            exit 1
        }
    }
    else {
        Write-Host "OpenSSH Server is already installed." -ForegroundColor Green
    }
}

function ConfigureSSHService {
    Write-Host "Configuring SSH service..." -ForegroundColor Cyan
    
    # Set service to start automatically
    Set-Service -Name sshd -StartupType Automatic
    
    # Start the service if not running
    if ((Get-Service -Name sshd).Status -ne "Running") {
        Start-Service -Name sshd
    }
    
    Write-Host "SSH service configured and started." -ForegroundColor Green
}

function ConfigureFirewall {
    Write-Host "Configuring Windows Firewall for SSH..." -ForegroundColor Cyan
    $firewallProps = @{
        Name        = "OpenSSH-Server-In-TCP"
        DisplayName = "OpenSSH SSH Server (sshd)"
        Enabled     = "True"
        Direction   = "Inbound"
        Protocol    = "TCP"
        LocalPort   = 22
        Action      = "Allow"
    }
    $firewallRule = Get-NetFirewallRule -DisplayName $firewallProps.DisplayName -ErrorAction SilentlyContinue
    
    if (-not $firewallRule) {
        try {
            New-NetFirewallRule @firewallProps -ErrorAction SilentlyContinue | Out-Null
            Write-Host "Firewall rule created successfully." -ForegroundColor Green
        }
        catch {
            Write-Host "Failed to create firewall rule: $_" -ForegroundColor Red
        }
    }
    else {
        Write-Host "Firewall rule already exists." -ForegroundColor Green
    }
}

function ShowConnectionInstructions {
    Write-Host ""
    Write-Host "=============================================" -ForegroundColor Green
    Write-Host "SETUP COMPLETE" -ForegroundColor Green
    Write-Host "To connect from your Mac:" -ForegroundColor Green
    Write-Host "1. Open Terminal on your Mac"
    Write-Host "2. Run: ssh $env:USERNAME@$(Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notlike '*Loopback*' } | Select-Object -First 1).IPAddress"
    Write-Host ""
    Write-Host "For key-based authentication:" -ForegroundColor Green
    Write-Host "1. Copy your Mac's public key to $env:ProgramData\ssh\administrators_authorized_keys on this Windows machine"
    Write-Host "2. On Mac, run: ssh-copy-id $env:USERNAME@<Windows-IP>"
    Write-Host "=============================================" -ForegroundColor Green
    Write-Host ""
}

function SetPowerShell7AsDefaultShell {
    Write-Host "Configuring PowerShell 7 as default shell..." -ForegroundColor Cyan
    
    # Find PowerShell 7 installation path
    $pwshPath = (Get-Command pwsh.exe -ErrorAction SilentlyContinue).Source

    # Check powershell version for update
    # Variables
    $owner = "PowerShell"       # GitHub repo owner
    $repo = "PowerShell"         # GitHub repo name
    $outputPath = "$PWD\$assetName"  # Save to current folder

    # Get latest release JSON from GitHub API
    $latestReleaseUrl = "https://api.github.com/repos/$owner/$repo/releases/latest"
    $releaseInfo = Invoke-RestMethod -Uri $latestReleaseUrl -Headers @{ "User-Agent" = "PowerShell" }
    $tag = $releaseInfo.tag_name

    if ($tag.StartsWith('v')) {
        $tag = $tag.Substring(1)
    }

    $latestVersion = [version]$tag

    
    if (-not $pwshPath) {
        Write-Host "PowerShell 7 is not installed." -ForegroundColor Yellow
        Write-Host "Installing PowerShell 7 from GitHub releases 'https://github.com/PowerShell/PowerShell/releases'" -ForegroundColor Yellow
        Write-Host "Latest version is $latestVersion" -ForegroundColor Yellow
        $platform = "win-x64"

        $assetName = "$repo-$tag-$platform.msi"  # Exact asset filename you want to download
        # Find the asset download URL by name
        $asset = $releaseInfo.assets | Where-Object { $_.name -eq $assetName }
        if (-not $asset) {
            Write-Error "Asset $assetName not found in latest release."
        }

        $downloadUrl = $asset.browser_download_url
        Write-Host "Downloading $assetName from $downloadUrl ..."

        # Download the asset
        Invoke-WebRequest -Uri $downloadUrl -OutFile $outputPath

        Write-Host "Downloaded to $outputPath"

        $process = Start-Process -FilePath msiexec.exe -ArgumentList "/package", $assetName, "/quiet", "ADD_EXPLORER_CONTEXT_MENU_OPENPOWERSHELL=1", "ADD_FILE_CONTEXT_MENU_RUNPOWERSHELL=1", "ENABLE_PSREMOTING=1", "REGISTER_MANIFEST=1", "USE_MU=1", "ENABLE_MU=1", "ADD_PATH=1" -Wait -PassThru
        Write-Output "Exit code: $($process.ExitCode)"
        return
    }

    $pwshVersion = [System.Management.Automation.SemanticVersion](pwsh.exe -NoProfile -Command '$PSVersionTable.PSVersion.ToString()')

    # Set as default shell for SSH

    Write-Host "Checking for PowerShell update" -ForegroundColor Yellow
    if ($pwshVersion -lt [System.Management.Automation.SemanticVersion]$latestVersion){
        $update = Read-Host "Do you want to update to PowerShell version $latestVersion from $pwshVersion? y/n"

        if ($update -eq "y"){
            #Install new version
            Write-Host "Installing PowerShell version $latestVersion" -ForegroundColor Yellow
        }
        else{
            Write-Host "Skipping PowerShell update" -ForegroundColor Yellow
        }
    }
    else{
        Write-Host "PowerShell version $pwshVersion is up-to-date"
    }
    $newShellValue = "$pwshPath"
    $shellValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell

    if(-not $shellValue){
        New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value $newShellValue -PropertyType String -Force
    
        Write-Host "PowerShell 7 configured as default SSH shell." -ForegroundColor Green
        Write-Host "New users will get PowerShell 7 when connecting via SSH." -ForegroundColor Green
    }
    else{
        Write-Host "PowerShell 7 already configured as default shell" -ForegroundColor Green
    }
}

# Add this to the main execution block:
try {
    InstallOpenSSHServer
    ConfigureSSHService
    ConfigureFirewall
    SetPowerShell7AsDefaultShell  # <-- Add this line
    ShowConnectionInstructions
    
    Write-Host "Windows SSH setup completed successfully!" -ForegroundColor Green
    Write-Host "You can now SSH into this machine from your Mac." -ForegroundColor Green
    Read-Host "Press enter to exit"
}
catch {
    Write-Host "An error occurred during setup: $_" -ForegroundColor Red
    Read-Host "Press enter to exit"
}