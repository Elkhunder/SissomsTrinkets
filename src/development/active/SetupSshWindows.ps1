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
    
    $ruleName = "OpenSSH-Server-In-TCP"
    $firewallRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    
    if (-not $firewallRule) {
        try {
            New-NetFirewallRule -Name $ruleName -DisplayName $ruleName -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 -ErrorAction Stop
            Write-Host "Firewall rule created successfully." -ForegroundColor Green
        }
        catch {
            Write-Host "Failed to create firewall rule: $_" -ForegroundColor Red
            exit 1
        }
    }
    else {
        Write-Host "Firewall rule already exists." -ForegroundColor Green
    }
}

function ConfigureSSHKeys {
    Write-Host "Configuring SSH key authentication..." -ForegroundColor Cyan
    
    $sshDir = "$env:ProgramData\ssh"
    $adminSshDir = "$env:USERPROFILE\.ssh"
    $authorizedKeysPath = "$env:ProgramData\ssh\administrators_authorized_keys"
    
    # Create .ssh directory if it doesn't exist
    if (-not (Test-Path $adminSshDir)) {
        New-Item -ItemType Directory -Path $adminSshDir -Force | Out-Null
    }
    
    # Generate SSH key pair if they don't exist
    if (-not (Test-Path "$adminSshDir\id_rsa")) {
        Write-Host "Generating new SSH key pair..." -ForegroundColor Yellow
        try {
            ssh-keygen -t rsa -b 4096 -f "$adminSshDir\id_rsa" -N '""' -q
            Write-Host "SSH key pair generated successfully." -ForegroundColor Green
        }
        catch {
            Write-Host "Failed to generate SSH keys: $_" -ForegroundColor Red
            exit 1
        }
    }
    
    # Display public key for user to copy to Mac
    if (Test-Path "$adminSshDir\id_rsa.pub") {
        $publicKey = Get-Content "$adminSshDir\id_rsa.pub"
        Write-Host ""
        Write-Host "=============================================" -ForegroundColor Yellow
        Write-Host "Your public key (add this to ~/.ssh/authorized_keys on your Mac if you want to connect from Windows to Mac):" -ForegroundColor Yellow
        Write-Host $publicKey -ForegroundColor White
        Write-Host "=============================================" -ForegroundColor Yellow
        Write-Host ""
    }
    
    # Configure authorized_keys for incoming connections
    if (-not (Test-Path $authorizedKeysPath)) {
        New-Item -ItemType File -Path $authorizedKeysPath -Force | Out-Null
    }
    
    # Set proper permissions on SSH directories and files
    try {
        icacls $sshDir /reset
        icacls $sshDir /inheritance:r
        icacls $sshDir /grant "SYSTEM:(OI)(CI)F" /grant "Administrators:(OI)(CI)F"
        
        if (Test-Path $authorizedKeysPath) {
            icacls $authorizedKeysPath /inheritance:r
            icacls $authorizedKeysPath /grant "SYSTEM:F" /grant "Administrators:F"
        }
        
        Write-Host "SSH directory permissions configured." -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to configure permissions: $_" -ForegroundColor Red
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
    
    if (-not $pwshPath) {
        Write-Host "PowerShell 7 is not installed." -ForegroundColor Yellow
        Write-Host "Download it from: https://aka.ms/powershell-release?tag=stable" -ForegroundColor Yellow
        return
    }

    # Set as default shell for SSH
    $newShellValue = "$pwshPath"
    New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value $newShellValue -PropertyType String -Force
    
    Write-Host "PowerShell 7 configured as default SSH shell." -ForegroundColor Green
    Write-Host "New users will get PowerShell 7 when connecting via SSH." -ForegroundColor Green
}

# Add this to the main execution block:
try {
    InstallOpenSSHServer
    ConfigureSSHService
    ConfigureFirewall
    SetPowerShell7AsDefaultShell  # <-- Add this line
    ConfigureSSHKeys
    ConfigureSSHConfig
    ShowConnectionInstructions
    
    Write-Host "Windows SSH setup completed successfully!" -ForegroundColor Green
    Write-Host "You can now SSH into this machine from your Mac." -ForegroundColor Green
}
catch {
    Write-Host "An error occurred during setup: $_" -ForegroundColor Red
    exit 1
}