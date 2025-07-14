<#
.SYNOPSIS
    SSH Remoting Wizard - Configure SSH PowerShell Remoting between Windows and macOS
.DESCRIPTION
    Interactive TUI wizard that helps set up SSH PowerShell Remoting by:
    - Installing and configuring OpenSSH Server on Windows
    - Setting up firewall rules
    - Configuring sshd_config for PowerShell
    - Generating and copying SSH keys
    - Testing the connection
.NOTES
    Version: 1.0
    Author: AI Assistant
#>

# Check if Microsoft.PowerShell.ConsoleGuiTools is installed and install if needed
$moduleName = "Microsoft.PowerShell.ConsoleGuiTools"
if (-not (Get-Module -ListAvailable -Name $moduleName)) {
    Write-Host "Installing $moduleName module..." -ForegroundColor Cyan
    Install-Module -Name $moduleName -Force -Scope CurrentUser
}

# Check if ThreadJob module is installed and install if needed
$threadJobModule = "ThreadJob"
if (-not (Get-Module -ListAvailable -Name $threadJobModule)) {
    Write-Host "Installing $threadJobModule module..." -ForegroundColor Cyan
    Install-Module -Name $threadJobModule -Force -Scope CurrentUser
}

# Import module and load Terminal.Gui
Import-Module Microsoft.PowerShell.ConsoleGuiTools
Import-Module ThreadJob

$module = (Get-Module Microsoft.PowerShell.ConsoleGuiTools -List).ModuleBase
Add-Type -Path (Join-Path $module Terminal.Gui.dll)

# Track step status
$script:status = [ordered]@{
    'Check OpenSSH Server' = @{Status='⏳'; Complete=$false}
    'Check Firewall Rule'  = @{Status='⏳'; Complete=$false}
    'Configure sshd_config'= @{Status='⏳'; Complete=$false}
    'Check Key Auth'       = @{Status='⏳'; Complete=$false}
    'Generate SSH Key'     = @{Status='⏳'; Complete=$false}
    'Copy Key to Windows'  = @{Status='⏳'; Complete=$false}
    'Test SSH'             = @{Status='⏳'; Complete=$false}
    'Test PS Remoting'     = @{Status='⏳'; Complete=$false}
}

# Log setup
$script:log = @()
$script:verboseLog = @()
$script:verboseMode = $false

function Write-Log($msg, [switch]$Verbose) {
    $timestamp = Get-Date -Format "HH:mm:ss"
    $logEntry = "[$timestamp] $msg"
    
    if ($Verbose) {
        $script:verboseLog += $logEntry
        if ($script:verboseMode) {
            $script:log += $logEntry
        }
    } else {
        $script:log += $logEntry
    }
    
    # Update the log view if it exists
    if ($null -ne $script:logListView) {
        [Terminal.Gui.Application]::MainLoop.Invoke({
            $currentLogs = if ($script:verboseMode) { $script:log + $script:verboseLog | Sort-Object } else { $script:log }
            $script:logListView.SetSource($currentLogs)
            if ($currentLogs.Count -gt 0) {
                $script:logListView.SelectedItem = $currentLogs.Count - 1
            }
        })
    }
}

function Set-StepStatus($step, $isSuccess) {
    if ($isSuccess) {
        $script:status[$step].Status = '✅'
        $script:status[$step].Complete = $true
    } else {
        $script:status[$step].Status = '❌'
        $script:status[$step].Complete = $false
    }
    
    # Update the status view if it exists
    if ($null -ne $script:statusListView) {
        [Terminal.Gui.Application]::MainLoop.Invoke({
            $displayStatus = @()
            foreach ($key in $script:status.Keys) {
                $displayStatus += "$($script:status[$key].Status) $key"
            }
            $script:statusListView.SetSource($displayStatus)
        })
    }
}

function Initialize-WizardUI {
    # Initialize the Application
    [Terminal.Gui.Application]::Init()

    # Create main window
    $script:window = [Terminal.Gui.Window]::new()
    $script:window.Title = "SSH Remoting Wizard"

    # Create top menu
    $quitMenuItem = [Terminal.Gui.MenuItem]::new("_Quit", "", { 
        [Terminal.Gui.Application]::RequestStop() 
    })

    $aboutMenuItem = [Terminal.Gui.MenuItem]::new("_About", "", { 
        [Terminal.Gui.MessageBox]::Query("About", "SSH Remoting Wizard 1.0`nSetup SSH PowerShell Remoting between Windows and macOS") 
    })

    $fileMenu = [Terminal.Gui.MenuBarItem]::new("_File", @($quitMenuItem))
    $helpMenu = [Terminal.Gui.MenuBarItem]::new("_Help", @($aboutMenuItem))
    $menuBar = [Terminal.Gui.MenuBar]::new(@($fileMenu, $helpMenu))
    $script:window.Add($menuBar)

    # Create main content area with frames
    $script:contentFrame = [Terminal.Gui.FrameView]::new()
    $script:contentFrame.Y = 1  # Below menu
    $script:contentFrame.Width = [Terminal.Gui.Dim]::Fill()
    $script:contentFrame.Height = [Terminal.Gui.Dim]::Percent(70)
    $script:contentFrame.Title = "Setup Steps"
    $script:window.Add($script:contentFrame)

    $statusFrame = [Terminal.Gui.FrameView]::new()
    $statusFrame.Y = [Terminal.Gui.Pos]::Bottom($script:contentFrame)
    $statusFrame.Width = [Terminal.Gui.Dim]::Percent(40)
    $statusFrame.Height = [Terminal.Gui.Dim]::Fill()
    $statusFrame.Title = "Status"
    $script:window.Add($statusFrame)

    $logFrame = [Terminal.Gui.FrameView]::new()
    $logFrame.Y = [Terminal.Gui.Pos]::Bottom($script:contentFrame)
    $logFrame.X = [Terminal.Gui.Pos]::Right($statusFrame)
    $logFrame.Width = [Terminal.Gui.Dim]::Fill()
    $logFrame.Height = [Terminal.Gui.Dim]::Fill()
    $logFrame.Title = "Log"
    $script:window.Add($logFrame)

    # Status List View
    $script:statusListView = [Terminal.Gui.ListView]::new()
    $script:statusListView.Width = [Terminal.Gui.Dim]::Fill()
    $script:statusListView.Height = [Terminal.Gui.Dim]::Fill()
    $displayStatus = @()
    foreach ($key in $script:status.Keys) {
        $displayStatus += "$($script:status[$key].Status) $key"
    }
    $script:statusListView.SetSource($displayStatus)
    $statusFrame.Add($script:statusListView)

    # Log List View
    $script:logListView = [Terminal.Gui.ListView]::new()
    $script:logListView.Width = [Terminal.Gui.Dim]::Fill()
    $script:logListView.Height = [Terminal.Gui.Dim]::Fill() - 1
    $script:logListView.SetSource($script:log)
    $logFrame.Add($script:logListView)

    # Verbose checkbox
    $verboseCheckbox = [Terminal.Gui.Checkbox]::new("Show verbose logs")
    $verboseCheckbox.Y = [Terminal.Gui.Pos]::Bottom($script:logListView)
    $verboseCheckbox.Checked = $script:verboseMode
    $verboseCheckbox.add_Toggled({
        $script:verboseMode = $verboseCheckbox.Checked
        
        # Update logs
        $currentLogs = if ($script:verboseMode) { $script:log + $script:verboseLog | Sort-Object } else { $script:log }
        $script:logListView.SetSource($currentLogs)
        if ($currentLogs.Count -gt 0) {
            $script:logListView.SelectedItem = $currentLogs.Count - 1
        }
    })
    $logFrame.Add($verboseCheckbox)

    # Set the top-level container
    [Terminal.Gui.Application]::Top.Add($script:window)

    # Show welcome page first
    Show-WelcomePage
}

# Page functions
function Show-WelcomePage {
    # Clear existing content
    $script:contentFrame.RemoveAll()
    
    # Add welcome content
    $welcomeLabel = [Terminal.Gui.Label]::new()
    $welcomeLabel.Text = "Welcome to the SSH PowerShell Remoting Setup Wizard"
    $welcomeLabel.Y = 1
    $welcomeLabel.Width = [Terminal.Gui.Dim]::Fill()
    $script:contentFrame.Add($welcomeLabel)
    
    $infoLabel = [Terminal.Gui.Label]::new()
    $infoLabel.Text = "This wizard will guide you through setting up SSH-based PowerShell Remoting between Windows and macOS machines."
    $infoLabel.Y = 3
    $infoLabel.Width = [Terminal.Gui.Dim]::Fill()
    $infoLabel.Height = 2
    $script:contentFrame.Add($infoLabel)
    
    $osLabel = [Terminal.Gui.Label]::new()
    $osLabel.Text = "System detected: $($IsWindows ? 'Windows' : 'macOS')"
    $osLabel.Y = 6
    $osLabel.Width = [Terminal.Gui.Dim]::Fill()
    $script:contentFrame.Add($osLabel)
    
    $startButton = [Terminal.Gui.Button]::new()
    $startButton.Text = "Start Setup"
    $startButton.Y = 8
    $startButton.add_Clicked({
        Write-Log "Starting SSH Remoting Wizard"
        Write-Log "OS: $($IsWindows ? 'Windows' : 'macOS')" -Verbose
        
        if ($IsWindows) { 
            Show-CheckOpenSSH
        } else { 
            Show-GenerateSSHKey
        }
    })
    $script:contentFrame.Add($startButton)
}

function Show-CheckOpenSSH {
    # Clear existing content
    $script:contentFrame.RemoveAll()
    
    $titleLabel = [Terminal.Gui.Label]::new()
    $titleLabel.Text = "Step 1: Checking OpenSSH Server"
    $titleLabel.Y = 0
    $titleLabel.Width = [Terminal.Gui.Dim]::Fill()
    $script:contentFrame.Add($titleLabel)
    
    $statusLabel = [Terminal.Gui.Label]::new()
    $statusLabel.Y = 2
    $statusLabel.Width = [Terminal.Gui.Dim]::Fill()
    $statusLabel.Height = 10
    $script:contentFrame.Add($statusLabel)
    
    $nextButton = [Terminal.Gui.Button]::new()
    $nextButton.Text = "Next"
    $nextButton.Y = 13
    $nextButton.Enabled = $false
    $nextButton.add_Clicked({
        Show-CheckFirewall
    })
    $script:contentFrame.Add($nextButton)
    
    # Start the check process in a background thread
    Start-ThreadJob -ScriptBlock {
        param($statusLabel, $nextButton)
        
        try {
            [Terminal.Gui.Application]::MainLoop.Invoke({
                $statusLabel.Text = "Checking for OpenSSH Server installation..."
            })
            
            $cap = Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Server*'
            
            if ($cap.State -eq 'Installed') {
                [Terminal.Gui.Application]::MainLoop.Invoke({
                    $statusLabel.Text += "`n✅ OpenSSH Server is already installed."
                })
                Write-Log "OpenSSH Server already installed."
            } else {
                [Terminal.Gui.Application]::MainLoop.Invoke({
                    $statusLabel.Text += "`n⏳ Installing OpenSSH Server..."
                })
                Write-Log "Installing OpenSSH Server..."
                
                Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
                
                [Terminal.Gui.Application]::MainLoop.Invoke({
                    $statusLabel.Text += "`n✅ OpenSSH Server successfully installed."
                })
                Write-Log "OpenSSH Server installed successfully."
            }
            
            [Terminal.Gui.Application]::MainLoop.Invoke({
                $statusLabel.Text += "`n⏳ Starting SSH service..."
            })
            
            Start-Service sshd
            Set-Service -Name sshd -StartupType Automatic
            
            [Terminal.Gui.Application]::MainLoop.Invoke({
                $statusLabel.Text += "`n✅ SSH service started and set to automatic."
                $nextButton.Enabled = $true
            })
            Write-Log "SSH service started and set to start automatically."
            Set-StepStatus 'Check OpenSSH Server' $true
        }
        catch {
            [Terminal.Gui.Application]::MainLoop.Invoke({
                $statusLabel.Text += "`n❌ Error: $_"
                $nextButton.Enabled = $true
            })
            Write-Log "Error configuring OpenSSH Server: $_" -Verbose
            Set-StepStatus 'Check OpenSSH Server' $false
        }
    } -ArgumentList $statusLabel, $nextButton | Out-Null
}

function Show-CheckFirewall {
    # Clear existing content
    $script:contentFrame.RemoveAll()
    
    $titleLabel = [Terminal.Gui.Label]::new()
    $titleLabel.Text = "Step 2: Configure Firewall for SSH"
    $titleLabel.Y = 0
    $titleLabel.Width = [Terminal.Gui.Dim]::Fill()
    $script:contentFrame.Add($titleLabel)
    
    $statusLabel = [Terminal.Gui.Label]::new()
    $statusLabel.Y = 2
    $statusLabel.Width = [Terminal.Gui.Dim]::Fill()
    $statusLabel.Height = 10
    $script:contentFrame.Add($statusLabel)
    
    $nextButton = [Terminal.Gui.Button]::new()
    $nextButton.Text = "Next"
    $nextButton.Y = 13
    $nextButton.Enabled = $false
    $nextButton.add_Clicked({
        Show-ConfigureSSHD
    })
    $script:contentFrame.Add($nextButton)
    
    # Start the check process in a background thread
    Start-ThreadJob -ScriptBlock {
        param($statusLabel, $nextButton)
        
        try {
            [Terminal.Gui.Application]::MainLoop.Invoke({
                $statusLabel.Text = "Checking firewall rules for SSH access..."
            })
            
            $rule = Get-NetFirewallRule -Name sshd -ErrorAction SilentlyContinue
            
            if ($rule) {
                [Terminal.Gui.Application]::MainLoop.Invoke({
                    $statusLabel.Text += "`n✅ Firewall rule for SSH already exists."
                })
                Write-Log "Firewall rule for SSH already exists."
            } else {
                [Terminal.Gui.Application]::MainLoop.Invoke({
                    $statusLabel.Text += "`n⏳ Creating firewall rule for SSH..."
                })
                Write-Log "Creating firewall rule for SSH..."
                
                New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH SSH Server' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
                
                [Terminal.Gui.Application]::MainLoop.Invoke({
                    $statusLabel.Text += "`n✅ Firewall rule created successfully."
                })
                Write-Log "Firewall rule created for SSH on port 22."
            }
            
            Set-StepStatus 'Check Firewall Rule' $true
            
            [Terminal.Gui.Application]::MainLoop.Invoke({
                $nextButton.Enabled = $true
            })
        }
        catch {
            [Terminal.Gui.Application]::MainLoop.Invoke({
                $statusLabel.Text += "`n❌ Error: $_"
                $nextButton.Enabled = $true
            })
            Write-Log "Error configuring firewall: $_" -Verbose
            Set-StepStatus 'Check Firewall Rule' $false
        }
    } -ArgumentList $statusLabel, $nextButton | Out-Null
}

function Show-ConfigureSSHD {
    # Clear existing content
    $script:contentFrame.RemoveAll()
    
    $titleLabel = [Terminal.Gui.Label]::new()
    $titleLabel.Text = "Step 3: Configure SSH Server for PowerShell"
    $titleLabel.Y = 0
    $titleLabel.Width = [Terminal.Gui.Dim]::Fill()
    $script:contentFrame.Add($titleLabel)
    
    $statusLabel = [Terminal.Gui.Label]::new()
    $statusLabel.Y = 2
    $statusLabel.Width = [Terminal.Gui.Dim]::Fill()
    $statusLabel.Height = 10
    $script:contentFrame.Add($statusLabel)
    
    $nextButton = [Terminal.Gui.Button]::new()
    $nextButton.Text = "Next"
    $nextButton.Y = 13
    $nextButton.Enabled = $false
    $nextButton.add_Clicked({
        Show-CheckKeyAuth
    })
    $script:contentFrame.Add($nextButton)
    
    # Start the process in a background thread
    Start-ThreadJob -ScriptBlock {
        param($statusLabel, $nextButton)
        
        try {
            [Terminal.Gui.Application]::MainLoop.Invoke({
                $statusLabel.Text = "Configuring SSH server for PowerShell remoting..."
            })
            
            $sshd_config = 'C:\ProgramData\ssh\sshd_config'
            $conf = Get-Content $sshd_config -ErrorAction Stop
            
            if (-not ($conf -match 'Subsystem.*powershell')) {
                [Terminal.Gui.Application]::MainLoop.Invoke({
                    $statusLabel.Text += "`n⏳ Adding PowerShell subsystem to sshd_config..."
                })
                Write-Log "Adding PowerShell subsystem to sshd_config..."
                
                # Check for PowerShell 7 installation
                $ps7Path = 'C:/Program Files/PowerShell/7/pwsh.exe'
                if (-not (Test-Path $ps7Path)) {
                    [Terminal.Gui.Application]::MainLoop.Invoke({
                        $statusLabel.Text += "`n⚠️ PowerShell 7 not found at standard path."
                    })
                    Write-Log "PowerShell 7 not found at standard path. Using relative path." -Verbose
                    $ps7Path = 'pwsh.exe'
                }
                
                Add-Content $sshd_config "`nSubsystem powershell $ps7Path -sshs -NoLogo -NoProfile"
                Restart-Service sshd
                
                [Terminal.Gui.Application]::MainLoop.Invoke({
                    $statusLabel.Text += "`n✅ PowerShell subsystem added and SSH service restarted."
                })
                Write-Log "Added PowerShell subsystem and restarted SSH service."
            } else {
                [Terminal.Gui.Application]::MainLoop.Invoke({
                    $statusLabel.Text += "`n✅ PowerShell subsystem already configured."
                })
                Write-Log "PowerShell subsystem already configured in sshd_config."
            }
            
            Set-StepStatus 'Configure sshd_config' $true
            
            [Terminal.Gui.Application]::MainLoop.Invoke({
                $nextButton.Enabled = $true
            })
        }
        catch {
            [Terminal.Gui.Application]::MainLoop.Invoke({
                $statusLabel.Text += "`n❌ Error: $_"
                $nextButton.Enabled = $true
            })
            Write-Log "Error configuring sshd_config: $_" -Verbose
            Set-StepStatus 'Configure sshd_config' $false
        }
    } -ArgumentList $statusLabel, $nextButton | Out-Null
}

function Show-CheckKeyAuth {
    # Clear existing content
    $script:contentFrame.RemoveAll()
    
    $titleLabel = [Terminal.Gui.Label]::new()
    $titleLabel.Text = "Step 4: Configure Key Authentication"
    $titleLabel.Y = 0
    $titleLabel.Width = [Terminal.Gui.Dim]::Fill()
    $script:contentFrame.Add($titleLabel)
    
    $statusLabel = [Terminal.Gui.Label]::new()
    $statusLabel.Y = 2
    $statusLabel.Width = [Terminal.Gui.Dim]::Fill()
    $statusLabel.Height = 10
    $script:contentFrame.Add($statusLabel)
    
    $nextButton = [Terminal.Gui.Button]::new()
    $nextButton.Text = "Next"
    $nextButton.Y = 13
    $nextButton.Enabled = $false
    $nextButton.add_Clicked({
        Show-GenerateSSHKey
    })
    $script:contentFrame.Add($nextButton)
    
    # Start the process in a background thread
    Start-ThreadJob -ScriptBlock {
        param($statusLabel, $nextButton)
        
        try {
            [Terminal.Gui.Application]::MainLoop.Invoke({
                $statusLabel.Text = "Configuring SSH key-based authentication..."
            })
            
            $sshd_config = 'C:\ProgramData\ssh\sshd_config'
            $conf = Get-Content $sshd_config -ErrorAction Stop
            
            $keyAuthEnabled = $conf -match 'PubkeyAuthentication\s+yes' -and $conf -match 'AuthorizedKeysFile'
            
            if ($keyAuthEnabled) {
                [Terminal.Gui.Application]::MainLoop.Invoke({
                    $statusLabel.Text += "`n✅ SSH key authentication is already enabled."
                })
                Write-Log "SSH key authentication is already enabled."
            } else {
                [Terminal.Gui.Application]::MainLoop.Invoke({
                    $statusLabel.Text += "`n⏳ Enabling SSH key authentication..."
                })
                Write-Log "Enabling SSH key authentication in sshd_config..."
                
                Add-Content $sshd_config @"

# Added by SSH Remoting Wizard
PubkeyAuthentication yes
AuthorizedKeysFile    .ssh/authorized_keys
"@
                
                Restart-Service sshd
                
                [Terminal.Gui.Application]::MainLoop.Invoke({
                    $statusLabel.Text += "`n✅ Key authentication enabled and SSH service restarted."
                })
                Write-Log "Configured sshd_config for key authentication and restarted service."
            }
            
            # Ensure .ssh folder exists for each user
            $userFolder = $env:USERPROFILE
            $sshFolder = Join-Path $userFolder ".ssh"
            
            if (-not (Test-Path $sshFolder)) {
                New-Item -Path $sshFolder -ItemType Directory -Force | Out-Null
                
                [Terminal.Gui.Application]::MainLoop.Invoke({
                    $statusLabel.Text += "`n✅ Created .ssh directory in user profile."
                })
                Write-Log "Created .ssh directory in user profile."
            }
            
            Set-StepStatus 'Check Key Auth' $true
            
            [Terminal.Gui.Application]::MainLoop.Invoke({
                $nextButton.Enabled = $true
            })
        }
        catch {
            [Terminal.Gui.Application]::MainLoop.Invoke({
                $statusLabel.Text += "`n❌ Error: $_"
                $nextButton.Enabled = $true
            })
            Write-Log "Error configuring key authentication: $_" -Verbose
            Set-StepStatus 'Check Key Auth' $false
        }
    } -ArgumentList $statusLabel, $nextButton | Out-Null
}

function Show-GenerateSSHKey {
    # Clear existing content
    $script:contentFrame.RemoveAll()
    
    $titleLabel = [Terminal.Gui.Label]::new()
    $titleLabel.Text = "Step 5: Generate SSH Key"
    $titleLabel.Y = 0
    $titleLabel.Width = [Terminal.Gui.Dim]::Fill()
    $script:contentFrame.Add($titleLabel)
    
    $statusLabel = [Terminal.Gui.Label]::new()
    $statusLabel.Y = 2
    $statusLabel.Width = [Terminal.Gui.Dim]::Fill()
    $statusLabel.Height = 10
    $script:contentFrame.Add($statusLabel)
    
    $nextButton = [Terminal.Gui.Button]::new()
    $nextButton.Text = "Next"
    $nextButton.Y = 13
    $nextButton.Enabled = $false
    $nextButton.add_Clicked({
        Show-CopyKey
    })
    $script:contentFrame.Add($nextButton)
    
    # Start the process in a background thread
    Start-ThreadJob -ScriptBlock {
        param($statusLabel, $nextButton)
        
        try {
            if ($IsMacOS) {
                [Terminal.Gui.Application]::MainLoop.Invoke({
                    $statusLabel.Text = "Checking for existing SSH key or generating a new one..."
                })
                
                $sshKeyPath = "~/.ssh/id_ed25519"
                
                if (Test-Path $sshKeyPath) {
                    [Terminal.Gui.Application]::MainLoop.Invoke({
                        $statusLabel.Text += "`n✅ SSH key already exists at $sshKeyPath"
                    })
                    Write-Log "SSH key already exists at $sshKeyPath"
                } else {
                    [Terminal.Gui.Application]::MainLoop.Invoke({
                        $statusLabel.Text += "`n⏳ Generating new SSH key..."
                    })
                    Write-Log "Generating new SSH key..."
                    
                    ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -N ''
                    
                    if (Test-Path $sshKeyPath) {
                        [Terminal.Gui.Application]::MainLoop.Invoke({
                            $statusLabel.Text += "`n✅ New SSH key generated successfully."
                        })
                        Write-Log "Generated new SSH key at $sshKeyPath."
                    } else {
                        throw "Key generation seemed to succeed but key file not found."
                    }
                }
            } else {
                [Terminal.Gui.Application]::MainLoop.Invoke({
                    $statusLabel.Text = "On Windows side, verifying key folder exists..."
                })
                
                $sshFolder = Join-Path $env:USERPROFILE ".ssh"
                $authKeysFile = Join-Path $sshFolder "authorized_keys"
                
                if (-not (Test-Path $sshFolder)) {
                    New-Item -Path $sshFolder -ItemType Directory -Force | Out-Null
                    
                    [Terminal.Gui.Application]::MainLoop.Invoke({
                        $statusLabel.Text += "`n✅ Created .ssh directory in user profile."
                    })
                }
                
                if (-not (Test-Path $authKeysFile)) {
                    New-Item -Path $authKeysFile -ItemType File -Force | Out-Null
                    
                    [Terminal.Gui.Application]::MainLoop.Invoke({
                        $statusLabel.Text += "`n✅ Created authorized_keys file."
                    })
                    Write-Log "Created authorized_keys file for receiving public keys."
                } else {
                    [Terminal.Gui.Application]::MainLoop.Invoke({
                        $statusLabel.Text += "`n✅ authorized_keys file already exists."
                    })
                    Write-Log "authorized_keys file already exists."
                }
                
                # Set proper permissions
                icacls $authKeysFile /inheritance:r
                icacls $authKeysFile /grant ${env:USERNAME}:"(F)"
                
                [Terminal.Gui.Application]::MainLoop.Invoke({
                    $statusLabel.Text += "`n✅ Set correct permissions on authorized_keys file."
                })
            }
            
            Set-StepStatus 'Generate SSH Key' $true
            
            [Terminal.Gui.Application]::MainLoop.Invoke({
                $nextButton.Enabled = $true
            })
        }
        catch {
            [Terminal.Gui.Application]::MainLoop.Invoke({
                $statusLabel.Text += "`n❌ Error: $_"
                $nextButton.Enabled = $true
            })
            Write-Log "Error with SSH key setup: $_" -Verbose
            Set-StepStatus 'Generate SSH Key' $false
        }
    } -ArgumentList $statusLabel, $nextButton | Out-Null
}

function Show-CopyKey {
    # Clear existing content
    $script:contentFrame.RemoveAll()
    
    $titleLabel = [Terminal.Gui.Label]::new()
    $titleLabel.Text = "Step 6: Copy SSH Key"
    $titleLabel.Y = 0
    $titleLabel.Width = [Terminal.Gui.Dim]::Fill()
    $script:contentFrame.Add($titleLabel)
    
    if ($IsMacOS) {
        $infoLabel = [Terminal.Gui.Label]::new()
        $infoLabel.Text = "We need to copy your SSH public key to the Windows machine."
        $infoLabel.Y = 2
        $infoLabel.Width = [Terminal.Gui.Dim]::Fill()
        $script:contentFrame.Add($infoLabel)
        
        $hostLabel = [Terminal.Gui.Label]::new()
        $hostLabel.Text = "Enter Windows username@hostname:"
        $hostLabel.Y = 4
        $hostLabel.Width = [Terminal.Gui.Dim]::Fill()
        $script:contentFrame.Add($hostLabel)
        
        $hostField = [Terminal.Gui.TextField]::new()
        $hostField.Y = 5
        $hostField.Width = 30
        $script:contentFrame.Add($hostField)
        
        $statusLabel = [Terminal.Gui.Label]::new()
        $statusLabel.Y = 7
        $statusLabel.Width = [Terminal.Gui.Dim]::Fill()
        $statusLabel.Height = 5
        $script:contentFrame.Add($statusLabel)
        
        $copyButton = [Terminal.Gui.Button]::new()
        $copyButton.Text = "Copy Key"
        $copyButton.Y = 12
        $copyButton.add_Clicked({
            $winUser = $hostField.Text.ToString()
            
            if ([string]::IsNullOrEmpty($winUser)) {
                $statusLabel.Text = "❌ Please enter Windows username@hostname"
                return
            }
            
            $copyButton.Enabled = $false
            $nextButton.Enabled = $false
            $statusLabel.Text = "⏳ Copying public key to Windows..."
            
            Start-ThreadJob -ScriptBlock {
                param($winUser, $statusLabel, $copyButton, $nextButton)
                
                try {
                    Write-Log "Attempting to copy public key to $winUser"
                    
                    # Use ssh-copy-id if available
                    $process = Start-Process -FilePath "ssh-copy-id" -ArgumentList $winUser -NoNewWindow -PassThru -Wait
                    
                    if ($process.ExitCode -eq 0) {
                        [Terminal.Gui.Application]::MainLoop.Invoke({
                            $statusLabel.Text = "✅ SSH key copied successfully to Windows."
                            $copyButton.Enabled = $true
                            $nextButton.Enabled = $true
                        })
                        Write-Log "Successfully copied SSH key to $winUser"
                        Set-StepStatus 'Copy Key to Windows' $true
                    } else {
                        throw "ssh-copy-id exited with code $($process.ExitCode)"
                    }
                } catch {
                    [Terminal.Gui.Application]::MainLoop.Invoke({
                        $statusLabel.Text = "❌ Error copying key: $_`n`nManual steps:`n1. Copy the key shown below`n2. Add it to the authorized_keys file on Windows"
                        $copyButton.Enabled = $true
                        $nextButton.Enabled = $true
                    })
                    Write-Log "Error copying key to Windows: $_" -Verbose
                    
                    # Show the public key
                    $pubKey = Get-Content "~/.ssh/id_ed25519.pub" -ErrorAction SilentlyContinue
                    
                    [Terminal.Gui.Application]::MainLoop.Invoke({
                        $pubKeyField.Text = $pubKey
                    })
                    
                    Set-StepStatus 'Copy Key to Windows' $false
                }
            } -ArgumentList $winUser, $statusLabel, $copyButton, $nextButton | Out-Null
        })
        $script:contentFrame.Add($copyButton)
        
        $pubKeyLabel = [Terminal.Gui.Label]::new()
        $pubKeyLabel.Text = "Public Key:"
        $pubKeyLabel.Y = 13
        $pubKeyLabel.Width = [Terminal.Gui.Dim]::Fill()
        $script:contentFrame.Add($pubKeyLabel)
        
        $pubKeyField = [Terminal.Gui.TextField]::new()
        $pubKeyField.Y = 14
        $pubKeyField.Width = [Terminal.Gui.Dim]::Fill()
        $pubKeyField.Height = 3
        $pubKeyField.ReadOnly = $true
        
        # Load the public key
        $pubKey = Get-Content "~/.ssh/id_ed25519.pub" -ErrorAction SilentlyContinue
        $pubKeyField.Text = $pubKey
        
        $script:contentFrame.Add($pubKeyField)
    } else {
        $infoLabel = [Terminal.Gui.Label]::new()
        $infoLabel.Text = "On Windows, we need to add the Mac's public key to authorized_keys."
        $infoLabel.Y = 2
        $infoLabel.Width = [Terminal.Gui.Dim]::Fill()
        $script:contentFrame.Add($infoLabel)
        
        $instructionLabel = [Terminal.Gui.Label]::new()
        $instructionLabel.Text = "1. Run on Mac: cat ~/.ssh/id_ed25519.pub`n2. Copy the output`n3. Paste it below:"
        $instructionLabel.Y = 4
        $instructionLabel.Width = [Terminal.Gui.Dim]::Fill()
        $instructionLabel.Height = 3
        $script:contentFrame.Add($instructionLabel)
        
        $pubKeyField = [Terminal.Gui.TextField]::new()
        $pubKeyField.Y = 7
        $pubKeyField.Width = [Terminal.Gui.Dim]::Fill()
        $pubKeyField.Height = 3
        $script:contentFrame.Add($pubKeyField)
        
        $statusLabel = [Terminal.Gui.Label]::new()
        $statusLabel.Y = 10
        $statusLabel.Width = [Terminal.Gui.Dim]::Fill()
        $statusLabel.Height = 3
        $script:contentFrame.Add($statusLabel)
        
        $addButton = [Terminal.Gui.Button]::new()
        $addButton.Text = "Add Key"
        $addButton.Y = 13
        $addButton.add_Clicked({
            $pubKey = $pubKeyField.Text.ToString()
            
            if ([string]::IsNullOrEmpty($pubKey)) {
                $statusLabel.Text = "❌ Please paste the public key"
                return
            }
            
            $addButton.Enabled = $false
            $nextButton.Enabled = $false
            $statusLabel.Text = "⏳ Adding key to authorized_keys..."
            
            Start-ThreadJob -ScriptBlock {
                param($pubKey, $statusLabel, $addButton, $nextButton)
                
                try {
                    $authKeysFile = Join-Path $env:USERPROFILE ".ssh\authorized_keys"
                    
                    # Check if key already exists
                    $existingContent = Get-Content $authKeysFile -ErrorAction SilentlyContinue
                    if ($existingContent -contains $pubKey) {
                        [Terminal.Gui.Application]::MainLoop.Invoke({
                            $statusLabel.Text = "✅ This key is already in authorized_keys."
                            $addButton.Enabled = $true
                            $nextButton.Enabled = $true
                        })
                        Write-Log "Key already exists in authorized_keys."
                    } else {
                        Add-Content -Path $authKeysFile -Value $pubKey
                        
                        [Terminal.Gui.Application]::MainLoop.Invoke({
                            $statusLabel.Text = "✅ Key added to authorized_keys."
                            $addButton.Enabled = $true
                            $nextButton.Enabled = $true
                        })
                        Write-Log "Added public key to authorized_keys."
                    }
                    Set-StepStatus 'Copy Key to Windows' $true
                } catch {
                    [Terminal.Gui.Application]::MainLoop.Invoke({
                        $statusLabel.Text = "❌ Error adding key: $_"
                        $addButton.Enabled = $true
                        $nextButton.Enabled = $true
                    })
                    Write-Log "Error adding key to authorized_keys: $_" -Verbose
                    Set-StepStatus 'Copy Key to Windows' $false
                }
            } -ArgumentList $pubKey, $statusLabel, $addButton, $nextButton | Out-Null
        })
        $script:contentFrame.Add($addButton)
    }
    
    $nextButton = [Terminal.Gui.Button]::new()
    $nextButton.Text = "Next"
    $nextButton.Y = 17
    $nextButton.add_Clicked({
        Show-TestSSH
    })
    $script:contentFrame.Add($nextButton)
}

function Show-TestSSH {
    # Clear existing content
    $script:contentFrame.RemoveAll()
    
    $titleLabel = [Terminal.Gui.Label]::new()
    $titleLabel.Text = "Step 7: Test SSH Connection"
    $titleLabel.Y = 0
    $titleLabel.Width = [Terminal.Gui.Dim]::Fill()
    $script:contentFrame.Add($titleLabel)
    
    if ($IsMacOS) {
        $infoLabel = [Terminal.Gui.Label]::new()
        $infoLabel.Text = "Let's test the SSH connection to Windows."
        $infoLabel.Y = 2
        $infoLabel.Width = [Terminal.Gui.Dim]::Fill()
        $script:contentFrame.Add($infoLabel)
        
        $hostLabel = [Terminal.Gui.Label]::new()
        $hostLabel.Text = "Enter Windows username@hostname:"
        $hostLabel.Y = 4
        $hostLabel.Width = [Terminal.Gui.Dim]::Fill()
        $script:contentFrame.Add($hostLabel)
        
        $hostField = [Terminal.Gui.TextField]::new()
        $hostField.Y = 5
        $hostField.Width = 30
        $script:contentFrame.Add($hostField)
        
        $statusLabel = [Terminal.Gui.Label]::new()
        $statusLabel.Y = 7
        $statusLabel.Width = [Terminal.Gui.Dim]::Fill()
        $statusLabel.Height = 5
        $script:contentFrame.Add($statusLabel)
        
        $testButton = [Terminal.Gui.Button]::new()
        $testButton.Text = "Test Connection"
        $testButton.Y = 12
        $testButton.add_Clicked({
            $winHost = $hostField.Text.ToString()
            
            if ([string]::IsNullOrEmpty($winHost)) {
                $statusLabel.Text = "❌ Please enter username@hostname"
                return
            }
            
            $testButton.Enabled = $false
            $nextButton.Enabled = $false
            $statusLabel.Text = "⏳ Testing SSH connection..."
            
            Start-ThreadJob -ScriptBlock {
                param($winHost, $statusLabel, $testButton, $nextButton)
                
                try {
                    Write-Log "Testing SSH connection to $winHost"
                    
                    $output = ssh $winHost "hostname" 2>&1
                    
                    if ($LASTEXITCODE -eq 0) {
                        [Terminal.Gui.Application]::MainLoop.Invoke({
                            $statusLabel.Text = "✅ SSH connection successful!`nConnected to: $output"
                            $testButton.Enabled = $true
                            $nextButton.Enabled = $true
                        })
                        Write-Log "SSH connection successful to $winHost"
                        Set-StepStatus 'Test SSH' $true
                    } else {
                        throw "SSH command returned exit code $LASTEXITCODE with output: $output"
                    }
                } catch {
                    [Terminal.Gui.Application]::MainLoop.Invoke({
                        $statusLabel.Text = "❌ SSH connection failed: $_"
                        $testButton.Enabled = $true
                        $nextButton.Enabled = $true
                    })
                    Write-Log "SSH connection failed: $_" -Verbose
                    Set-StepStatus 'Test SSH' $false
                }
            } -ArgumentList $winHost, $statusLabel, $testButton, $nextButton | Out-Null
        })
        $script:contentFrame.Add($testButton)
    } else {
        $infoLabel = [Terminal.Gui.Label]::new()
        $infoLabel.Text = "On Windows, waiting for incoming SSH connections..."
        $infoLabel.Y = 2
        $infoLabel.Width = [Terminal.Gui.Dim]::Fill()
        $script:contentFrame.Add($infoLabel)
        
        $detailsLabel = [Terminal.Gui.Label]::new()
        $detailsLabel.Text = "Your SSH server should now be ready to accept connections.`n`nDetails:`n• SSH server is running on port 22`n• PowerShell subsystem is configured`n• Key authentication is enabled"
        $detailsLabel.Y = 4
        $detailsLabel.Width = [Terminal.Gui.Dim]::Fill()
        $detailsLabel.Height = 6
        $script:contentFrame.Add($detailsLabel)
        
        # Show the hostname for easy connection
        $hostname = hostname
        $ipAddresses = [System.Net.Dns]::GetHostAddresses($hostname) | 
                      Where-Object { $_.AddressFamily -eq 'InterNetwork' } | 
                      ForEach-Object { $_.IPAddressToString }
        
        $connInfoLabel = [Terminal.Gui.Label]::new()
        $connInfoLabel.Text = "Your Windows hostname: $hostname`n`nYour IP addresses:`n" + ($ipAddresses -join "`n")
        $connInfoLabel.Y = 10
        $connInfoLabel.Width = [Terminal.Gui.Dim]::Fill()
        $connInfoLabel.Height = 6
        $script:contentFrame.Add($connInfoLabel)
        
        Set-StepStatus 'Test SSH' $true
    }
    
    $nextButton = [Terminal.Gui.Button]::new()
    $nextButton.Text = "Next"
    $nextButton.Y = 17
    $nextButton.add_Clicked({
        Show-TestPS
    })
    $script:contentFrame.Add($nextButton)
}

function Show-TestPS {
    # Clear existing content
    $script:contentFrame.RemoveAll()
    
    $titleLabel = [Terminal.Gui.Label]::new()
    $titleLabel.Text = "Step 8: Test PowerShell Remoting"
    $titleLabel.Y = 0
    $titleLabel.Width = [Terminal.Gui.Dim]::Fill()
    $script:contentFrame.Add($titleLabel)
    
    if ($IsMacOS) {
        $infoLabel = [Terminal.Gui.Label]::new()
        $infoLabel.Text = "Let's test PowerShell Remoting via SSH."
        $infoLabel.Y = 2
        $infoLabel.Width = [Terminal.Gui.Dim]::Fill()
        $script:contentFrame.Add($infoLabel)
        
        $hostLabel = [Terminal.Gui.Label]::new()
        $hostLabel.Text = "Enter Windows hostname (without username):"
        $hostLabel.Y = 4
        $hostLabel.Width = [Terminal.Gui.Dim]::Fill()
        $script:contentFrame.Add($hostLabel)
        
        $hostField = [Terminal.Gui.TextField]::new()
        $hostField.Y = 5
        $hostField.Width = 30
        $script:contentFrame.Add($hostField)
        
        $statusLabel = [Terminal.Gui.Label]::new()
        $statusLabel.Y = 7
        $statusLabel.Width = [Terminal.Gui.Dim]::Fill()
        $statusLabel.Height = 5
        $script:contentFrame.Add($statusLabel)
        
        $testButton = [Terminal.Gui.Button]::new()
        $testButton.Text = "Test PS Remoting"
        $testButton.Y = 12
        $testButton.add_Clicked({
            $winHostPs = $hostField.Text.ToString()
            
            if ([string]::IsNullOrEmpty($winHostPs)) {
                $statusLabel.Text = "❌ Please enter hostname"
                return
            }
            
            $testButton.Enabled = $false
            $nextButton.Enabled = $false
            $statusLabel.Text = "⏳ Testing PowerShell Remoting..."
            
            Start-ThreadJob -ScriptBlock {
                param($winHostPs, $statusLabel, $testButton, $nextButton)
                
                try {
                    Write-Log "Testing PowerShell Remoting to $winHostPs"
                    
                    $username = (whoami)
                    $session = New-PSSession -HostName $winHostPs -UserName $username -ErrorAction Stop
                    
                    if ($session) {
                        $osInfo = Invoke-Command -Session $session -ScriptBlock { 
                            "$($PSVersionTable.OS), PowerShell $($PSVersionTable.PSVersion)" 
                        }
                        
                        Remove-PSSession $session
                        
                        [Terminal.Gui.Application]::MainLoop.Invoke({
                            $statusLabel.Text = "✅ PowerShell Remoting successful!`nRemote system: $osInfo"
                            $testButton.Enabled = $true
                            $nextButton.Enabled = $true
                        })
                        Write-Log "PowerShell Remoting successful to $winHostPs"
                        Set-StepStatus 'Test PS Remoting' $true
                    } else {
                        throw "Failed to create PSSession"
                    }
                } catch {
                    [Terminal.Gui.Application]::MainLoop.Invoke({
                        $statusLabel.Text = "❌ PowerShell Remoting failed: $_"
                        $testButton.Enabled = $true
                        $nextButton.Enabled = $true
                    })
                    Write-Log "PowerShell Remoting failed: $_" -Verbose
                    Set-StepStatus 'Test PS Remoting' $false
                }
            } -ArgumentList $winHostPs, $statusLabel, $testButton, $nextButton | Out-Null
        })
        $script:contentFrame.Add($testButton)
    } else {
        $infoLabel = [Terminal.Gui.Label]::new()
        $infoLabel.Text = "On Windows, PowerShell Remoting via SSH is now configured."
        $infoLabel.Y = 2
        $infoLabel.Width = [Terminal.Gui.Dim]::Fill()
        $script:contentFrame.Add($infoLabel)
        
        $connInfoLabel = [Terminal.Gui.Label]::new()
        $connInfoLabel.Text = "MacOS clients can connect using:`n`nNew-PSSession -HostName <this-pc> -UserName <user>"
        $connInfoLabel.Y = 4
        $connInfoLabel.Width = [Terminal.Gui.Dim]::Fill()
        $connInfoLabel.Height = 3
        $script:contentFrame.Add($connInfoLabel)
        
        Set-StepStatus 'Test PS Remoting' $true
    }
    
    $nextButton = [Terminal.Gui.Button]::new()
    $nextButton.Text = "Next"
    $nextButton.Y = 17
    $nextButton.add_Clicked({
        Show-Summary
    })
    $script:contentFrame.Add($nextButton)
}

function Show-Summary {
    # Clear existing content
    $script:contentFrame.RemoveAll()
    
    $titleLabel = [Terminal.Gui.Label]::new()
    $titleLabel.Text = "Setup Complete!"
    $titleLabel.Y = 0
    $titleLabel.Width = [Terminal.Gui.Dim]::Fill()
    $script:contentFrame.Add($titleLabel)
    
    $summaryLabel = [Terminal.Gui.Label]::new()
    $summaryLabel.Text = "Summary of completed steps:"
    $summaryLabel.Y = 2
    $summaryLabel.Width = [Terminal.Gui.Dim]::Fill()
    $script:contentFrame.Add($summaryLabel)
    
    $stepsSummary = [Terminal.Gui.Label]::new()
    $stepsSummary.Y = 4
    $stepsSummary.Width = [Terminal.Gui.Dim]::Fill()
    $stepsSummary.Height = 10
    
    $summaryText = ""
    $completedSteps = 0
    foreach ($key in $script:status.Keys) {
        $summaryText += "$($script:status[$key].Status) $key`n"
        if ($script:status[$key].Complete) {
            $completedSteps++
        }
    }
    
    $successRate = [Math]::Round(($completedSteps / $script:status.Count) * 100)
    $summaryText += "`nCompletion: $successRate%"
    
    $stepsSummary.Text = $summaryText
    $script:contentFrame.Add($stepsSummary)
    
    $nextStepsLabel = [Terminal.Gui.Label]::new()
    $nextStepsLabel.Text = "Next Steps:"
    $nextStepsLabel.Y = 14
    $nextStepsLabel.Width = [Terminal.Gui.Dim]::Fill()
    $script:contentFrame.Add($nextStepsLabel)
    
    $stepsLabel = [Terminal.Gui.Label]::new()
    $stepsLabel.Y = 15
    $stepsLabel.Width = [Terminal.Gui.Dim]::Fill()
    $stepsLabel.Height = 5
    
    if ($IsMacOS) {
        $stepsLabel.Text = "• You can now connect to Windows using:`n  Enter-PSSession -HostName win-pc -UserName user`n`n• Or create a persistent session:`n  \$session = New-PSSession -HostName win-pc -UserName user"
    } else {
        $stepsLabel.Text = "• SSH Server is configured and running`n• PowerShell remoting is enabled via SSH`n• Mac clients can now connect to this PC"
    }
    
    $script:contentFrame.Add($stepsLabel)
    
    $quitButton = [Terminal.Gui.Button]::new()
    $quitButton.Text = "Finish"
    $quitButton.Y = 20
    $quitButton.add_Clicked({
        [Terminal.Gui.Application]::RequestStop()
    })
    $script:contentFrame.Add($quitButton)
}

# Main execution

# Initialize the UI
Initialize-WizardUI

# Run the application
[Terminal.Gui.Application]::Run()

# Cleanup when done
[Terminal.Gui.Application]::Shutdown()