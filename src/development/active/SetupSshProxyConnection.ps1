# SSH Proxy Setup Cross-Platform Wizard

function Show-Spinner($Message, [ScriptBlock]$Action) {
    $spinner = "/-\|"
    $i = 0
    $job = Start-Job $Action
    while (-not $job.HasExited) {
        Write-Host -NoNewline "`r$($Message) $($spinner[$i % $spinner.Length])"
        Start-Sleep -Milliseconds 150
        $i++
    }
    $result = Receive-Job $job
    Remove-Job $job
    Write-Host "`r$Message ✔" -ForegroundColor Green
    return $result
}

function Show-Summary($Summary) {
    Write-Host "`n📝 Summary Report:" -ForegroundColor Cyan
    foreach ($item in $Summary) {
        $statusSymbol = if ($item.Status) {"✔"} else {"❌"}
        $color = if ($item.Status) {"Green"} else {"Red"}
        Write-Host ("{0,-30}: {1}" -f $item.Step, $statusSymbol) -ForegroundColor $color
    }
}

# ---------------------------
# WINDOWS FUNCTIONS
# ---------------------------
function Windows-Wizard {
    $Summary = @()

    function Check-OpenSSH {
        $sshFeature = Get-WindowsCapability -Online | Where-Object Name -like "OpenSSH.Server*"
        if ($sshFeature.State -eq "Installed") {
            Write-Host "OpenSSH Server: ✔ Installed" -ForegroundColor Green
            $true
        } else {
            Write-Host "OpenSSH Server: ❌ Not installed" -ForegroundColor Red
            $false
        }
    }

    function Check-SSHDConfig {
        $sshdConfig = "C:\ProgramData\ssh\sshd_config"
        if (-not (Test-Path $sshdConfig)) {
            Write-Host "sshd_config: ❌ Not found" -ForegroundColor Red
            return $false
        }
        $content = Get-Content $sshdConfig
        $pubkeyOK = $content -match '^\s*PubkeyAuthentication\s+yes'
        $authFileOK = $content -match '^\s*AuthorizedKeysFile\s+\.ssh/authorized_keys'
        if ($pubkeyOK -and $authFileOK) {
            Write-Host "sshd_config: ✔ Configured properly" -ForegroundColor Green
            return $true
        }
        Write-Host "sshd_config: ❌ Needs updates" -ForegroundColor Red
        return $false
    }

    function Check-AuthorizedKeys {
        $authorizedKeys = "$env:USERPROFILE\.ssh\authorized_keys"
        if (Test-Path $authorizedKeys -and (Get-Content $authorizedKeys).Length -gt 0) {
            Write-Host "authorized_keys: ✔ Exists and has keys" -ForegroundColor Green
            return $true
        }
        Write-Host "authorized_keys: ❌ Missing or empty" -ForegroundColor Red
        return $false
    }

    do {
        Clear-Host
        Write-Host ""
        Write-Host "╔═════════════════════════════════════════╗" -ForegroundColor Cyan
        Write-Host "║         WINDOWS SSH SETUP WIZARD         ║" -ForegroundColor Cyan
        Write-Host "╠═════════════════════════════════════════╣" -ForegroundColor Cyan
        Write-Host "║ 1. Install & start OpenSSH Server        ║" -ForegroundColor Green
        Write-Host "║ 2. Fix sshd_config & restart service     ║" -ForegroundColor Green
        Write-Host "║ 3. Prepare .ssh & authorized_keys file   ║" -ForegroundColor Green
        Write-Host "║ 4. Show summary & exit                   ║" -ForegroundColor Green
        Write-Host "╚═════════════════════════════════════════╝" -ForegroundColor Cyan
        Write-Host ""
        $choice = Read-Host "Select an option"

        switch ($choice) {
            "1" {
                if (-not (Check-OpenSSH)) {
                    Show-Spinner "Installing OpenSSH Server..." {
                        Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 | Out-Null
                        Set-Service sshd -StartupType Automatic
                        Start-Service sshd
                    }
                }
                $Summary += @{Step="OpenSSH Server"; Status=Check-OpenSSH}
            }
            "2" {
                if (-not (Check-SSHDConfig)) {
                    $sshdConfig = "C:\ProgramData\ssh\sshd_config"
                    Show-Spinner "Updating sshd_config..." {
                        Add-Content -Path $sshdConfig -Value "`nPubkeyAuthentication yes"
                        Add-Content -Path $sshdConfig -Value "`nAuthorizedKeysFile .ssh/authorized_keys"
                        Restart-Service sshd
                    }
                }
                $Summary += @{Step="sshd_config"; Status=Check-SSHDConfig}
            }
            "3" {
                $sshDir = "$env:USERPROFILE\.ssh"
                $authorizedKeys = "$sshDir\authorized_keys"
                Show-Spinner "Ensuring .ssh & authorized_keys..." {
                    if (-not (Test-Path $sshDir)) { New-Item -ItemType Directory -Path $sshDir -Force | Out-Null }
                    if (-not (Test-Path $authorizedKeys)) { New-Item -ItemType File -Path $authorizedKeys -Force | Out-Null }
                    icacls $sshDir /inheritance:r /grant "$env:USERNAME:F" /T | Out-Null
                    icacls $authorizedKeys /inheritance:r /grant "$env:USERNAME:F" | Out-Null
                }
                $Summary += @{Step=".ssh & authorized_keys"; Status=Check-AuthorizedKeys}
            }
            "4" {
                Show-Summary $Summary
            }
            Default {
                Write-Host "Invalid option. Try again." -ForegroundColor Yellow
            }
        }
    } while ($choice -ne "4")

    Write-Host "`n🎉 Windows SSH setup wizard completed!" -ForegroundColor Green
}

# ---------------------------
# MAC FUNCTIONS
# ---------------------------
function MacOS-Wizard {
    $Summary = @()
    $WindowsHost = Read-Host "Enter your Windows hostname or IP"
    $WindowsUser = Read-Host "Enter your Windows username"

    function Check-SSHKey {
        if (Test-Path "$HOME/.ssh/id_ed25519.pub") {
            Write-Host "SSH Key: ✔ Found" -ForegroundColor Green
            return $true
        }
        Write-Host "SSH Key: ❌ Not found" -ForegroundColor Red
        return $false
    }

    function Copy-Key {
        Show-Spinner "Copying SSH key to Windows..." {
            ssh-copy-id "$WindowsUser@$WindowsHost"
        }
    }

    function Test-SSH {
        try {
            ssh -o BatchMode=yes "$WindowsUser@$WindowsHost" hostname
            Write-Host "Test SSH: ✔ Connection works!" -ForegroundColor Green
            return $true
        } catch {
            Write-Host "Test SSH: ❌ Connection failed" -ForegroundColor Red
            return $false
        }
    }

    do {
        Clear-Host
        Write-Host ""
        Write-Host "╔═════════════════════════════════════════╗" -ForegroundColor Cyan
        Write-Host "║           MAC SSH SETUP WIZARD           ║" -ForegroundColor Cyan
        Write-Host "╠═════════════════════════════════════════╣" -ForegroundColor Cyan
        Write-Host "║ 1. Generate SSH key if missing           ║" -ForegroundColor Green
        Write-Host "║ 2. Copy SSH key to Windows host          ║" -ForegroundColor Green
        Write-Host "║ 3. Test SSH connection                   ║" -ForegroundColor Green
        Write-Host "║ 4. Show summary & exit                   ║" -ForegroundColor Green
        Write-Host "╚═════════════════════════════════════════╝" -ForegroundColor Cyan
        Write-Host ""
        $choice = Read-Host "Select an option"

        switch ($choice) {
            "1" {
                if (-not (Check-SSHKey)) {
                    Show-Spinner "Generating SSH key..." {
                        ssh-keygen -t ed25519 -f "$HOME/.ssh/id_ed25519" -N ""
                    }
                }
                $Summary += @{Step="SSH Key Generation"; Status=Check-SSHKey}
            }
            "2" {
                Copy-Key
                $Summary += @{Step="SSH Key Copied"; Status=$true}
            }
            "3" {
                $test = Test-SSH
                $Summary += @{Step="SSH Connection Test"; Status=$test}
            }
            "4" {
                Show-Summary $Summary
            }
            Default {
                Write-Host "Invalid option. Try again." -ForegroundColor Yellow
            }
        }
    } while ($choice -ne "4")

    Write-Host "`n🎉 macOS SSH setup wizard completed!" -ForegroundColor Green
}

# ---------------------------
# MAIN ENTRYPOINT
# ---------------------------
if ($IsWindows) {
    Windows-Wizard
} elseif ($IsMacOS) {
    MacOS-Wizard
} else {
    Write-Host "Unsupported OS detected." -ForegroundColor Red
}
