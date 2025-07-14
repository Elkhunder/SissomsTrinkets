function Set-ProxySettings {
    [CmdletBinding()]
    param ()

    $homeDir = $HOME ?? [Environment]::GetFolderPath("UserProfile")
    $sshDir = Join-Path $homeDir ".ssh"
    $configPath = Join-Path $sshDir "proxysettings.json"

    if (-not (Test-Path $sshDir)) {
        New-Item -Path $sshDir -ItemType Directory | Out-Null
    }

    $ProxyHost = Read-Host "Enter Proxy Host (e.g. jumpbox.domain.com)"
    $UserName  = Read-Host "Enter SSH Username"
    $KeyFilePath = Read-Host "Enter full path to SSH private key"
    $Port = Read-Host "Enter SSH port (default 22)"
    if ([string]::IsNullOrWhiteSpace($Port)) { $Port = 22 }

    $settings = @{
        ProxyHost   = $ProxyHost
        UserName    = $UserName
        KeyFilePath = $KeyFilePath
        Port        = [int]$Port
    }

    $settings | ConvertTo-Json | Set-Content -Path $configPath -Force

    Write-Host "✅ Proxy settings saved to $configPath"
}