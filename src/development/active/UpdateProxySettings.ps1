function Update-ProxySettings {
    [CmdletBinding()]
    param ()

    $homeDir = $HOME ?? [Environment]::GetFolderPath("UserProfile")
    $sshDir = Join-Path $homeDir ".ssh"
    $configPath = Join-Path $sshDir "proxysettings.json"

    if (-not (Test-Path $configPath)) {
        Write-Warning "No existing proxy settings found. Run Set-ProxySettings first."
        return
    }

    $current = Get-Content $configPath | ConvertFrom-Json

    $ProxyHost = Read-Host "Enter Proxy Host [$($current.ProxyHost)]"
    if ([string]::IsNullOrWhiteSpace($ProxyHost)) { $ProxyHost = $current.ProxyHost }

    $UserName = Read-Host "Enter SSH Username [$($current.UserName)]"
    if ([string]::IsNullOrWhiteSpace($UserName)) { $UserName = $current.UserName }

    $KeyFilePath = Read-Host "Enter SSH Key Path [$($current.KeyFilePath)]"
    if ([string]::IsNullOrWhiteSpace($KeyFilePath)) { $KeyFilePath = $current.KeyFilePath }

    $Port = Read-Host "Enter SSH Port [$($current.Port)]"
    if ([string]::IsNullOrWhiteSpace($Port)) { $Port = $current.Port }

    $settings = @{
        ProxyHost   = $ProxyHost
        UserName    = $UserName
        KeyFilePath = $KeyFilePath
        Port        = [int]$Port
    }

    $settings | ConvertTo-Json | Set-Content -Path $configPath -Force
    Write-Host "✅ Updated proxy settings saved to $configPath"
}
