function Get-ProxySession {
    [CmdletBinding()]
    param()

    $homeDir = $HOME ?? [Environment]::GetFolderPath("UserProfile")
    $sshDir = Join-Path $homeDir ".ssh"
    $configPath = Join-Path $sshDir "proxysettings.json"

    if (-not (Test-Path $configPath)) {
        Write-Verbose "No proxy settings file found."
        return $null
    }

    try {
        $config = Get-Content $configPath | ConvertFrom-Json
        Write-Verbose "Proxy settings loaded: Host=$($config.ProxyHost)"

        $session = New-PSSession -HostName $config.ProxyHost `
                                 -Port ($config.Port ?? 22) `
                                 -UserName $config.UserName `
                                 -KeyFilePath $config.KeyFilePath

        return $session
    }
    catch {
        Write-Warning "Failed to create proxy session: $_"
        return $null
    }
}
