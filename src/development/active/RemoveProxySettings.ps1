function Remove-ProxySettings {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param()

    # Use a separate variable to avoid clobbering the built-in $HOME
    $homeDir = $HOME ?? [Environment]::GetFolderPath("UserProfile")
    $sshDir = Join-Path $homeDir ".ssh"
    $configPath = Join-Path $sshDir "proxysettings.json"

    if (-not (Test-Path $configPath)) {
        Write-Warning "No proxy settings file found at $configPath."
        return
    }

    if ($PSCmdlet.ShouldProcess($configPath, "Delete proxy settings file")) {
        Remove-Item $configPath -Force
        Write-Host "✅ Proxy settings removed from $configPath"
    }
}
