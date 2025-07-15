$sshDir = "$env:USERPROFILE\.ssh"
$authKeys = Join-Path $sshDir 'authorized_keys'
$pubKeyPath = "$env:USERPROFILE\id_ed25519.pub"

if (-not (Test-Path $sshDir)) {
    New-Item -ItemType Directory -Path $sshDir -Force | Out-Null
}

if (-not (Test-Path $authKeys)) {
    New-Item -ItemType File -Path $authKeys -Force | Out-Null
}

$pubKeyContent = Get-Content $pubKeyPath -Raw

$currentKeys = Get-Content $authKeys -Raw

if ($currentKeys -notmatch [regex]::Escape($pubKeyContent)) {
    Add-Content -Path $authKeys -Value $pubKeyContent
    Write-Host '✅ Public key added.'
} else {
    Write-Host 'ℹ️ Public key already present.'
}

# Set permissions correctly
$user = "$env:USERDOMAIN\$env:USERNAME"
icacls $sshDir /inheritance:r | Out-Null
icacls $sshDir /grant "${user}:(OI)(CI)F" "SYSTEM:(OI)(CI)F" | Out-Null
icacls $authKeys /inheritance:r | Out-Null
icacls $authKeys /grant "$user:F" "SYSTEM:F" | Out-Null

Write-Host '🔒 Permissions set on .ssh directory.'