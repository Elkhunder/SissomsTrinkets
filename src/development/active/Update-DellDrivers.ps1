Update-DellDrivers{
    [CmdletBinding()]
    param(
        [string[]]$ComputerName,
        [pscredential]$Credential,
        [Parameter(Mandatory=$true)]
        [ValidateSet("BIOS", "Chipset", "Network", "Video", "Audio", "Storage", "Application", "Security", "Other")]
        [string]$Category,
        [string]$DownloadUrl = "https://dl.dell.com/FOLDER13309338M/2/Dell-Command-Update-Application_Y5VJV_WIN64_5.5.0_A00_01.EXE",
        [switch]$UninstallWhenDone,
        [switch]$RebootWhenFinished,
        [switch]$Intune,
        [switch]$ClassicCore
    )
    # Map category to DCU CLI argument
    $categoryMap = @{
        "BIOS"        = "bios"
        "Chipset"     = "chipset"
        "Network"     = "network"
        "Video"       = "video"
        "Audio"       = "audio"
        "Storage"     = "storage"
        "Application" = "application"
        "Security"    = "security"
        "Other"       = "other"
    }
    Get-DellUpdateStatus -ComputerName $_.ComputerName -Credential $Credential -Category $Category -ApplyUpdates -RebootWhenFinished:$RebootWhenFinished -UninstallWhenDone:$UninstallWhenDone -Intune:$Intune -ClassicCore:$ClassicCore


    $dcuExe = "C:\Program Files (x86)\Dell\CommandUpdate\dcu-cli.exe"

    # Check if Dell Command | Update is installed
    if (-not (Test-Path $dcuExe)) {
        Write-Error "Dell Command | Update is not installed. Please install it first."
        return
    }

    # Check for updates
    Write-Host "Checking for Dell updates..."
    
    $updateCheck = & $dcuExe /checkForUpdates -silent

    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to check for updates. Please ensure Dell Command | Update is functioning correctly."
        return
    } else {
        if ($updateCheck -match "No updates available") {
            Write-Host "✅ No updates available."
        }
    }
    $catArg = $categoryMap[$Category]

    # Run Dell Command | Update for the specified category
    & "dcu-cli.exe" /scan -c=$catArg /applyUpdates -silent

    if ($LASTEXITCODE -eq 0) {
        Write-Host "Dell drivers for category '$Category' updated successfully."
    } else {
        Write-Error "Failed to update Dell drivers for category '$Category'."
    }
}