function Get-DellUpdateStatus {
    param(
        [string]$DownloadUrl = "https://dl.dell.com/FOLDER13309338M/2/Dell-Command-Update-Application_Y5VJV_WIN64_5.5.0_A00_01.EXE",
        [pscredential]$Credential,
        [DellCommandCategory[]]$Categories,
        [switch]$UninstallWhenDone,
        [switch]$ApplyUpdates,
        [switch]$RebootWhenFinished,
        [switch]$Intune,
        [switch]$ClassicCore
    )

    # Map category to DCU CLI argument
    $categoryMap = @{
        [DellCommandCategory]::BIOS        = "bios"
        [DellCommandCategory]::Chipset     = "chipset"
        [DellCommandCategory]::Network     = "network"
        [DellCommandCategory]::Video       = "video"
        [DellCommandCategory]::Audio       = "audio"
        [DellCommandCategory]::Storage     = "storage"
        [DellCommandCategory]::Application = "application"
        [DellCommandCategory]::Security    = "security"
        [DellCommandCategory]::Other       = "other"
    }
    $catArgs = ($Categories | ForEach-Object { $categoryMap[$_] }) -join ","

    $instances = Confirm-DellCommandExists -ComputerName $ComputerName -Credential $Credential -DownloadUrl $DownloadUrl | Where-Object Status -eq [DellCommandStatus]::Installed
    
    foreach ($instance in $instances){
        $dcuCli = $instance.Path
        
        & $dcuCli /scan -report="C:\Temp\" -silent -updateType="$catArgs"
    }

    $tempDir = "C:\Temp\"
    $installerPath = "$tempDir\DellCommandUpdate_5.5.0.exe"

    # Ensure temp folder exists
    if (-not (Test-Path $tempDir)) { New-Item -ItemType Directory -Path $tempDir | Out-Null }

    # Find existing Dell Command | Update installation
    $dcuExe = @(
        "C:\Program Files\Dell\CommandUpdate\dcu-cli.exe",
        "C:\Program Files (x86)\Dell\CommandUpdate\dcu-cli.exe"
    ) | Where-Object { Test-Path $_ } | Select-Object -First 1

    if (-not $dcuExe) {
        Write-Host "Dell Command | Update not found. Installing..."
        Write-Host "Dell Command | Downloading..."
        # Download installer with User-Agent to avoid CDN block
        Invoke-WebRequest -Uri $DownloadUrl -OutFile $installerPath -Headers @{
            "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0 Safari/537.36"
        }

        # Verify file is a real EXE (not HTML)
        if ((Get-Item $installerPath).Length -lt 1MB) {
            Write-Error "Download failed or returned an HTML error page. Exiting."
            return
        }
        Write-Host "Dell Command | Download Complete"
        Write-Host "Dell Command | Installing..."
        # Install silently
        Start-Process -FilePath $installerPath -ArgumentList "/s" -Wait

        # Locate installed EXE
        $dcuExe = @(
            "C:\Program Files\Dell\CommandUpdate\dcu-cli.exe",
            "C:\Program Files (x86)\Dell\CommandUpdate\dcu-cli.exe"
        ) | Where-Object { Test-Path $_ } | Select-Object -First 1

        if (-not $dcuExe) {
            Write-Error "Dell Command | Update installation failed."
            return
        }
        Write-Host "✅ Dell Command | Update installed successfully."
    }

    # Generate scan report

    & $dcuExe /scan -report="C:\Temp\" -silent -updateType="bios,firmware,driver"


    # Parse XML
    [xml]$scanReport = Get-Content "C:\Temp\DCUApplicableUpdates.xml"
    $pendingUpdates = @($scanReport.updates.update) | Where-Object { $_ -ne $null}

    
    $pendingUpdates
    if (-not $pendingUpdates -or $pendingUpdates.Count -eq 0){
        Write-Host "`n✅ System is fully up to date.`n"
    }
    else {
        Write-Host "`n==== Dell Updates Available ===="
        $pendingUpdates | Select-Object `
            name,
            version,
            date,
            urgency,
            type,
            category | 
        Format-Table -AutoSize
    } 

    # Apply updates if requested
    if ($ApplyUpdates -and $pendingUpdates.Count -gt 0) {
        
        $biosUpdates = @($pendingUpdates | Where-Object { $_.type -eq "BIOS"})
        $remainingUpdates = @($pendingUpdates | Where-Object { $_.type -ne "BIOS"})

        if ($biosUpdates.Count -gt 0){
            if($Intune){
                & $dcuExe /configure -biosPassword="rTLM2p5!" -silent
            }
            elseif ($ClassicCore) {
                & $dcuExe /configure -biosPassword="yous2323" -silent
            }
            else{
                Write-Host "`nProvide Bios Password..."
                & $dcuExe /configure -secureBiosPassword -silent
            }
                Write-Host "`nApplying Dell BIOS updates..."
                & $dcuExe /applyUpdates -updateType=bios -autoSuspendBitLocker=enable -silent -reboot=disable
            }
        if ($remainingUpdates.Count -gt 0) {
            
            Write-Host "`nApplying Dell updates (excluding applications)..."
            & $dcuExe /applyUpdates -updateType="firmware,driver" -autoSuspendBitLocker=enable -silent -reboot=disable
            Write-Host "✅ Update process complete. Reboot if BIOS/Firmware updates were installed."
        } else {
            Write-Host "`nNo other updates to apply."
        }
    }

    # Optional uninstall
    if ($UninstallWhenDone) {
        $answer = Read-Host "Do you want to uninstall Dell Command | Update? (Y/N)"
        if ($answer -match '^[Yy]$') {
            Write-Host "Uninstalling Dell Command | Update..."
            $product = Get-WmiObject Win32_Product | Where-Object { $_.Name -like "Dell Command | Update*" }
            if ($product) {
                $product.Uninstall() | Out-Null
                Write-Host "✅ Dell Command | Update uninstalled."
            } else {
                Write-Warning "Dell Command | Update not found in Win32_Product."
            }
        }
    }

    # Cleanup
    Remove-Item $installerPath -Force -ErrorAction SilentlyContinue

    if($RebootWhenFinished){
        Restart-Computer -Force
    }
}
