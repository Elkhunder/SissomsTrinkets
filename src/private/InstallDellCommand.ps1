function Install-DellCommand {
    [CmdletBinding()]
    param (
        [string[]]$ComputerName,
        [pscredential]$Credential,
        
        [string]$InstallerName = "Dell-Command-Update-Application_Y5VJV_WIN64_5.5.0_A00_01.EXE",
        [string]$InstallerUrl = "https://dl.dell.com/FOLDER13309338M/2/$InstallerName",
        [string]$TempDir = "C:\Temp"
    )

    $results = @{}  # Hashtable to store per-machine results

    $scriptBlock = {
        param($InstallerUrl, $InstallerName, $TempDir)

        $InstallerPath = Join-Path $TempDir $InstallerName

        try {
            if (-not (Test-Path $TempDir)) {
                New-Item -ItemType Directory -Path $TempDir -Force | Out-Null
            }

            Invoke-WebRequest -Uri $InstallerUrl -OutFile $InstallerPath -Headers @{
                "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
            } -UseBasicParsing

            if (-not (Test-Path $InstallerPath) -or ((Get-Item $InstallerPath).Length -lt 1MB)) {
                return $false
            }

            Start-Process -FilePath $InstallerPath -ArgumentList "/s" -Wait

            $exePaths = @(
                "C:\Program Files\Dell\CommandUpdate\dcu-cli.exe",
                "C:\Program Files (x86)\Dell\CommandUpdate\dcu-cli.exe"
            )

            $installed = $false
            foreach ($exe in $exePaths) {
                if (Test-Path $exe) { $installed = $true; break }
            }

            try {
                Remove-Item $InstallerPath -Force -ErrorAction Stop
            } catch { }

            return $installed
        }
        catch {
            return $false
        }
    }

    if ($ComputerName) {
        foreach ($computer in $ComputerName) {
            try {
                $result = Invoke-Command -ComputerName $computer -Credential $Credential `
                    -ScriptBlock $scriptBlock `
                    -ArgumentList $InstallerUrl, $InstallerName, $TempDir `
                    -ErrorAction Stop
                $results[$computer] = [bool]$result
            }
            catch {
                $results[$computer] = $false
            }
        }
    }
    else {
        try {
            $localResult = & $scriptBlock $InstallerUrl $InstallerName $TempDir
            $results["localhost"] = [bool]$localResult
        }
        catch {
            $results["localhost"] = $false
        }
    }
    
    return $results
}
