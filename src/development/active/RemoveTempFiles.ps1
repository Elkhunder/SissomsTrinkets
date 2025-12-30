function Remove-TempFiles {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string[]]$ComputerName = @('localhost'),
        [System.Management.Automation.PSCredential]$Credential,
        [string]$DriveLetter = 'C',
        [switch]$Delete,
        [switch]$ConfirmDelete,
        [string]$LogDir = 'C:\WsMgmt\Logs'
    )
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $logPath = Join-Path $LogDir "ProfileCleanup_$($env:COMPUTERNAME)_$stamp.log"
    $transcriptPath = Join-Path $LogDir "ProfileCleanup_$($env:COMPUTERNAME)_$stamp.transcript.log"

    function Write-Log {
        param(
            [Parameter(Mandatory)] [string] $Message,
            [ValidateSet('INFO', 'WARN', 'ERROR')] [string] $Level = 'INFO'
        )

        $line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] $Message"
        $line | Write-Host
        Add-Content -Path $logPath -Value $line
    }
    Start-Transcript -Path $transcriptPath -Append | Out-Null

    try {
        $tempPaths = @(
            "$DriveLetter`:\Temp",
            "$DriveLetter`:\Windows\Temp"
        )

        Write-Log "Starting temporary files removal process."
        Write-Log "Log file: $logPath"
        Write-Log "Transcript: $transcriptPath"

        foreach ($path in $tempPaths) {
            if (Test-Path $path) {
                Write-Log "Processing: $path"
                if ($PSCmdlet.ShouldProcess($path, "Remove all files and subdirectories")) {
                    Remove-Item -Path "$path\*" -Recurse -Force -ErrorAction Stop
                    Write-Log "Removed contents of: $path"
                }
                else {
                    Write-Log "WHATIF/CONFIRM: Would remove contents of: $path"
                }
            }
        }
    }
    catch {
        Write-Log -Level 'ERROR' "An error occurred: $_"
    }
    finally {
        Write-Log "Temporary files removal process completed."
        Stop-Transcript | Out-Null
    }
}