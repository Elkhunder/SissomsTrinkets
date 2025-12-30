function Start-CleanupImage {
    [CmdletBinding(SupportsShouldProcess)]
    param(
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
        Write-Log "Starting image cleanup process."
        Write-Log "Log file: $logPath"
        Write-Log "Transcript: $transcriptPath"

        if ($PSCmdlet.ShouldProcess("System Image", "Perform cleanup")) {
            $Drive = (Get-CimInstance -ClassName Win32_OperatingSystem).SystemDrive.TrimEnd(':')
            Write-Log "Optimizing volume $Drive"
            Optimize-Volume -DriveLetter $Drive -ErrorAction SilentlyContinue
            Write-Log "Volume optimization completed"
            Write-Log "Running DISM component cleanup"
            Dism.exe /Online /Cleanup-Image /StartComponentCleanup /Quiet | Out-Null
            Write-Log "DISM component cleanup completed"
        }
        else {
            Write-Log "WHATIF/CONFIRM: Would perform image cleanup"
        }
    }
    catch {
        Write-Log -Level 'ERROR' "An error occurred: $_"
    }
    finally {
        Write-Log "Image cleanup process completed."
        Stop-Transcript | Out-Null
    }
}