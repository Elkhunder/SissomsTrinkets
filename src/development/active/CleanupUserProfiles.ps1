function Invoke-ProfileCleanup {
  [CmdletBinding(SupportsShouldProcess)]
  param(
    [int]    $TargetFreeGB = 75,
    [string] $DriveLetter  = 'C',
    [string] $LogDir       = 'C:\WsMgmt\Logs'
  )

  function Get-FreeGB([string]$Letter) {
    (Get-PSDrive -Name $Letter).Free / 1GB
  }

  # Prepare log paths
  New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
  $stamp          = Get-Date -Format 'yyyyMMdd_HHmmss'
  $logPath        = Join-Path $LogDir "ProfileCleanup_$($env:COMPUTERNAME)_$stamp.log"
  $transcriptPath = Join-Path $LogDir "ProfileCleanup_$($env:COMPUTERNAME)_$stamp.transcript.log"

  function Write-Log {
    param(
      [Parameter(Mandatory)] [string] $Message,
      [ValidateSet('INFO','WARN','ERROR')] [string] $Level = 'INFO'
    )

    $line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] $Message"
    $line | Write-Host
    Add-Content -Path $logPath -Value $line
  }

  # Notify user of locations immediately
  Write-Host "Log file: $logPath"
  Write-Host "Transcript: $transcriptPath"

  Start-Transcript -Path $transcriptPath -Append | Out-Null

  try {
    Write-Log "Starting profile cleanup. Target free space: $TargetFreeGB GB on drive $DriveLetter`:."
    Write-Log "Log file: $logPath"
    Write-Log "Transcript: $transcriptPath"
    Write-Log "WhatIfPreference (inside function scope): $WhatIfPreference"

    $startFree = [math]::Round((Get-FreeGB $DriveLetter), 2)
    Write-Log "Initial free space: $startFree GB"

    $profileRoot = "$DriveLetter`:\Users"

    # Oldest first
    $profileFolders =
      Get-ChildItem -Path $profileRoot -Directory -Force |
      Sort-Object LastWriteTime

    # Query once
    $profiles = Get-CimInstance -ClassName Win32_UserProfile

    foreach ($folder in $profileFolders) {
      $free = [math]::Round((Get-FreeGB $DriveLetter), 2)
      if ($free -ge $TargetFreeGB) {
        Write-Log "Reached target free space ($free GB >= $TargetFreeGB GB). Stopping."
        break
      }

      $p = $profiles | Where-Object {
        $_.LocalPath -eq $folder.FullName -and -not $_.Special -and -not $_.Loaded
      }

      if ($null -eq $p) {
        Write-Log "Skipping (no removable Win32_UserProfile match, or Special/Loaded): $($folder.FullName) (LastWrite: $($folder.LastWriteTime))" "WARN"
        continue
      }

      $target = $p.LocalPath
      $action = "Remove user profile (SID: $($p.SID)); free-space target: $TargetFreeGB GB"

      # Master -WhatIf / -Confirm handling
      if ($PSCmdlet.ShouldProcess($target, $action)) {
        Write-Log "Removing profile: $target (LastWrite: $($folder.LastWriteTime), SID: $($p.SID))"
        Remove-CimInstance -InputObject $p -Confirm:$false

        $after = [math]::Round((Get-FreeGB $DriveLetter), 2)
        Write-Log "Removed. Free space now: $after GB"
      }
      else {
        Write-Log "WHATIF/CONFIRM: Would remove profile: $target (LastWrite: $($folder.LastWriteTime), SID: $($p.SID))"
      }
    }

    $endFree = [math]::Round((Get-FreeGB $DriveLetter), 2)
    Write-Log "Done. Final free space: $endFree GB"
  }
  catch {
    Write-Log "Unhandled error: $($_.Exception.Message)" "ERROR"
    throw
  }
  finally {
    Stop-Transcript | Out-Null
    Write-Log "Finished. Review log at: $logPath and transcript at: $transcriptPath"
  }
}
