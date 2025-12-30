function Get-SpacePlan {
    <#
    .SYNOPSIS
    Optimized disk space cleanup script with hang detection and timeout protection.
    
    .DESCRIPTION
    Scans and identifies large folders on Windows systems for cleanup. Includes timeout protection,
    hang detection, and comprehensive verbose logging for troubleshooting.
    
    .PARAMETER ComputerName
    Target computer(s). Default is localhost.
    
    .PARAMETER Credential
    Credentials for remote execution.
    
    .PARAMETER Drive
    Drive letter to scan (default: C).
    
    .PARAMETER TargetFreeSpace
    Target free space in GB (default: 75).
    
    .PARAMETER FolderTimeoutSeconds
    Timeout per folder scan (default: 45 seconds).
    
    .PARAMETER ScanTimeoutSeconds
    Overall scan timeout (default: 600 seconds = 10 minutes).
    
    .PARAMETER MaxRecursionDepth
    Maximum folder depth to recurse (default: 8, protects against loops).
    
    .PARAMETER IncludePSTFiles
    Include Outlook PST file locations in scan (default: true).
    
    .PARAMETER PassThru
    Return result objects.
    
    .PARAMETER ShowProgress
    Show real-time scanning progress.
    
    .EXAMPLE
    Invoke-SpacePlan -Credential $cred -ComputerName "SERVER01" -Verbose
    
    .EXAMPLE
    Invoke-SpacePlan -ComputerName "SERVER01","SERVER02"  -Verbose
    #>
    [CmdletBinding()]
    param (
        [Parameter()] [string[]]$ComputerName = @('localhost'),
        [Parameter ()] [PSCredential]$Credential,
        [Parameter()] [ValidatePattern('^\d+$')] [int] $TargetFreeSpace = 75,
        [Parameter()] [int] $MinFileSize = 1,
        [Parameter()] [hashtable] $ScanLocationMap,
        [Parameter()] [int] $ScanTimeoutSeconds = 300,
        [Parameter()] [int] $FolderTimeoutSeconds = 60,
        [Parameter()] [int]$MaxRecursionDepth = 8,
        [Parameter()] [switch] $IncludeUserProfiles,
        [Parameter()] [switch]$IncludePSTFiles,
        [Parameter()] [switch]$ShowProgress
    )
    begin {
        Write-Verbose "[$([DateTime]::Now.ToString('HH:mm:ss'))] Begin block started"
        
        if ($ScanLocationMap) {
            $locations = ($ScanLocationMap.Keys -join ', ')
            Write-Host ("ScanLocationMap provided; merging additional locations: {0}" -f $locations)

        }
        if (-not $ScanLocationMap){$ScanLocationMap = @{}}
        $ScanLocationMap += @{
            'Temp'          = 'C:\Temp'
            'Logs'          = 'C:\Logs'
        }
        if ($IncludeUserProfiles) {
            $ScanLocationMap['UserProfiles'] = 'C:\Users'
        }
        Write-Verbose "  ScanLocationMap: $($ScanLocationMap | Out-String)"
        # Build immutable config object
        Write-Verbose "Building configuration object"
        $cfg = [pscustomobject]@{
            TargetFreeSpaceGB   = $TargetFreeSpace
            MinFileSize       = $MinFileSize
            FolderTimeoutSeconds= $FolderTimeoutSeconds
            TotalTimeoutSeconds = $TotalTimeoutSeconds
            MaxRecursionDepth   = $MaxRecursionDepth
            IncludeUserProfiles = [bool]$IncludeUserProfiles
            IncludeUserCaches   = [bool]$IncludeUserCaches
            IncludePSTFiles     = [bool]$IncludePSTFiles
            ScanLocationMap     = $ScanLocationMap
            ProfileIncludeRegex = $ProfileIncludeRegex
            ProfileExcludeRegex = $ProfileExcludeRegex
            ExcludePatterns     = $ExcludePatterns
            PathsInclude        = [string[]]$PathsInclude
            Delete              = [bool]$Delete
            ConfirmDelete       = [bool]$ConfirmDelete
            PassThru            = [bool]$PassThru
            ShowProgress        = [bool]$ShowProgress
            Verbose             = [bool]$PSCmdlet.MyInvocation.BoundParameters['Verbose']
        }

        Write-Verbose "[$([DateTime]::Now.ToString('HH:mm:ss'))] Invoke-SpacePlan started"
        Write-Verbose "  ComputerName: $($ComputerName -join ', ')"
        Write-Verbose "  Drive: $Drive"
        Write-Verbose "  TargetFreeSpaceGB: $TargetFreeSpaceGB"
        Write-Verbose "  FolderTimeoutSeconds: $FolderTimeoutSeconds"
        Write-Verbose "  TotalTimeoutSeconds: $TotalTimeoutSeconds"

        function IsLocal {
            param([string]$Name)
            $local = @('localhost', '.', $env:COMPUTERNAME)
            $isLocal = ($local -contains $Name)
            Write-Verbose "    IsLocal: '$Name' = $isLocal"
            return $isLocal
        }
        function GetVolumeInfo {
            param (
                [Parameter()] [string]$DriveLetter,
                [Parameter()] [CimSession]$CimSession
            )
            Write-Verbose "    Get-VolumeInfo: Querying volume info for $DriveLetter on $ComputerName"
            $splatParams = @{
                Class       = 'Win32_LogicalDisk'
                Filter      = "DeviceID='${DriveLetter}:'"
                ErrorAction = 'SilentlyContinue'
            }
            if ($CimSession) { $splatParams.CimSession = $CimSession }

            $volume = Get-CimInstance @splatParams
            if (-not $volume) {
                Write-Warning "    Get-VolumeInfo: Unable to retrieve volume info for $DriveLetter on $ComputerName"
                return $null
            }

            $freeSpaceGB = [math]::Round($volume.FreeSpace / 1GB, 2)
            $totalSpaceGB = [math]::Round($volume.Size / 1GB, 2)
            Write-Verbose "    Get-VolumeInfo: Volume $DriveLetter on $ComputerName has $freeSpaceGB GB free of $totalSpaceGB GB total"
            return @{
                FreeSpaceGB  = $freeSpaceGB
                TotalSpaceGB = $totalSpaceGB
            }
        }

        function GetUserProfilePaths{
            param(
                [Parameter()] [string]$ComputerName,
                [Parameter()] [CimSession]$CimSession)

            Write-Verbose "    Get-UserProfileRoots: Querying user profiles"
            $splatParams = @{
                Class       = 'Win32_UserProfile'
                ErrorAction = 'SilentlyContinue'
            }
            if ($CimSession) { $splatParams.CimSession = $CimSession }

            $profiles = Get-CimInstance @splatParams |
                Where-Object { $_.LocalPath -and $_.LocalPath -like 'C:\Users\*' }

            Write-Verbose "    Get-UserProfileRoots: Found $($profiles.Count) profiles"

            $roots = $profiles.LocalPath
            if ($ProfileIncludeRegex) {
                $roots = $roots | Where-Object { $_ -match $ProfileIncludeRegex }
                Write-Verbose "    Get-UserProfileRoots: After include regex: $($roots.Count) profiles"
            }
            if ($ProfileExcludeRegex) {
                $roots = $roots | Where-Object { $_ -notmatch $ProfileExcludeRegex }
                Write-Verbose "    Get-UserProfileRoots: After exclude regex: $($roots.Count) profiles"
            }
            return $roots
        }

        function CleanupImage {
            param (
                [Parameter()] [string]$ComputerName,
                [Parameter()] [PSSession]$PSSession
            )
            Write-Verbose "    CleanupImage: Running DISM cleanup on $ComputerName"
            $scriptBlock = {
                Write-Verbose "      Running volume optimization"
                Optimize-Volume -DriveLetter $using:Drive -ErrorAction SilentlyContinue
                Write-Verbose "      Volume optimization completed"
                Write-Verbose "      Running DISM component cleanup"
                Dism.exe /Online /Cleanup-Image /StartComponentCleanup /Quiet | Out-Null
                Write-Verbose "      DISM component cleanup completed"
            }
            if (IsLocal -Name $ComputerName) {
                & $scriptBlock
            } else {
                try {
                    Invoke-Command -Session $PSSession -ScriptBlock $scriptBlock
                }
                catch {
                    Write-Warning "    CleanupImage: Failed to run DISM cleanup on $ComputerName: $_"
                }
            }
        }

        function

        $coreExecutionBlock = {
            param (
                [pscustomobject]$cfg
            )

            $VerbosePreference = if ($cfg.Verbose) { 'Continue' } else { 'SilentlyContinue' }

            Write-Verbose "  CoreExecutionBlock started for $ComputerName"

            # Extract config values
            $TargetFreeSpace         = $cfg.TargetFreeSpace
            $TopResults              = $cfg.TopResults
            $MinSizeBytes            = $cfg.MinSizeBytes
            $FolderTimeoutSeconds    = $cfg.FolderTimeoutSeconds
            $TotalTimeoutSeconds     = $cfg.TotalTimeoutSeconds
            $MaxRecursionDepth       = $cfg.MaxRecursionDepth
            $IncludeUserProfiles     = [bool]$cfg.IncludeUserProfiles
            $IncludeUserCaches       = [bool]$cfg.IncludeUserCaches
            $IncludePSTFiles         = [bool]$cfg.IncludePSTFiles
            $ScanLocationMap         = $cfg.ScanLocationMap
            $ProfileIncludeRegex     = $cfg.ProfileIncludeRegex
            $ProfileExcludeRegex     = $cfg.ProfileExcludeRegex
            $PassThru                = [bool]$cfg.PassThru
            $ShowProgress            = [bool]$cfg.ShowProgress
        }

        function CleanupImage {
                param (
                    [Parameter()] [string]$DriveLetter
                )
                Write-Verbose "      Running volume optimization"
                Optimize-Volume -DriveLetter $Drive -ErrorAction SilentlyContinue
                Write-Verbose "      Volume optimization completed"
                Write-Verbose "      Running DISM component cleanup"
                Dism.exe /Online /Cleanup-Image /StartComponentCleanup /Quiet | Out-Null
                Write-Verbose
            }

    }

    process {
        if (IsLocal -Name $ComputerName) {
            Write-Verbose "Processing local computer: $ComputerName"
            & $coreExecutionBlock -cfg $cfg
            return
        }
        $sessions = New-PSSession -ComputerName $ComputerName -Credential $Credential -ErrorAction SilentlyContinue

        foreach ($session in $sessions) {
            $compName = $session.ComputerName
            Write-Verbose "Processing computer: $compName"

            try {
                Invoke-Command -Session $session -ScriptBlock $coreExecutionBlock -ArgumentList $cfg
            }
            catch {
                Write-Warning "  Failed to process ${compName}: $_"
            }
            finally {
                Remove-PSSession -Session $session
            }
        }
    }

    end {

    }
    
}

Get-SpacePlan -TargetFreeSpace 50

try {
    # Query user profiles from the remote computer
    $profiles = Get-CimInstance -ClassName Win32_UserProfile -ErrorAction Stop

    # Filter out system profiles and optionally by username
    $filteredProfiles = $profiles |
        Where-Object {
            -not $_.Special -and
            $_.LocalPath -match "\\Users\\" 
        }

    if (-not $filteredProfiles) {
        Write-Host "No matching profiles found on $ComputerName." -ForegroundColor Yellow
        return
    }

    # Output profile info with readable date
    $filteredProfiles | Select-Object `
        @{Name="ComputerName"; Expression={$ComputerName}},
        @{Name="UserName"; Expression={Split-Path $_.LocalPath -Leaf}},
        @{Name="LastUseTime"; Expression={$_.LastUseTime.ToLocalTime()}},
        LocalPath
    | Sort-Object LastUseTime -Descending
    | Format-Table -AutoSize

} catch {
    Write-Host "Error connecting to $ComputerName: $_" -ForegroundColor Red
}
