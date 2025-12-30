function Invoke-SpacePlan {
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
    
    .PARAMETER TargetFreeSpaceGB
    Target free space in GB (default: 75).
    
    .PARAMETER TopResults
    Number of largest folders to identify (default: 25).
    
    .PARAMETER FolderTimeoutSeconds
    Timeout per folder scan (default: 45 seconds).
    
    .PARAMETER TotalTimeoutSeconds
    Overall scan timeout (default: 600 seconds = 10 minutes).
    
    .PARAMETER MaxRecursionDepth
    Maximum folder depth to recurse (default: 8, protects against loops).
    
    .PARAMETER IncludePSTFiles
    Include Outlook PST file locations in scan (default: true).
    
    .PARAMETER Delete
    Enable deletion (preview mode only if not set).
    
    .PARAMETER ConfirmDelete
    Confirm each deletion individually.
    
    .PARAMETER PassThru
    Return result objects.
    
    .PARAMETER ShowProgress
    Show real-time scanning progress (default: true).
    
    .EXAMPLE
    Invoke-SpacePlan -Credential $cred -ComputerName "SERVER01" -Verbose
    
    .EXAMPLE
    Invoke-SpacePlan -ComputerName "SERVER01","SERVER02" -Delete -ConfirmDelete -Verbose
    #>
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param(
        [Parameter()] [string[]]$ComputerName = @('localhost'),
        [Parameter()] [System.Management.Automation.PSCredential]$Credential,
        [Parameter()] [ValidatePattern('^[A-Za-z]$')] [string]$Drive = 'C',
        [Parameter()] [decimal]$TargetFreeSpaceGB = 75,
        [Parameter()] [int]$TopResults = 25,
        [Parameter()] [int]$MaxDegreeOfParallelism = 10,
        [Parameter()] [long]$MinSizeBytes = 104857600,  # 100MB
        [Parameter()] [int]$FolderTimeoutSeconds = 45,
        [Parameter()] [int]$TotalTimeoutSeconds = 600,
        [Parameter()] [int]$MaxRecursionDepth = 8,
        [Parameter()] [switch]$IncludeUserProfiles,
        [Parameter()] [switch]$IncludeUserCaches,
        [Parameter()] [switch]$IncludePSTFiles,
        [Parameter()] [switch]$IncludeUserRecycleBins,
        [Parameter()] [hashtable]$ScanLocationMap,
        [Parameter()] [switch]$Preview,
        [Parameter()] [string]$ProfileIncludeRegex = '',
        [Parameter()] [string]$ProfileExcludeRegex = 'Default|Public',
        [Parameter()] [string]$ExcludePatterns = 'Windows|Program Files|ProgramData|System Volume Information|PerfLogs|WsMgmt|Documents and Settings|Boot|bootmgr|Config.Msi|MSOCache|All Users|Oracle|\\AppData\\Local\\Packages$',
        [Parameter()] [string[]]$PathsInclude = @(),
        [Parameter()] [switch]$Delete,
        [Parameter()] [switch]$ConfirmDelete,
        [Parameter()] [switch]$PassThru,
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
            'UserProfiles'  = 'C:\Users'
            'Temp'          = 'C:\Temp'
            'Logs'          = 'C:\Logs'
        }
        Write-Verbose "  ScanLocationMap: $($ScanLocationMap | Out-String)"
        # Build immutable config object
        Write-Verbose "Building configuration object"
        $cfg = [pscustomobject]@{
            Drive               = $Drive
            TargetFreeSpaceGB   = $TargetFreeSpaceGB
            TopResults          = $TopResults
            MinSizeBytes        = $MinSizeBytes
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

        function Test-IsLocal {
            param([string]$Name)
            $local = @('localhost', '.', $env:COMPUTERNAME)
            $isLocal = ($local -contains $Name)
            Write-Verbose "    Test-IsLocal: '$Name' = $isLocal"
            return $isLocal
        }
    }

    process {
        # Core scriptblock for remote execution
        $core = {
            param([pscustomobject]$cfg)

            

            $VerbosePreference = if ($cfg.Verbose) { 'Continue' } else { 'SilentlyContinue' }

            Write-Verbose "[$([DateTime]::Now.ToString('HH:mm:ss'))] Core scriptblock started on $env:COMPUTERNAME"

            $Drive                  = $cfg.Drive
            $TargetFreeSpaceGB      = $cfg.TargetFreeSpaceGB
            $TopResults             = $cfg.TopResults
            $MinSizeBytes           = $cfg.MinSizeBytes
            $FolderTimeoutSeconds   = $cfg.FolderTimeoutSeconds
            $TotalTimeoutSeconds    = $cfg.TotalTimeoutSeconds
            $MaxRecursionDepth      = $cfg.MaxRecursionDepth
            $IncludeUserProfiles    = [bool]$cfg.IncludeUserProfiles
            $IncludeUserCaches      = [bool]$cfg.IncludeUserCaches
            $IncludePSTFiles        = [bool]$cfg.IncludePSTFiles
            $ScanLocationMap        = $cfg.ScanLocationMap
            $ProfileIncludeRegex    = $cfg.ProfileIncludeRegex
            $ProfileExcludeRegex    = $cfg.ProfileExcludeRegex
            $ExcludePatterns        = $cfg.ExcludePatterns
            $PathsInclude           = [string[]]$cfg.PathsInclude
            $Delete                 = [bool]$cfg.Delete
            $ConfirmDelete          = [bool]$cfg.ConfirmDelete
            $PassThru               = [bool]$cfg.PassThru
            $ShowProgress           = [bool]$cfg.ShowProgress

            Write-Verbose "  Configuration loaded: Drive=$Drive, Target=${TargetFreeSpaceGB}GB, Timeout=${FolderTimeoutSeconds}s"

            function Get-VolumeInfo {
                param(
                    [Parameter()] [Microsoft.Management.Infrastructure.CimSession]$CimSession,
                    [Parameter()] [string]$Drive = 'C'
                )

                Write-Verbose "    Get-VolumeInfo: Querying drive ${Drive}:"
                $splatParams = @{
                    ClassName   = 'Win32_LogicalDisk'
                    Filter      = "DeviceID='${Drive}:'"
                    ErrorAction = 'Stop'
                }
                if ($CimSession) { $splatParams.CimSession = $CimSession }

                $disk = Get-CimInstance @splatParams
                if (-not $disk) { throw "Drive ${Drive}: not found." }

                $result = [pscustomobject]@{
                    TotalGB = [math]::Round($disk.Size / 1GB, 2)
                    FreeGB  = [math]::Round($disk.FreeSpace / 1GB, 2)
                }
                Write-Verbose "    Get-VolumeInfo: Total=${result.TotalGB}GB, Free=${result.FreeGB}GB"
                return $result
            }

            function Get-UserProfileRoots {
                param([Microsoft.Management.Infrastructure.CimSession]$CimSession)

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

            function Expand-UserAreas {
                param(
                    [string]$ProfileRoot,
                    [switch]$Caches,
                    [switch]$PSTFiles
                )

                if ([string]::IsNullOrWhiteSpace($ProfileRoot)) {
                    return [string[]]@()
                }

                Write-Verbose "      Expand-UserAreas: Processing $ProfileRoot (Caches=$Caches, PSTFiles=$PSTFiles)"

                $paths = New-Object System.Collections.Generic.List[string]
                $paths.AddRange([string[]]@(
                    (Join-Path $ProfileRoot 'Downloads')
                    (Join-Path $ProfileRoot 'Documents')
                    (Join-Path $ProfileRoot 'Desktop')
                    (Join-Path $ProfileRoot 'Pictures')
                    (Join-Path $ProfileRoot 'Videos')
                    (Join-Path $ProfileRoot 'OneDrive')
                    (Join-Path $ProfileRoot 'AppData\Local\Temp')
                    (Join-Path $ProfileRoot 'AppData\Local\Packages')
                ))

                if ($Caches) {
                    Write-Verbose "        Adding cache paths"
                    $paths.Add((Join-Path $ProfileRoot 'AppData\Roaming\Microsoft\Teams'))
                    $paths.Add((Join-Path $ProfileRoot 'AppData\Local\Packages\MSTeams_8wekyb3d8bbwe'))
                    $paths.Add((Join-Path $ProfileRoot 'AppData\Local\Google\Chrome\User Data\Default\Cache'))
                    $paths.Add((Join-Path $ProfileRoot 'AppData\Local\Microsoft\Edge\User Data\Default\Cache'))
                    $paths.Add((Join-Path $ProfileRoot 'AppData\Local\Firefox\Profiles'))
                }

                if ($PSTFiles) {
                    Write-Verbose "        Adding PST file paths"
                    $paths.Add((Join-Path $ProfileRoot 'AppData\Local\Microsoft\Outlook'))
                    $paths.Add((Join-Path $ProfileRoot 'Documents\Outlook Files'))
                    $paths.Add((Join-Path $ProfileRoot 'AppData\Roaming\Microsoft\Outlook'))
                }

                if ($IncludeUserRecycleBins) {
                    try {
                        $userProfile = Get-CimInstance -ClassName Win32_UserProfile -Filter "LocalPath='$ProfileRoot'" -ErrorAction SilentlyContinue
                        if ($userProfile -and $userProfile.SID) {
                            $recycleBinPath = "C:\$Recycle.Bin\$($userProfile.SID)"
                            if (Test-Path $recycleBinPath -PathType Container -ErrorAction SilentlyContinue) {
                                $paths.Add($recycleBinPath)
                                Write-Verbose "        Adding Recycle Bin path for user: $recycleBinPath"
                            }
                        }
                    } catch {
                        Write-Verbose "        Could not add Recycle Bin for $ProfileRoot"
                    }
                }

                $existing = $paths |
                    Where-Object { Test-Path $_ -PathType Container -ErrorAction SilentlyContinue } |
                    Select-Object -Unique

                Write-Verbose "        Found $($existing.Count) existing paths out of $($paths.Count) checked"
                if (-not $existing) {
                    return [string[]]@()
                }

                return [string[]]$existing
            }

            function Get-FolderSizeWithTimeout {
                param(
                    [Parameter(Mandatory)] [string]$Path,
                    [Parameter()] [int]$TimeoutSeconds = 45,
                    [Parameter()] [int]$MaxRecursionDepth = 8
                )

                Write-Verbose "        Get-FolderSizeWithTimeout: Starting scan of $Path (timeout=${TimeoutSeconds}s, maxDepth=$MaxRecursionDepth)"

                $startTime   = [System.DateTime]::Now
                [long]$bytes = 0
                [int]$fileCount = 0
                [int]$dirsScanned = 0
                $dirStack = New-Object System.Collections.Stack
                $dirStack.Push(@{ Path = $Path; Depth = 0 })

                try {
                    while ($dirStack.Count -gt 0) {
                        $currentTime     = [System.DateTime]::Now
                        $elapsed         = $currentTime - $startTime
                        $elapsedSeconds  = [int]$elapsed.TotalSeconds

                        if ($elapsedSeconds -gt $TimeoutSeconds) {
                            Write-Verbose "        Get-FolderSizeWithTimeout: TIMEOUT at ${elapsedSeconds}s for $Path"
                            throw "Timeout: Folder scan exceeded ${TimeoutSeconds}s (likely symlink or permission loop)"
                        }

                        $current      = $dirStack.Pop()
                        $currentPath  = $current.Path
                        $currentDepth = $current.Depth

                        if ($currentDepth -gt $MaxRecursionDepth) {
                            Write-Verbose "          Max depth reached at $currentPath"
                            continue
                        }

                        try {
                            $di = [System.IO.DirectoryInfo]$currentPath

                            foreach ($file in $di.EnumerateFiles()) {
                                $bytes += $file.Length
                                $fileCount++
                            }

                            $dirsScanned++

                            foreach ($subdir in $di.EnumerateDirectories()) {
                                $dirStack.Push(@{ Path = $subdir.FullName; Depth = ($currentDepth + 1) })
                            }
                        } catch {
                            Write-Verbose "          Access denied or error: $currentPath"
                            continue
                        }
                    }
                } catch {
                    if ($_ -match 'Timeout') {
                        throw $_
                    }
                    Write-Verbose "        Get-FolderSizeWithTimeout: Exception - $($_.Exception.Message)"
                    throw $_
                }

                $endTime      = [System.DateTime]::Now
                $totalElapsed = $endTime - $startTime
                $totalSeconds = [math]::Round($totalElapsed.TotalSeconds, 2)

                Write-Verbose "        Get-FolderSizeWithTimeout: Completed - ${totalSeconds}s, $dirsScanned dirs, $fileCount files, $([math]::Round($bytes/1GB,2))GB"

                return @{
                    SizeBytes   = $bytes
                    FileCount   = $fileCount
                    DirsScanned = $dirsScanned
                    TimeSeconds = $totalSeconds
                }
            }

            function Get-LargestFoldersFast {
                param(
                    [Parameter(Mandatory)] [string[]]$Folders,
                    [Parameter()] [int]$Top = 25,
                    [Parameter()] [string]$ExcludePatterns = '',
                    [Parameter()] [long]$MinSizeBytes = 104857600,
                    [Parameter()] [bool]$ShowProgress = $true,
                    [Parameter()] [int]$FolderTimeoutSeconds = 45,
                    [Parameter()] [int]$TotalTimeoutSeconds = 600,
                    [Parameter()] [int]$MaxRecursionDepth = 8,
                    [Parameter()] [string[]]$PathsInclude = @(),
                    [Parameter()] [decimal]$TargetFreeGB = 0
                )

                Write-Verbose "      Get-LargestFoldersFast: Starting scan of $($Folders.Count) folders"
                Write-Verbose "        Parameters: Top=$Top, MinSize=$([math]::Round($MinSizeBytes/1MB))MB, FolderTimeout=${FolderTimeoutSeconds}s"

                $rows           = New-Object System.Collections.Generic.List[object]
                $totalFolders   = $Folders.Count
                $currentIndex   = 0
                $scanStartTime  = Get-Date
                $skippedCount   = 0
                $timedOutFolders = @()
                $errorFolders    = @()

                foreach ($folderPath in $Folders) {
                    $elapsedSeconds = ((Get-Date) - $scanStartTime).TotalSeconds

                    if ($elapsedSeconds -gt $TotalTimeoutSeconds) {
                        Write-Verbose "      Get-LargestFoldersFast: OVERALL TIMEOUT at ${elapsedSeconds}s"
                        Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
                        Write-Warning "OVERALL SCAN TIMEOUT: Exceeded ${TotalTimeoutSeconds}s. Aborting remaining $($Folders.Count - $currentIndex) folders."
                        break
                    }

                    $currentIndex++
                    Write-Verbose "        [$currentIndex/$totalFolders] Processing: $folderPath"

                    $isExplicitlyIncluded = $false
                    if ($PathsInclude.Count -gt 0) {
                        foreach ($includedPath in $PathsInclude) {
                            if ($folderPath -eq $includedPath -or $folderPath -like "$includedPath*") {
                                $isExplicitlyIncluded = $true
                                Write-Verbose "          Path is explicitly included - bypassing exclusion patterns"
                                break
                            }
                        }
                    }

                    if (-not $isExplicitlyIncluded -and $ExcludePatterns -and ($folderPath -match $ExcludePatterns)) {
                        Write-Verbose "          Excluded by pattern"
                        $skippedCount++
                        continue
                    }

                    if (-not (Test-Path $folderPath -PathType Container -ErrorAction SilentlyContinue)) {
                        Write-Verbose "          Path does not exist"
                        $skippedCount++
                        continue
                    }

                    if ($ShowProgress) {
                        $folderName   = Split-Path $folderPath -Leaf
                        $timeElapsed  = [math]::Round($elapsedSeconds, 1)
                        Write-Progress -Activity "Scanning folders" `
                            -Status "[$currentIndex/$totalFolders] Scanning: $folderName (${timeElapsed}s / ${TotalTimeoutSeconds}s)" `
                            -PercentComplete ([math]::Round($currentIndex / $totalFolders * 100)) `
                            -CurrentOperation $folderPath
                    }

                    try {
                        $result = Get-FolderSizeWithTimeout -Path $folderPath `
                            -TimeoutSeconds $FolderTimeoutSeconds `
                            -MaxRecursionDepth $MaxRecursionDepth

                        $bytes     = $result.SizeBytes
                        $fileCount = $result.FileCount

                        if ($bytes -lt $MinSizeBytes) {
                            $skippedCount++
                            Write-Verbose "          Below threshold: $([math]::Round($bytes/1MB,1))MB"
                            if ($ShowProgress) {
                                Write-Verbose "  [SKIP] $folderPath ($(([math]::Round($bytes / 1MB, 1))) MB - below threshold)"
                            }
                            continue
                        }

                        $folderResult = [pscustomobject]@{
                            Name        = Split-Path $folderPath -Leaf
                            Path        = $folderPath
                            SizeBytes   = $bytes
                            SizeGB      = [math]::Round($bytes / 1GB, 2)
                            FileCount   = $fileCount
                            DirsScanned = $result.DirsScanned
                            ScanTime    = $result.TimeSeconds
                        }

                        $rows.Add($folderResult)
                        Write-Verbose "          FOUND: $($folderResult.SizeGB)GB, $fileCount files"

                        if ($ShowProgress) {
                            Write-Verbose "  [FOUND] $($folderResult.SizeGB) GB - $folderPath (scanned $($folderResult.DirsScanned) dirs in $($folderResult.ScanTime)s)"
                        }

                    } catch {
                        $errorMsg = $_.Exception.Message

                        if ($errorMsg -match 'Timeout') {
                            $timedOutFolders += $folderPath
                            Write-Verbose "          TIMEOUT: $folderPath"
                            if ($ShowProgress) {
                                Write-Host "  [TIMEOUT] $folderPath (${FolderTimeoutSeconds}s exceeded - likely symlink/permission loop)" -ForegroundColor Red
                            }
                        } else {
                            $errorFolders += @{ Path = $folderPath; Error = $errorMsg }
                            Write-Verbose "          ERROR: $errorMsg"
                            if ($ShowProgress) {
                                Write-Host "  [ERROR] $folderPath - $errorMsg" -ForegroundColor Yellow
                            }
                        }
                    }
                }

                if ($ShowProgress) {
                    $totalFoundGB = ($rows | Measure-Object -Property SizeBytes -Sum).Sum / 1GB
                    $totalFoundGB = [math]::Round($totalFoundGB, 2)
                    Write-Progress -Activity "Scanning folders" -Completed

                    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
                    Write-Host "Scan Summary:" -ForegroundColor Cyan
                    Write-Host "  Target to clear: $([math]::Round($TargetFreeGB,2)) GB" -ForegroundColor Yellow
                    Write-Host "  Total space found: $totalFoundGB GB" -ForegroundColor Cyan
                    Write-Host "  Scanned: $currentIndex / $totalFolders folders" -ForegroundColor Gray
                    Write-Host "  Successfully analyzed: $($rows.Count) folders" -ForegroundColor Green
                    Write-Host "  Skipped: $skippedCount folders (too small/excluded)" -ForegroundColor Gray

                    if ($timedOutFolders.Count -gt 0) {
                        Write-Host "  Timed out (${FolderTimeoutSeconds}s): $($timedOutFolders.Count) folders (LIKELY SYMLINKS/LOOPS)" -ForegroundColor Red
                        $timedOutFolders | ForEach-Object { Write-Host "    ⚠ $_" -ForegroundColor Red }
                    }

                    if ($errorFolders.Count -gt 0) {
                        Write-Host "  Errors: $($errorFolders.Count) folders" -ForegroundColor Yellow
                        $errorFolders | ForEach-Object { Write-Host "    ! $($_.Path): $($_.Error)" -ForegroundColor Yellow }
                    }

                    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
                }

                Write-Verbose "      Get-LargestFoldersFast: Completed - Found $($rows.Count) candidates"
                $sorted = $rows | Sort-Object SizeBytes -Descending
                return $sorted | Select-Object -First $Top
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
                Write-Verbose "      DISM component cleanup completed"
            }

            # === MAIN EXECUTION (with early returns) ===

            $cimSession = $null
            try {
                Write-Verbose "  Creating CIM session"
                $cimSession = New-CimSession -ErrorAction SilentlyContinue

                Write-Verbose "  Step 1: Get volume info"
                $vol   = Get-VolumeInfo -CimSession $cimSession -Drive $Drive
                $needGB = [math]::Round(($TargetFreeSpaceGB - $vol.FreeGB), 2)

                Write-Host "Drive: ${Drive}:  Total: $($vol.TotalGB) GB, Free: $($vol.FreeGB) GB, Target Free: $TargetFreeSpaceGB GB" -ForegroundColor Cyan

                if ($needGB -le 0) {
                    Write-Host "Already at or above target free space; no cleanup needed." -ForegroundColor Green
                    Write-Verbose "  Early exit: Target already met"
                    if ($PassThru) { return @() }
                    return
                }

                Write-Host "Need to free approximately $needGB GB." -ForegroundColor Yellow

                Write-Verbose "  Step 2: Build scan list"
                $scanRoots = New-Object System.Collections.Generic.List[string]

                Write-Host "`nBuilding scan list..." -ForegroundColor Cyan
                $topLevel = Get-ChildItem -LiteralPath "${Drive}:\" -Directory -Force -ErrorAction SilentlyContinue |
                    Select-Object -ExpandProperty FullName |
                    Where-Object { $_ -notmatch '^[A-Za-z]:\\Users$' }
                if ($topLevel) {
                    $scanRoots.AddRange([string[]]$topLevel)
                    Write-Verbose "    Added $($topLevel.Count) top-level directories (excluding C:\Users)"
                }

                if ($IncludeUserProfiles) {
                    Write-Verbose "    Including user profiles"
                    $profileCount   = 0
                    $daysThreshold  = 30
                    $cutoff         = (Get-Date).AddDays(-$daysThreshold)

                    $userProfiles = Get-CimInstance -ClassName Win32_UserProfile -ErrorAction SilentlyContinue |
                        Where-Object { $_.LocalPath -like 'C:\Users\*' -and $_.LastUseTime } |
                        ForEach-Object {
                            Write-Verbose "      Profile: $($_.LocalPath.Split('\')[2]), LastUseTime: $($_.LastUseTime)"
                        }

                    $inactiveProfiles = @()
                    foreach ($userProfile in $userProfiles) {
                        try {
                            $lastUsed = [System.Management.ManagementDateTimeConverter]::ToDateTime($userProfile.LastUseTime)
                            if ($lastUsed -lt $cutoff) {
                                $inactiveProfiles += [PSCustomObject]@{
                                    UserName    = $userProfile.LocalPath
                                    LastUseTime = $lastUsed
                                    SID         = $userProfile.SID
                                }
                            }
                        } catch {}
                    }

                    if ($inactiveProfiles.Count -gt 0) {
                        Write-Host "Profiles NOT logged into in the last $daysThreshold days:" -ForegroundColor Yellow
                        $inactiveProfiles | Select-Object UserName,LastUseTime,SID | Format-Table -AutoSize | Out-Host
                    } else {
                        Write-Host "No inactive profiles found." -ForegroundColor Green
                    }

                    foreach ($root in (Get-UserProfileRoots -CimSession $cimSession)) {
                        if ([string]::IsNullOrWhiteSpace($root)) { continue }
                        $profileCount++
                        $uPaths = Expand-UserAreas -ProfileRoot $root -Caches:$IncludeUserCaches -PSTFiles:$IncludePSTFiles
                        if ($uPaths -and $uPaths.Count) {
                            $scanRoots.AddRange([string[]]$uPaths)
                            Write-Verbose "      Profile $($root): Added $($uPaths.Count) paths"
                        }
                    }
                    Write-Host "  Added $profileCount user userProfile(s)" -ForegroundColor Gray
                }

                if ($PathsInclude.Count) {
                    $scanRoots.AddRange([string[]]$PathsInclude)
                    Write-Host "  Added $($PathsInclude.Count) custom path(s)" -ForegroundColor Gray
                    Write-Verbose "    Custom paths: $($PathsInclude -join ', ')"
                }

                if (-not $scanRoots.Count) {
                    Write-Host "No scan roots could be determined; aborting." -ForegroundColor Yellow
                    Write-Verbose "  Early exit: Scan roots list empty"
                    if ($PassThru) { return @() }
                    return
                }

                Write-Verbose "  Step 3: Scan folders (Total: $($scanRoots.Count) locations)"
                Write-Host "`nScanning $($scanRoots.Count) locations (timeout: ${FolderTimeoutSeconds}s per folder, ${TotalTimeoutSeconds}s overall)..." -ForegroundColor Cyan
                Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray

                $candidates = Get-LargestFoldersFast -Folders $scanRoots.ToArray() -Top $TopResults `
                    -ExcludePatterns $ExcludePatterns -MinSizeBytes $MinSizeBytes `
                    -ShowProgress $ShowProgress `
                    -FolderTimeoutSeconds $FolderTimeoutSeconds `
                    -TotalTimeoutSeconds $TotalTimeoutSeconds `
                    -MaxRecursionDepth $MaxRecursionDepth `
                    -PathsInclude $PathsInclude `
                    -TargetFreeGB $needGB

                if (-not $candidates -or -not $candidates.Count) {
                    Write-Host "`nScan complete. No candidate folders found.`n" -ForegroundColor Yellow
                    Write-Verbose "  Early exit: No candidates returned from scan"
                    if ($PassThru) { return @() }
                    return
                }

                Write-Host "`nScan complete. Found $($candidates.Count) candidate folder(s).`n" -ForegroundColor Cyan
                Write-Verbose "  Step 4: Build recommendations"

                $recommend = @()
                $accum = 0.0
                foreach ($c in $candidates) {
                    if ($accum -ge $needGB) {
                        Write-Verbose "    Target met at $accum GB"
                        break
                    }
                    $recommend += $c
                    $accum = [math]::Round($accum + $c.SizeGB, 2)
                }

                if (-not $recommend) {
                    Write-Host "No candidate folders found (permissions, exclusions, or no large data)." -ForegroundColor Yellow
                    Write-Verbose "  Early exit: No recommendations generated"
                    if ($PassThru) { return @() }
                    return
                }

                Write-Host "Recommended folders to review (largest-first, cumulative ~ $accum GB):" -ForegroundColor Cyan
                $recommend | Select-Object Name, SizeGB, FileCount, Path | Format-Table -AutoSize | Out-Host

                if ($Preview) {
                    Write-Host "Preview mode only; re-run with -Delete to remove recommended items." -ForegroundColor Yellow
                    Write-Verbose "  Preview mode - no deletion"
                    if ($PassThru) { return $recommend }
                    return
                }

                if (-not $Delete) {
                    Write-Verbose "  Early exit: Delete switch not specified"
                    if ($PassThru) { return $recommend }
                    return
                }

                # Deletion phase (Delete is true at this point)
                Write-Verbose "  Step 5: Deletion phase"

                if ($ConfirmDelete) {
                    Write-Verbose "    Deletion mode: Individual confirmation"
                    foreach ($r in $recommend) {
                        $ans = Read-Host "Delete '$($r.Path)' (~$($r.SizeGB) GB)? [Y/N]"
                        if ($ans -match '^[Nn]') {
                            Write-Verbose "      Deletion cancelled by user for: $($r.Path)"
                            Write-Host "Skipped: $($r.Path)" -ForegroundColor Yellow
                            continue
                        }

                        try {
                            Write-Verbose "      Deleting: $($r.Path)"
                            Remove-Item -LiteralPath $r.Path -Recurse -Force -ErrorAction Stop
                            Write-Host "Deleted: $($r.Path)" -ForegroundColor Green
                        } catch {
                            Write-Verbose "      Failed to delete: $($_.Exception.Message)"
                            Write-Warning "Failed to delete: $($r.Path) — $($_.Exception.Message)"
                        }
                    }
                } else {
                    Write-Verbose "    Deletion mode: Bulk confirmation"
                    $ans = Read-Host "Delete ALL recommended folders (~$accum GB total)? [Y/N]"
                    if ($ans -match '^[Nn]') {
                        Write-Verbose "      Bulk deletion cancelled by user"
                        Write-Host "Bulk deletion cancelled." -ForegroundColor Yellow
                        if ($PassThru) { return $recommend }
                        return
                    }

                    foreach ($r in $recommend) {
                        try {
                            Write-Verbose "      Deleting: $($r.Path)"
                            Remove-Item -LiteralPath $r.Path -Recurse -Force -ErrorAction Stop
                            Write-Host "Deleted: $($r.Path)" -ForegroundColor Green
                        } catch {
                            Write-Verbose "      Failed to delete: $($_.Exception.Message)"
                            Write-Warning "Failed to delete: $($r.Path) — $($_.Exception.Message)"
                        }
                    }
                    Write-Host "Bulk deletion completed." -ForegroundColor Green
                }

                CleanupImage -DriveLetter $Drive

                $post = Get-VolumeInfo -CimSession $cimSession -Drive $Drive
                Write-Host "`nAfter cleanup — Free: $($post.FreeGB) GB of $($post.TotalGB) GB total" -ForegroundColor Cyan
                Write-Verbose "  Post-cleanup: Free space = $($post.FreeGB)GB"

                if ($PassThru) { return $recommend }

            } finally {
                if ($cimSession) {
                    Write-Verbose "  Cleanup: Removing CIM session"
                    Remove-CimSession -CimSession $cimSession
                }
            }
        }

        # === PARALLEL EXECUTION (top level) ===

        $results = @()

        if ($ComputerName.Count -eq 1) {
            Write-Verbose "Single machine execution mode"
            $cn = $ComputerName[0]

            if (Test-IsLocal -Name $cn -and -not $PSBoundParameters.ContainsKey('Credential')) {
                Write-Verbose "Executing locally without remoting"
                $out = & $core $cfg
                if ($PassThru -and $out) {
                    $results += $out | ForEach-Object {
                        $_ | Add-Member -NotePropertyName Computer -NotePropertyValue $env:COMPUTERNAME -PassThru
                    }
                }
            } else {
                Write-Verbose "Executing remotely on $cn"
                $session = New-PSSession -ComputerName $cn -Credential $Credential -ErrorAction Stop
                try {
                    $icmParams = @{
                        Session      = $session
                        ScriptBlock  = $core
                        ArgumentList = @($cfg)
                        ErrorAction  = 'Continue'
                    }
                    if ($PSBoundParameters.ContainsKey('Credential') -and $Credential) {
                        $icmParams.Credential = $Credential
                    }

                    $out = Invoke-Command @icmParams
                    if ($PassThru -and $out) {
                        $results += $out | ForEach-Object {
                            $_ | Add-Member -NotePropertyName Computer -NotePropertyValue $cn -PassThru
                        }
                    }
                } finally {
                    if ($session) {
                        Remove-PSSession -Session $session
                    }
                }
            }
        } else {
            Write-Verbose "Multi-machine parallel execution mode ($($ComputerName.Count) machines)"
            $jobs = @()

            foreach ($cn in $ComputerName) {
                Write-Verbose "  Queuing job for $cn"
                $useRemoting = -not (Test-IsLocal -Name $cn -and -not $PSBoundParameters.ContainsKey('Credential'))

                if ($useRemoting) {
                    $icmParams = @{
                        ComputerName = $cn
                        ScriptBlock  = $core
                        ArgumentList = @($cfg)
                        AsJob        = $true
                        JobName      = "SpacePlan_$cn"
                        ErrorAction  = 'Continue'
                    }
                    if ($PSBoundParameters.ContainsKey('Credential') -and $Credential) {
                        $icmParams.Credential = $Credential
                    }
                    $jobs += Invoke-Command @icmParams
                } else {
                    $jobs += Start-Job -ScriptBlock {
                        param($core, $cfg)
                        & $core $cfg
                    } -ArgumentList $core, $cfg -Name "SpacePlan_$cn"
                }

                while (@($jobs | Where-Object { $_.State -eq 'Running' }).Count -ge $MaxDegreeOfParallelism) {
                    Start-Sleep -Milliseconds 100
                }
            }

            Write-Verbose "  Waiting for $($jobs.Count) jobs to complete"
            $completed = 0
            while ($jobs | Where-Object { $_.State -eq 'Running' }) {
                $done = (@($jobs | Where-Object { $_.State -ne 'Running' })).Count
                if ($done -ne $completed) {
                    Write-Progress -Activity "Processing remote machines" `
                        -Status "$done of $($jobs.Count) completed" `
                        -PercentComplete ([math]::Round($done / $jobs.Count * 100))
                    Write-Verbose "    Jobs completed: $done / $($jobs.Count)"
                    $completed = $done
                }
                Start-Sleep -Milliseconds 200
            }

            Write-Progress -Activity "Processing remote machines" -Completed

            Write-Verbose "  Collecting results from jobs"
            foreach ($job in $jobs) {
                $out = Receive-Job -Job $job -ErrorAction Continue
                if ($PassThru -and $out) {
                    $results += $out | ForEach-Object {
                        $_ | Add-Member -NotePropertyName Computer -NotePropertyValue $job.Location -PassThru
                    }
                }
                Remove-Job -Job $job -Force
            }
        }

        Write-Verbose "[$([DateTime]::Now.ToString('HH:mm:ss'))] Invoke-SpacePlan completed"
        if ($PassThru -and $results) {
            return $results
        }
    }

    end {
    }
    
    

    

    

    
}
