# Create a log file for tracking
$logFile = "C:\Users\jsissom\Development\PowerShell\SissomsTrinkets\logfile.log"
function Log {
    param (
        [string]$message
    )
    Add-Content -Path $logFile -Value ("[{0}] {1}" -f (Get-Date), $message)
}

# Known installation locations for specific applications
$KnownInstallLocations = @{
    "Centricity Periop Anesthesia Client" = "C:\Program Files (x86)\GE Healthcare\Centricity Perioperative Anesthesia"
}

# Function to get known installation location by display name
function Get-KnownInstallLocation {
    param (
        [string]$displayName
    )

    foreach ($appName in $KnownInstallLocations.Keys) {
        if ($displayName -like "*$appName*") {
            Log "Known installation location found for '$displayName': $($KnownInstallLocations[$appName])"
            return $KnownInstallLocations[$appName]
        }
    }

    Log "No known installation location found for '$displayName'."
    return $null
}

# Function to check directories for executables
function CheckDirectoryForExecutables {
    param (
        [string]$directoryPath
    )
    
    $executables = Get-ChildItem -Recurse -Path $directoryPath -Filter '*.exe' -ErrorAction SilentlyContinue
    if ($executables) {
        foreach ($exe in $executables) {
            Log "Executable found: $($exe.FullName)"
            Write-Host $exe.FullName
        }
        return $true
    } else {
        Log "No executables found in directory: $directoryPath"
        return $false
    }
}

# Function to try word-based searches
function TryWordBasedSearch {
    param (
        [string]$directoryBase,
        [string[]]$words
    )

    foreach ($word in $words) {
        Log "Attempting search with word '$word' in directory: $directoryBase"
        
        # Non-recursive search for the word as a folder
        $wordAppDirectory = Get-ChildItem -Path $directoryBase -ErrorAction SilentlyContinue -Filter $word
        if ($wordAppDirectory) {
            Log "Found directory for word '$word': $($wordAppDirectory.FullName)"
            if (CheckDirectoryForExecutables -directoryPath $wordAppDirectory.FullName) {
                return $true
            }
        }
        
        # Try a recursive search for the word in subdirectories
        $wordAppDirectory = Get-ChildItem -Recurse -ErrorAction SilentlyContinue -Path $directoryBase -Filter $word
        if ($wordAppDirectory) {
            Log "Found directory recursively for word '$word': $($wordAppDirectory.FullName)"
            if (CheckDirectoryForExecutables -directoryPath $wordAppDirectory.FullName) {
                return $true
            }
        }
    }
    
    Log "No valid directories or executables found using word-based search."
    return $false
}

# Retrieve installed software from registry paths
$SoftwareList = New-Object System.Collections.Generic.List[System.String]
$registryPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
$registryPathWow64 = "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
$installedSoftware = Get-ChildItem -Path @($registryPath, $registryPathWow64)

Log "Retrieving installed software from registry paths."
Log "Registry paths: $registryPath, $registryPathWow64"

# Populate SoftwareList with installed software names
foreach ($obj in $installedSoftware) {
    $applicationName = $obj.GetValue('DisplayName')
    if ([string]::IsNullOrEmpty($applicationName)) {
        continue
    }
    $SoftwareList.Add($applicationName)
}

Log "Total software found: $($SoftwareList.Count)"

# Sort and display software list in GUI (assume New-ListBox is a custom function)
$SoftwareList = $SoftwareList | Sort-Object | Where-Object {$_ }
$targetSoftwareName = New-ListBox -TitleText "Software List" -LabelText "Select desired software" -ListBoxItems ($SoftwareList)

Log "User selected: $targetSoftwareName"

# Find selected software in the registry
$selectedSoftware = $null
foreach ($object in $InstalledSoftware) {
    $displayName = $object.GetValue("DisplayName")
    if ($displayName -eq $targetSoftwareName) {
        $selectedSoftware = Get-ItemProperty -Path $object.PSPath
        break
    }
}

if (-not $selectedSoftware) {
    Log "Error: Selected software '$targetSoftwareName' not found in the registry."
    Write-Error "Selected software '$targetSoftwareName' not found."
    return
} else {
    Log "Found selected software in registry: $($selectedSoftware.PSPath)"
}

# Step 1: Check for a known installation location
$knownInstallLocation = Get-KnownInstallLocation -displayName $selectedSoftware.DisplayName
if ($knownInstallLocation) {
    Log "Using known installation location: $knownInstallLocation"
    if (-not (CheckDirectoryForExecutables -directoryPath $knownInstallLocation)) {
        Log "No executables found in known installation location."
    }
} else {
    # Step 2: If no known location, proceed with the regular search in Program Files and Program Files (x86)
    Log "No known location found, proceeding with normal search."
    
    $programFilePaths = @($ENV:ProgramFiles, ${ENV:ProgramFiles(x86)})
    $programFilesPath = $ENV:ProgramFiles
    $programFilesX86Path = ${ENV:ProgramFiles(x86)}

    Log "Searching in Program Files first: $programFilesPath"
    $appDirectory = Get-ChildItem -Path $programFilesPath -ErrorAction SilentlyContinue -Filter $selectedSoftware.DisplayName

    # If no directory found, split display name into words and try each word
    if (-not $appDirectory) {
        Log "Initial search in Program Files for '$($selectedSoftware.DisplayName)' failed. Trying recursive search."
        $appDirectory = Get-ChildItem -Recurse -ErrorAction SilentlyContinue -Path $programFilesPath -Filter $selectedSoftware.DisplayName
    }

    if ($appDirectory) {
        Log "Found application directory in Program Files: $($appDirectory.FullName)"
        if (-not (CheckDirectoryForExecutables -directoryPath $appDirectory.FullName)) {
            Log "No executables found in the directory, attempting word-based search."
            $words = $selectedSoftware.DisplayName -split ' '
            if (-not (TryWordBasedSearch -directoryBase $programFilesPath -words $words)) {
                Log "No executables found using word-based search in Program Files."
            }
        }
    } else {
        Log "No directory found with the full DisplayName in Program Files. Attempting word-based search."
        $words = $selectedSoftware.DisplayName -split ' '
        if (-not (TryWordBasedSearch -directoryBase $programFilesPath -words $words)) {
            Log "No executables found in Program Files after word-based search. Falling back to Program Files (x86)."
            
            # Fall back to Program Files (x86)
            $appDirectory = Get-ChildItem -Path $programFilesX86Path -ErrorAction SilentlyContinue -Filter $selectedSoftware.DisplayName
            if (-not $appDirectory) {
                Log "Initial search in Program Files (x86) for '$($selectedSoftware.DisplayName)' failed. Trying recursive search."
                $appDirectory = Get-ChildItem -Recurse -ErrorAction SilentlyContinue -Path $programFilesX86Path -Filter $selectedSoftware.DisplayName
            }

            if ($appDirectory) {
                Log "Found application directory in Program Files (x86): $($appDirectory.FullName)"
                if (-not (CheckDirectoryForExecutables -directoryPath $appDirectory.FullName)) {
                    Log "No executables found in Program Files (x86)."
                    Write-Error "No executables found in either Program Files or Program Files (x86)."
                }
            } else {
                Log "Error: Application directory for '$($selectedSoftware.DisplayName)' not found in Program Files (x86)."
                Write-Error "Application directory not found in Program Files (x86)."
            }
        }
    }
}

Write-Host "Log file located at: $logFile"