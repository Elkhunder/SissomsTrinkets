<#
        Scenarios
        1. Install Location property exists
        2. A directory in program files / program files x86 is a direct match to the display name
          - Executable is in root
          - Executable is in a well known labeled directory i.e. bin
        3. No directory matches but a subdirectory has a match
          - Executable is in that subdirectory
          - Executable is in a well know labeled directory in the parent directory
          - Executable is in a well know labeled directory in the subdirectory
        4. Look for running processes, windows startup items, or scheduled tasks that may point to the executable path 

        Updated Business Logic:
        1. Primary check: InstallLocation in the registry:
          - Check if the InstallLocation registry value is populated for the target software.
          - If populated, search for .exe files in that directory (or common subdirectories).
        2. Fallbacks:
          - If InstallLocation is empty or doesn't exist, fall back to:
            - Searching Program Files directories.
            - Checking the UninstallString for possible executable paths.
            - Searching for a running process of the application.
      #>

enum Scope {
  Global
  User
}
function Add-ApplicationShortcut{
  [CmdletBinding()]

  param (
    # Named ParameterSet
    [Parameter(Mandatory, ParameterSetName = 'NamedParameterSet')]
    [string[]]
    $ComputerName,

    # File ParameterSet
    [Parameter(Mandatory, ParameterSetName = 'FileParameterSet')]
    [string]
    $InputObject,

    # Common ParameterSet
    [Parameter(Mandatory, ParameterSetName = 'NamedParameterSet')]
    [Parameter(Mandatory, ParameterSetName = 'FileParameterSet')]
    [pscredential]
    $Credential,

    [Parameter(ParameterSetName = 'NamedParameterSet')]
    [Parameter(ParameterSetName = 'FileParameterSet')]
    [ValidateSet(
      "Global",
      "User"
    )]
    [Scope]
    $Scope = [Scope]::Global,

    [Parameter(ParameterSetName = 'NamedParameterSet')]
    [Parameter(ParameterSetName = 'FileParameterSet')]
    [string]
    $AppPath,

    [Parameter(ParameterSetName = 'NamedParameterSet')]
    [Parameter(ParameterSetName = 'FileParameterSet')]
    [string]
    $ShortcutPath

  )

  begin{
    $targetUser = "Public"

    if ($AppPath){
      # Verify that the executable path exists and is a file
      if (-not (Test-Path $ExePath -PathType Leaf)) {
        Write-Error "The executable path '$ExePath' is not valid or does not exist."
        return
      }

      # Verify that the executable file has an .exe extension
      if (-not $ExePath.ToLower().EndsWith('.exe')) {
          Write-Error "The file at '$ExePath' is not an executable (.exe) file."
          return
      }
    }

    if ($ShortcutPath){
      # Verify that the shortcut directory exists
      $shortcutDirectory = [System.IO.Path]::GetDirectoryName($ShortcutPath)
      if (-not (Test-Path $shortcutDirectory -PathType Container)) {
          Write-Error "The directory for the shortcut path '$shortcutDirectory' does not exist."
          return
      }
    }
  }

  process {
    foreach($computer in $ComputerName){
      $psSession = New-PSSession -ComputerName $computer -Credential $Credential
      if (-not $AppPath){
        $SoftwareList = Invoke-Command -Session $psSession -ScriptBlock {
          $SoftwareList = New-Object System.Collections.Generic.List[System.String]
          $registryPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
          $registryPathWow64 = "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
          $installedSoftware = Get-ChildItem -Path @($registryPath, $registryPathWow64)
          
          foreach($obj in $InstalledSoftware){
            $applicationName = $obj.GetValue('DisplayName')
            if([string]::IsNullOrEmpty($applicationName)){continue}
            $SoftwareList.Add($applicationName)
          }
          Return $SoftwareList = $SoftwareList | Sort-Object | Where-Object {$_ }
        }
        $targetSoftwareName = New-ListBox -TitleText "Software List" -LabelText "Select desired software" -ListBoxItems ($SoftwareList)
        foreach ($object in $InstalledSoftware){
          $displayName = $object.GetValue("DisplayName")
          if($displayName -eq $targetSoftwareName){
            $targetSoftware = Get-ItemProperty -Path $object.PSPath
          }
        }
        if (-not $targetSoftware.InstallLocation -or -not (Test-Path -PathType Container -Path $targetSoftware.InstallLocation) -and $null -ne $targetSoftware){
          
          $targetAppFiles = Invoke-Command -ArgumentList $targetSoftware -Session $psSession -ScriptBlock{
            param($selectedSoftware)
            
            $SoftwareList = New-Object System.Collections.Generic.List[System.String]
          $registryPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
          $registryPathWow64 = "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
          $installedSoftware = Get-ChildItem -Path @($registryPath, $registryPathWow64)
          
          foreach($obj in $InstalledSoftware){
            $applicationName = $obj.GetValue('DisplayName')
            if([string]::IsNullOrEmpty($applicationName)){continue}
            $SoftwareList.Add($applicationName)
          }
          $SoftwareList = $SoftwareList | Sort-Object | Where-Object {$_ }

        $targetSoftwareName = New-ListBox -TitleText "Software List" -LabelText "Select desired software" -ListBoxItems ($SoftwareList)
        foreach ($object in $InstalledSoftware){
          $displayName = $object.GetValue("DisplayName")
          if($displayName -eq $targetSoftwareName){
            $selectedSoftware = Get-ItemProperty -Path $object.PSPath
          }
        }
            # Search in both Program Files and Program Files (x86)
            $programFilePaths = @($ENV:ProgramFiles, ${ENV:ProgramFiles(x86)})
            $appDirectory = Get-ChildItem -Path $programFilePaths -ErrorAction SilentlyContinue -Filter $selectedSoftware.DisplayName
            
            if (-not (Test-Path -PathType Container -Path $appDirectory -ErrorAction SilentlyContinue)){
              # Check for any subdirectories that match
              $appDirectory = Get-ChildItem -Recurse -ErrorAction SilentlyContinue -Path $programFilePaths -Filter $selectedSoftware.DisplayName
              
              if (-not (Test-Path -PathType Container -Path $appDirectory -ErrorAction SilentlyContinue)){
                $appDirectory = Get-ChildItem -ErrorAction SilentlyContinue -Path $programFilePaths -Filter ($selectedSoftware.DisplayName.Split(" "))[0]

                if (-not (Test-Path -PathType Container -Path $appDirectory -ErrorAction SilentlyContinue)){
                  $appDirectory = Get-ChildItem -Recurse -ErrorAction SilentlyContinue -Path $programFilePaths -Filter ($selectedSoftware.DisplayName.Split(" "))[0]
                }
              }
            }
            $parentAppDirectory = [System.IO.Path]::GetDirectoryName($appDirectory.FullName)

            if (-not ($programFilePaths.Contains($parentAppDirectory))){
              # Check if parent directory is a subdirectory of program files, and recursively get the files of the parent directory
              Write-Host "False"
              Get-ChildItem -Recurse -Path $parentAppDirectory -Filter '*.exe' -ErrorAction SilentlyContinue
            } else {
              Write-Host "True"
              Get-ChildItem -Recurse -Path $appDirectory -Filter '*.exe' -ErrorAction SilentlyContinue
            }
          }
      
          $targetAppName = New-ListBox -TitleText "File List" -LabelText "Select desired file" -ListBoxItems $targetAppFiles.Name
          $AppPath = ($targetAppFiles | Where-Object {$_.Name -eq $targetAppName}).FullName
        }
      }
      if (-not $ShortcutPath){

      }
      
      
      

      
        
      if ($Scope -eq [Scope]::User){
        $cimSession = New-CimSession -ComputerName $computer -Credential $Credential
        $userList = New-Object System.Collections.Generic.List[System.String]
        $win32_UserProfile = Get-CimInstance -CimSession $cimSession -ClassName Win32_UserProfile
        $userPaths =  $win32_UserProfile | Where-Object -not Special | Select-Object -ExpandProperty LocalPath

        foreach ($path in $userPaths){
          $userList.Add($path.Split('\')[2])
        }

        $targetUser = New-ListBox -TitleText "Users" -LabelText "Select target user" -ListBoxItems $userList
        $targetUserSID = ($win32_UserProfile | Where-Object {$_.LocalPath -like "*\$targetUser*"}).SID
        $targetUserDesktopPath = Invoke-Command -ArgumentList $targetUserSID -Session $psSession -ScriptBlock {
          param ($targetUserSID)
          $desktopRegistryKey = Get-ItemProperty -Path "Registry::HKEY_USERS\$targetUserSID\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "Desktop"
          return $desktopRegistryKey.Desktop
        }
      }

      Invoke-Command -ArgumentList $targetFile, $targetSoftware, $targetUserDesktopPath, $scope -Session $psSession -ScriptBlock {
        param(
          $targetFile, $targetSoftware, $targetUserDesktopPath, $scope
        )
        enum Scope {
          Global
          User
        }

        
        
        if ($scope -eq [Scope]::Global){
          $WScriptShell = New-Object -ComObject WScript.Shell
        $targetUserDesktopPath = $WScriptShell.SpecialFolders("AllUsersDesktop")
        }

        $targetAppDirectory = (Split-Path -Path $targetFile)

        
        
        $Shortcut = $WScriptShell.CreateShortcut("$targetUserDesktopPath\$targetSoftware.lnk")
        $Shortcut.WindowStyle = 1
        $Shortcut.TargetPath = $targetFile
        $Shortcut.WorkingDirectory = $targetAppDirectory
        $Shortcut.IconLocation = $targetFile
        $Shortcut.Save()
      }

    }
  }

  end {

  }

  # $InstalledSoftware = Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
  # $InstalledSoftware = Get-ChildItem "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
  # foreach($obj in $InstalledSoftware){write-host $obj.GetValue('DisplayName')}
}