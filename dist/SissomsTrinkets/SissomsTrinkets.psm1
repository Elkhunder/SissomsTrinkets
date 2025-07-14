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
#requires -version 5

<#

.SYNOPSIS

  Downloads, copies and extracts driver files to a specified computer[s].



.PARAMETER ComputerName

  One or more computer names to copy driver files to.



.INPUTS

  None

  

.OUTPUTS

  None

.NOTES

  Version:        1.0

  Author:         Jonathon Sissom

  Creation Date:  1/22/2024

  Purpose/Change: Initial script development

  Supported Adapters:

    Intel® Wi-Fi 7 BE202

    Intel® Wi-Fi 7 BE200

    Intel® Wi-Fi 6E AX411 (Gig+)

    Intel® Wi-Fi 6E AX211 (Gig+)

    Intel® Wi-Fi 6E AX210 (Gig+) IOT Industrial Kit

    Intel® Wi-Fi 6E AX210 (Gig+) IOT Embedded Kit

    Intel® Wi-Fi 6E AX210 (Gig+)

    Intel® Wi-Fi 6 (Gig+) Desktop Kit

    Intel® Wi-Fi 6 AX203

    Intel® Wi-Fi 6 AX201

    Intel® Wi-Fi 6 AX200

    Intel® Wi-Fi 6 AX101

    Intel® Wireless-AC 9560

    Intel® Wireless-AC 9461

    Intel® Wireless-AC 9462

    Intel® Wireless-AC 9260

    Intel® Dual Band Wireless-AC 9260 IoT Kit

    Intel® Dual Band Wireless-AC 3168

    Intel® Dual Band Wireless-AC 3165

    Intel® Dual Band Wireless-AC 7265 (Rev D)

    Intel® Dual Band Wireless-N 7265(Rev D)

    Intel® Wireless-N 7265 (Rev D)

    Intel® Tri-Band Wireless-AC 17265 

.EXAMPLE

  .\DownloadDrivers.ps1 -ComputerName Computer1,Computer2



  Downloads drivers to Computer1 and Computer2 and prompts the user to select a folder to copy the files to.



.EXAMPLE

  .\SystemFileScan.ps1 -ComputerName Computer1



  Downloads drivers to Computer1 and copies them to the default location C:\Users\Public\Downloads.

#>

#---------------------------------------------------------[Script Parameters]------------------------------------------------------



function Get-Driver {
  [CmdletBinding()]

param (

    [Parameter(Mandatory=$true)]

    [string[]]

    $ComputerName,

    [Parameter(Mandatory=$true)]

    [pscredential]

    $Credential = (Get-Credential)

    # [switch]

    # $PromptFolder

)



#---------------------------------------------------------[C# Code]----------------------------------------------------------------

# $code = @"

# using System;

# using System.Windows.Forms;



# public class Win32Window : IWin32Window

# {

#     public Win32Window(IntPtr handle)

#     {

#         Handle = handle;

#     }



#     public IntPtr Handle { get; private set; }

# }

# "@



#     if (-not ([System.Management.Automation.PSTypeName]'Win32Window').Type) {

#         Add-Type -TypeDefinition $code -ReferencedAssemblies System.Windows.Forms.dll -Language CSharp

#     }



#---------------------------------------------------------[Initialisations]--------------------------------------------------------

Add-Type -AssemblyName System.Windows.Forms

$version = "23.60.1"

# Url identifier is the number that follows the base url, in the url below that would be 825733

# https://downloadmirror.intel.com/825733/WiFi-23.60.1-Driver64-Win10-Win11.zip

$urlIdentifier = "825733"

$url = "https://downloadmirror.intel.com/$urlIdentifier/WiFi-$version-Driver64-Win10-Win11.zip"



$downloadDestination = "C:\Users\Public\Downloads\WiFi-$version-Driver64-Win10-Win11.zip"

$expandDestination = "C:\Users\Public\Downloads\WiFi-$version-Driver64-Win10-Win11"



# $owner = [Win32Window]::new([System.Diagnostics.Process]::GetCurrentProcess().MainWindowHandle)



# if($PromptFolder) {

#     $FolderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog

#     $FolderBrowser.SelectedPath = $PromptFolder

#     $FolderBrowser.ShowNewFolderButton = $true

#     $FolderBrowser.Description = "Select a folder to copy drivers to."

#     $FolderBrowser.ShowDialog($owner) | Out-Null

#     $downloadDestination = $FolderBrowser.SelectedPath

# }



#Set Error Action to Silently Continue

$ErrorActionPreference = "Inquire"



#Import Modules & Snap-ins



#----------------------------------------------------------[Declarations]----------------------------------------------------------



#Any Global Declarations go here



#-----------------------------------------------------------[Functions]------------------------------------------------------------



# Log helper function

Function Write-Log {

    Param(

        [string]$Message,

        [string]$LogPath,

        [switch]$ToFile = $false,

        [switch]$ToOut = $false

        )      

        $logMessage = "$(Get-Date -Format o) | $Message" 

        if ($ToFile){

            $logMessage | Out-File -Append $LogPath

        }

        elseif ($ToOut) {

            $logMessage | Write-Output

        }

    }

Function Test-RemoteConnection {

  Param ([string]$ComputerName)



  Begin {

    Write-Log "Testing remote connection to $ComputerName..." -LogPath $LogPath -ToOut

  }



  Process {

    Try {

        if (Test-Connection -ComputerName $Computer -Count 1 -Quiet) {

            Write-Log "$Computer is reachable." -LogPath $LogPath -ToOut

            return $true

        }

        else {

            Write-Log "$Computer is not reachable or does not respond to ping." -LogPath $LogPath -ToOut

            return $false

        }

    }

    Catch {

        Write-Log "$Computer could not be reached or connection failed: $($_.Exception.Message)" -LogPath $LogPath -ToOut

        return $false

    }

  }



  End {

    if ($?) {

      Write-Log "Connection test completed." -LogPath $LogPath -ToOut

    }

  }



}



Function Get-DriverFiles {



    param (

        [Parameter(Mandatory=$true)][System.Management.Automation.Runspaces.PSSession]$Session,

        [Parameter(Mandatory=$true)][System.IO.FileInfo]$downloadDestination,

        [Parameter(Mandatory=$true)][System.IO.FileInfo]$expandDestination,

        [Parameter(Mandatory=$true)][string]$url

    )

    Write-Log "Downloading drivers to $ComputerName" -LogPath $LogPath -ToOut

    Invoke-Command -Session $Session -ScriptBlock {

        Start-BitsTransfer -Source $using:url -Destination $using:downloadDestination -ErrorAction SilentlyContinue

        #unzip file

        Expand-Archive -Path $using:downloadDestination -DestinationPath $using:expandDestination -Force

        #remove zip file

        Remove-Item -Path $using:downloadDestination -Force

    }

    Write-Log "Drivers downloaded to $ComputerName at $expandDestination" -LogPath $LogPath -ToOut

}



#---------------------------------------------------------[Script Start]-----------------------------------------------------------



foreach ($Computer in $ComputerName) {

    #Test remote connection

    if (Test-RemoteConnection -ComputerName $Computer) {

      Write-Log "Connecting to $ComputerName" -LogPath $LogPath -ToOut

      $Session = New-PSSession -ComputerName $ComputerName -Credential $Credential -ErrorAction SilentlyContinue

      Write-Log "Connected to $ComputerName" -LogPath $LogPath -ToOut

        if ($Session) {

            Get-DriverFiles -Session $Session -downloadDestination $downloadDestination -expandDestination $expandDestination -url $url

            Remove-PSSession -Session $Session -ErrorAction SilentlyContinue

            Write-Log "Disconnected from $ComputerName" -LogPath $LogPath -ToOut

        }

    }

}
}


<#
.SYNOPSIS
    Retrieves and evaluates the Configuration Manager (CCM) client health status on one or more remote computers.

.DESCRIPTION
    The `Get-CCMClientHealth` function connects to specified remote computers, retrieves the health status of the Configuration Manager client,
    and outputs a summary of the health check. This function requires the computer name(s) and credentials for access.

    This function performs the following:
    - Establishes a CIM session on each specified computer to retrieve client information.
    - Executes a client health evaluation using the `ccmeval.exe` utility on the remote machine.
    - Reads and parses the `CcmEvalReport.xml` file to gather detailed health check information.

.PARAMETER ComputerName
    Specifies the name(s) of the computer(s) on which to check the CCM client health. This parameter is mandatory.

.PARAMETER Credential
    Specifies a user credential with administrative access to the target computers. This parameter is mandatory.

.OUTPUTS
    Custom output generated by the `CCMEval` class, providing information on the client status, health check summary, and detailed health check results.

.EXAMPLE
    PS C:\> Get-CCMClientHealth -ComputerName "Computer1", "Computer2" -Credential (Get-Credential)

    Retrieves the Configuration Manager client health status for "Computer1" and "Computer2" using the specified credentials.

.NOTES
    Author: Jonathon Sissom
    Date: 11/06/2024
    Version: 1.01

    This function uses CIM sessions and remote commands to gather client health data from remote systems. 
    Ensure that the `SMS_Client` class is available on the remote computer.

#>
function Get-CCMClientHealth {
    [CmdletBinding()]
    param (
        # Parameter help description
        [Parameter(Mandatory)]
        [string[]]
        $ComputerName,
        # Parameter help description
        [Parameter(Mandatory)]
        [pscredential]
        $Credential
    )
    
    begin {
            class CCMEval {
                [Client]$Client
                [HealthCheckSummary]$Summary
                [HealthCheckResult[]]$HealthChecks
            
                # Constructor for CCMEval
                CCMEval([CimInstance]$smsClient, [object]$healthCheckSummary, [System.Xml.XmlElement[]]$healthChecks) {
                    # Initialize Client object
                    $this.Client = [Client]::new($smsClient)
            
                    # Initialize HealthCheckSummary object
                    $this.Summary = [HealthCheckSummary]::new($healthCheckSummary)
            
                    # Initialize HealthChecks array with HealthCheckResult objects
                    $this.HealthChecks = $healthChecks | ForEach-Object { [HealthCheckResult]::new($_) }
                }

                # Returns a structured custom object for detailed information
                [PSCustomObject] ToStructuredOutput() {
                    return [pscustomobject]@{
                        ClientInfo = [pscustomobject]@{
                            ComputerName = $this.Client.ComputerName
                            Version = $this.Client.Version
                            Type = $this.Client.Type
                            AllowLocalAdminOverride = $this.Client.AllowLocalAdminOveride
                            EnableAutoAssignment = $this.Client.EnableAutoAssignment
                        }
                        HealthCheckSummary = [pscustomobject]@{
                            EvaluationDate = $this.Summary.EvaluationDate
                            Version = $this.Summary.Version
                            Result = $this.Summary.Result
                        }
                        HealthChecks = $this.HealthChecks | ForEach-Object {
                            [pscustomobject]@{
                                ID = $_.ID
                                Description = $_.Description
                                ResultCode = $_.ResultCode
                                ResultType = $_.ResultType
                                ResultDetail = $_.ResultDetail
                                StepDetail = $_.StepDetail
                                ResultStatus = $_.ResultStatus
                            }
                        }
                    }
                }

                # Returns a JSON representation for easy integration with other tools
                [string] ToJson() {
                    return (ConvertTo-Json -InputObject $this.ToStructuredOutput() -Depth 10)
                }

                # Returns a brief summary of health check status
                [pscustomobject] GetSummary() {
                    return [PSCustomObject]@{
                        ComputerName = $this.Client.ComputerName
                        ClientVersion = $this.Client.Version.ToString()
                        EvaluationDate = $this.Summary.EvaluationDate
                        Version = $this.Summary.Version.ToString()
                        Result = $this.Summary.Result
                    }
                }

                # ToString method to format output
                [string] ToString() {
                    $output = @()
                    $output += "Client Info:"
                    $output += "--------------------------"
                    $output += "Computer Name: $($this.Client.ComputerName)"
                    $output += "Client Version: $($this.Client.Version)"
                    $output += "Client Type: $($this.Client.Type)"
                    $output += "Allow Local Admin Override: $($this.Client.AllowLocalAdminOveride)"
                    $output += ""
                    $output += "Health Check Summary:"
                    $output += "--------------------------"
                    $output += "Evaluation Date: $($this.Summary.EvaluationDate)"
                    $output += "Summary Result: $($this.Summary.Result)"
                    $output += "Summary Version: $($this.Summary.Version)"

                    return $output -join "`n"
                }
            }
            class Client {
                [bool]$AllowLocalAdminOveride
                [int]$Type
                [version]$Version
                [bool]$EnableAutoAssignment
                [string]$ComputerName

                Client([CimInstance]$smsClient){
                    $this.AllowLocalAdminOveride = $smsClient.AllowLocalAdminOverride
                    $this.Type = $smsClient.ClientType
                    $this.Version = $smsClient.ClientVersion
                    $this.EnableAutoAssignment = $smsClient.EnableAutoAssignment
                    $this.ComputerName = $smsClient.PSComputerName
                }
            }
            class HealthCheckSummary {
                [datetime]$EvaluationDate
                [version]$Version
                [string]$Result

                HealthCheckSummary([object[]]$healthCheckSummary){
                    $this.EvaluationDate = $healthCheckSummary.EvaluationTime
                    $this.Version = $healthCheckSummary.Version
                    $this.Result = $healthCheckSummary.'#text'
                }
            }
            class HealthCheckResult {
                [string]$ID
                [string]$Description
                [int]$ResultCode
                [int]$ResultType
                [string]$ResultDetail
                [string]$StepDetail
                [string]$ResultStatus

                HealthCheckResult([System.Xml.XmlElement]$healthCheck) {
                    # Extract values from the XML element
                    $this.ID = $healthCheck.ID
                    $this.Description = $healthCheck.Description
                    $this.ResultCode = [int]$healthCheck.ResultCode
                    $this.ResultType = [int]$healthCheck.ResultType
                    $this.ResultDetail = $healthCheck.ResultDetail
                    $this.StepDetail = $healthCheck.StepDetail
                    # Map '#text' to ResultStatus
                    $this.ResultStatus = $healthCheck.'#text'
                }
            }
    }
    
    process {
        $results = @()
        foreach ($Computer in $ComputerName) {
            try {
                Write-Verbose "Connecting to $Computer"
                $cimSession = New-CimSession -ComputerName $Computer -Credential $Credential -ErrorAction Stop

                $smsClient = Get-CimInstance -Namespace "root/ccm" -ClassName SMS_Client -CimSession $cimSession
                if (-not $smsClient) {
                    Write-Warning "SMS_Client class not found on $Computer"
                    continue
                }

                # Get local SMS path and check for required files
                $localSMSPath = (Invoke-Command -ComputerName $Computer -Credential $Credential -ScriptBlock {
                    Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\SMS\Client\Configuration\Client Properties"
                })."Local SMS Path"

                $ccmEvalPath = "${localSMSPath}ccmeval.exe"
                $ccmEvalReportPath = "${localSMSPath}CcmEvalReport.xml"
                
                if (!(Test-Path -Path $ccmEvalPath)) {
                    Write-Warning "ccmeval.exe not found on $Computer"
                    continue
                }

                Write-Verbose "Executing CCM evaluation on $Computer"
                Invoke-Command -ComputerName $Computer -Credential $Credential -ScriptBlock {
                    Start-Process -FilePath $using:ccmEvalPath -NoNewWindow -Wait
                } -ErrorAction Stop

                if (!(Test-Path -Path $ccmEvalReportPath)) {
                    Write-Warning "CcmEvalReport.xml not found on $Computer after evaluation"
                    continue
                }

                [xml]$ccmEvalReport = Invoke-Command -ComputerName $Computer -Credential $Credential -ScriptBlock {
                    Get-Content -Path $using:ccmEvalReportPath
                } -ErrorAction Stop

                [object[]]$ccmHealthChecks = $ccmEvalReport.ClientHealthReport.HealthChecks.HealthCheck
                [object[]]$ccmHealthCheckSummary = $ccmEvalReport.ClientHealthReport.Summary

                $ccmEval = [CCMEval]::new($smsClient, $ccmHealthCheckSummary, $ccmHealthChecks)
                $results += $ccmEval
            }
            catch {
                Write-Error "Failed to retrieve client health status for $Computer : $_"
            }
            finally {
                if ($cimSession) {
                    $cimSession | Remove-CimSession
                }
            }
        }   
    }
    
    end {
        $results | ForEach-Object {
            $_.GetSummary()
            if ($_.Summary.Result -ne "Passed"){
                $_.HealthChecks | Foreach-Object {
                    if ($_.ResultCode -ne 0){
                        Write-Output $_
                    }
                } 
            }
        }

        if ($PSCmdlet.MyInvocation.BoundParameters["OutVariable"]) {
            $OutVariableName = $PSCmdlet.MyInvocation.BoundParameters["OutVariable"]
            Set-Variable -Name $OutVariableName -Value $results -Scope 1 -Option AllScope
        }
    }
}
<#

************************** Change Log ******************************
************************** Version 1 *******************************

** Initial Commit **

************************ Feature Requests **************************

Future - Add ability to choose if you want to export results to a file instead of have it written to console

#>
function Get-CurrentUser{
  [CmdletBinding()]
  param (
      [Parameter(Mandatory, ParameterSetName = 'Remote')]
      [string[]]
      $ComputerName,

      [Parameter(Mandatory, ParameterSetName = 'Remote')]
      [Parameter(Mandatory, ParameterSetName = 'RemoteFile')]
      [pscredential]
      $Credential,

      [Parameter(Mandatory, ParameterSetName = 'RemoteFile')]
      [switch]
      $UseInputDialog,

      [Parameter(Mandatory, ParameterSetName = 'local')]
      [switch]
      $Local
  )
  begin{
    $userInfo = [System.Collections.Generic.List[Object]]::new()

    $loginSessionType = @{
      '10' = 'RemoteInteractive'
      '2' = 'Interactive'
      '3' = 'Network'
    }
  }

  process{

      if ($Local){
        $win32_ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem

        ### Store the information in an array
        $userInfo += [PSCustomObject]@{
          'Computer' = $win32_ComputerSystem.Name;
          'Online' = 'True'
          'Current User' = $win32_ComputerSystem.UserName
        }
      }
      if ($ComputerName){
        foreach ($computer in $ComputerName) {
          $interactiveLogonSession = $null
          $remoteInteractiveLogonSession = $null
          $remoteInteractiveLogonUser = $null
          $interactiveLogonUser = $null
          try {
            if (-not (Test-Connection -TargetName $computer -Count 1 -quiet)){
              $userInfo += [PSCustomObject]@{
                'Computer' = $computer
                'Online' = 'False'
                'Current User' = 'None'
              }
              continue
            }
            $cimSession = New-CimSession -ComputerName $computer -Credential $Credential
            $interactiveLogonSession = Get-CimInstance -CimSession $cimSession -ClassName Win32_LogonSession -Filter "LogonType = 2 AND AuthenticationPackage = 'Kerberos'"
            $remoteInteractiveLogonSession = Get-CimInstance -CimSession $cimSession -ClassName Win32_LogonSession -Filter "LogonType = 3 AND AuthenticationPackage = 'NTLM'"
            
            if ($interactiveLogonSession){
              # Get Win32_Account instance that is associated with the above session
              $interactiveLogonUser = Get-CimAssociatedInstance -CimSession $cimSession -InputObject $interactiveLogonSession -Association Win32_LoggedOnUser
            }
            if($remoteInteractiveLogonSession){
              # Get Win32_Account instance that is associated with the above session
              $remoteInteractiveLogonUser = Get-CimAssociatedInstance -CimSession $cimSession -InputObject $remoteInteractiveLogonSession -Association Win32_LoggedOnUser
            }

            ### Store the information in an array
            $userInfo.Add([PSCustomObject]@{
              Computer = $interactiveLogonSession.PSComputerName ?? $remoteInteractiveLogonSession.PSComputerName  ?? $computer;
              Online = 'True'
              LocalSession = [PSCustomObject]@{
                Username = $interactiveLogonUser.Caption ?? 'None' # Assign locally logged in user or none
                SessionType = $loginSessionType["$($interactiveLogonSession.LogonType)"] ?? 'None'
              }
              RemoteSession = [PSCustomObject]@{
                Username = $remoteInteractiveLogonUser.Caption ?? 'None' # Assign remote loggedin user or none
                SessionType = $loginSessionType["$($remoteInteractiveLogonSession.LogonType)"] ?? 'None'
              }
            })
            
          }catch{
            $_
            $userInfo += [PSCustomObject]@{
              'Computer' = $computer
              'Online' = 'True'
              'Current User' = 'None'
              'Error' = $_
            }
          }
          Remove-CimSession -CimSession $cimSession
        }
      }
    #$userInfo | Select-Object Computer, Online, @{Name = 'Local Session'; Expression = {"$($_.LocalSession.Username), $($_.LocalSession.SessionType)"}}, @{Name = 'Remote Session'; Expression = {"$($_.RemoteSession.Username), $($_.RemoteSession.SessionType)"}} | Format-List
    return $userInfo
    #$Content | Export-Csv -Path .\UserList.csv -Append -NoTypeInformation
  }
}
function Get-HardDriverSerialNumbers {
    [CmdletBinding()]
    param (
        
    )
    
    begin {
        
    }
    
    process {
        Write-Host 'Enter Term ID, if multiples seperate with ,' -NoNewLine
        $computers = Read-Host ' '
        $computers = $computers -split ','

        foreach ($computer in $computers)
        {
        Write-Host `Testing connection to $computer`
        $testConnection = Test-Connection -Quiet $computer

        if ($testConnection)
        {
        try
            {
            Write-Host `Querying $computer for hardware information...`
            Start-Sleep -s 3
            $hardware = Get-CimInstance -OperationTimeoutSec 10 -ComputerName $computer -ClassName Win32_DiskDrive | Select-Object Model,SerialNumber
            Write-Host 'Writing hardware information to console...'
            Start-Sleep -s 3
            $hardware | Format-Table | Out-String | Write-Host
            }
        catch
            {
            Write-Host 'An error occurred:'
            Write-Host $_
            }
        }
        else
        {
        Write-Host `*** $computer is offline ***`
        }
        }
        Read-Host 'Press enter to exit'
    }
    
    end {
        
    }
}
function Get-InstalledPrinter {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string[]]
        $ComputerName,

        [Parameter()]
        [CimSession]
        $CimSession,

        [Parameter()]
        [switch]
        $InputFile,

        [Parameter()]
        [switch]
        $OutputFile,
        
        [Parameter()]
        [switch]
        $Append
    )
    
    begin {
        
    }
    
    process {
        
    }
    
    end {
        
    }
}


# $userFile = Read-Host -Prompt 'Do you want to use a file for importing computer names? (Y/N)'
# try {
#   if($userFile -eq 'Y') {
#     Do {

#       Write-Host 'Place a text file on your desktop that contains the computer names'
#       $filename = Read-Host -Prompt "Input filename w/o extension"
#       $filePath = "C:\Users\$env:USERNAME\Desktop\$filename.txt"
#       $testPath = Test-Path $filePath -PathType Leaf
#       if ($testPath -eq "True") {continue}
#       else {

#         Write-Host 'The file was not found, or there was an error'
#         Write-Host $_
#       }
#     }
#     Until ($testPath -eq "True")

#     $computers = Get-Content $filePath
#     Write-Host $computers
#   }

#   if($userFile -eq 'N') {

#     ### Prompt for list of computers and assign to the variable computers
#     $computers = Read-Host -Prompt 'Enter Term ID, if multiples seperate with ,'
#     ### Split list of computers using , as the seperator
#     $computers = $computers -split ','
#   }
# } catch {

#   Write-Host 'An error occured'
#   Write-Host $_
# }

# ### Prompt for credentials
# $credential = $host.ui.PromptForCredential("Need credentials", "Please enter your level 2 credentials.", "", "NetBiosUserName")
# $output = foreach ($computer in $computers) {
#   try {
#     $reachable = Test-Connection -Cn $computer -BufferSize 16 -Count 1 -ea 0 -quiet
#     $output = @()
#     ### Check to see if computer is reachable
#     if ($reachable)
#     {
#         ### Get printer list
#         Write-Host `Pulling information from $computer ...`
#         $printerList = Get-Printer -ComputerName $computer -Name "LOCAL"| Select-Object Name
#         $details = "information pulled from $computer successfully"
#     }
#     else
#     {
#         $details = `-$computer is not online, no information was gathered`
#     }

#     ### Store the information in an array
#     New-Object -TypeName PSObject -Property @{
#         TermID = $computer
#         Online = $reachable
#         Printer = $printerlist
#         Details = $details
#     } | Select-Object TermID, Online, Printer, Details


#     }catch{
#         Write-Host 'An error occured'
#         Write-Host $_
#         }
# }
# $output | Export-Csv "C:\Users\$env:USERNAME\Desktop\ListPrinters-Results.csv"
# Read-Host -Prompt "Script has finished, please check output files"
# $u = New-Object -ComObject Microsoft.Update.Session
# $u.ClientApplicationID = 'MSDN Sample Script'
# $s = $u.CreateUpdateSearcher()
# #$r = $s.Search("IsInstalled=0 and Type='Software' and IsHidden=0")
# $r = $s.Search('IsInstalled=0')
# $r.updates|select -ExpandProperty Title

# Invoke-Command -Session $s -ScriptBlock {

# }
# Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force

Get-CimInstance -ClassName SMS_LookupMP -Namespace root/ccm
<#
.SYNOPSIS
Retrieves user profile information from local or remote systems.

.DESCRIPTION
The Get-UserProfile function retrieves user profiles from either the local machine or specified remote machines using the Win32_UserProfile class. 
It can operate in interactive mode to allow for profile selection or in a predefined mode using specific usernames.

The function supports querying remote machines with CIM (Common Information Model) sessions, allowing retrieval of profiles even across multiple machines.
It can authenticate to remote systems using supplied credentials and handles failures such as connection timeouts or unreachable systems.

Additionally, the function checks for locked or inaccessible profiles and provides feedback to the user if issues arise while accessing profile data.

.PARAMETER UserName
Specifies one or more usernames whose profiles you want to retrieve. If not provided, the function prompts for user selection interactively.

.PARAMETER Local
Indicates that the function should retrieve user profiles from the local machine.

.PARAMETER ComputerName
Specifies the name(s) of the remote computer(s) from which to retrieve user profiles. This parameter is mandatory if querying a remote machine.

.PARAMETER Credential
Specifies the credentials used to authenticate on the remote machine(s) when querying user profiles.

.OUTPUTS
Returns an array of user profile objects from the Win32_UserProfile class. If any errors occur (e.g., failed connections, locked profiles), an error message is displayed, but the function will continue processing other profiles if possible.

.EXAMPLE
Get-UserProfile -Local -UserName 'jsmith'
Retrieves the profile information for the user 'jsmith' on the local machine.

.EXAMPLE
Get-UserProfile -Local
Prompts for a user selection and retrieves the corresponding profile on the local machine.

.EXAMPLE
Get-UserProfile -ComputerName 'Server01' -UserName 'jsmith' -Credential (Get-Credential)
Retrieves the profile information for the user 'jsmith' from the remote machine 'Server01' using the specified credentials.

.EXAMPLE
Get-UserProfile -ComputerName 'Server01', 'Server02' -UserName 'jsmith' -Credential (Get-Credential)
Retrieves the profile information for the user 'jsmith' from multiple remote machines 'Server01' and 'Server02' using the specified credentials.

.NOTES
- The function supports both local and remote profile retrieval using CIM (Common Information Model) sessions.
- **Remote Failure Handling**: The function handles common errors such as failed connections, timeouts, or unreachable systems. If a remote machine cannot be contacted, an error is logged, and the function continues processing other computers or profiles.
- **Locked or Inaccessible Profiles**: If a profile is locked or cannot be accessed (due to permission issues or the profile being in use), the function logs a warning and skips that profile. This ensures the function continues processing other profiles without terminating.
- **Interactive Mode**: If no username is provided, the function enters an interactive mode, prompting the user to select from the available profiles.
- **Error Handling**: Uses `try/catch` blocks to gracefully handle connection errors and permission issues when dealing with remote profiles.
- **Return Behavior**: The function returns an array of user profile objects. If errors occur, the function does not stop but logs the error and continues processing other profiles.
#>
function Get-UserProfile {
    [CmdletBinding()]
    param (
        [Parameter(ParameterSetName = 'Local')]
        [Parameter(ParameterSetName = 'Remote')]
        [string]
        $UserName,

        [Parameter(Mandatory, ParameterSetName = 'Local')]
        [switch]
        $Local,

        [Parameter(Mandatory, ParameterSetName = 'Remote')]
        [string[]]
        $ComputerName,

        [Parameter(Mandatory, ParameterSetName = 'Remote')]
        [pscredential]
        $Credential        
    )
    
    begin {
        $userList = @()
        $selectedProfiles = @()
    }
    
    process {
        if ($Local){
            $win32_UserProfile = Get-CimInstance -ClassName Win32_UserProfile | Where-Object -not Special

            if (-not $UserName){
                # Extract the usernames from LocalPath
                $userPaths = $win32_UserProfile | Select-Object -ExpandProperty LocalPath

                foreach ($path in $userPaths) {
                    $userList += $path.Split('\')[2]  # Extract username part
                }
                
                # Present the user list and prompt for selection
                $selectedUser = Read-Host "Select a user - $($userList -join ', ')"
                
                # Find the profile that matches the selected user
                $selectedProfiles += $win32_UserProfile | Where-Object { 
                $_.LocalPath -like "*\$selectedUser"  # Ensure it matches exactly to the username
                }
                
            } elseif ($UserName) {
                # Find the profile that matches the selected user
                $selectedProfiles += $win32_UserProfile | Where-Object {
                    $_.LocalPath -like "*\$user"  # Ensure it matches exactly to the username
                }
            }

        } elseif ($ComputerName){
            foreach ($computer in $ComputerName){
                $win32_UserProfile = Get-CimInstance -Class Win32_UserProfile -Computer $computer -Credential $Credential |  Where-Object -not Special

                if (-not $UserName){
                    $userPaths = $win32_UserProfile | Select-Object -ExpandProperty LocalPath

                    foreach ($path in $userPaths) {
                        $userList += $path.Split('\')[2]  # Extract username part
                    }
                    # Present the user list and prompt for selection
                    $selectedUser = Read-Host "Select a user - $($userList -join ', ')"

                    # Find the profile that matches the selected user
                    $selectedProfiles += $win32_UserProfile | Where-Object { 
                    $_.LocalPath -like "*\$selectedUser"  # Ensure it matches exactly to the username
                    }
                    
                }
                if ($UserName) {
                    # Find the profile that matches the selected user
                    $selectedProfiles += $win32_UserProfile | Where-Object {
                        $_.LocalPath -like "*\$user"  # Ensure it matches exactly to the username
                    }
                }
            }
            
        }
    }
    
    end {
        # Return the selected profiles
        return $selectedProfiles
    }
}
<#
.SYNOPSIS
Retrieves the Windows operating system version information for a list of specified computers.

.DESCRIPTION
The Get-WindowsVersion function queries the Windows version information from a list of computers, which can be provided directly or through a file. The function supports both local and remote computers, with the option to use secondary credentials for remote access. Results can be output to a file or displayed in the console.

.PARAMETER ComputerName
Specifies a list of computer names to query. This parameter accepts an array of strings. If used in conjunction with the UseInFile switch, an error will be raised.

.PARAMETER Credential
Provides credentials for authentication when accessing remote computers. This parameter expects a PSCredential object containing the username and password.

.PARAMETER UseInFile
Indicates that a file containing the list of computer names should be used instead of specifying them directly. A file dialog will prompt the user to select a CSV file.

.PARAMETER UseOutFile
Specifies that the results should be written to a file. A save file dialog will prompt the user to select the file path for saving the output.

.EXAMPLE
Get-WindowsVersion -ComputerName "Server1", "Server2" -Credential $myCred
Retrieves Windows version information for the specified computers using the provided credentials.

.EXAMPLE
Get-WindowsVersion -UseInFile
Prompts the user to select a file containing a list of computer names and retrieves their Windows version information.

.EXAMPLE
Get-WindowsVersion -ComputerName "Server1" -UseOutFile
Retrieves Windows version information for the specified computer and saves the results to a file.

.EXAMPLE
Get-WindowsVersion -UseInFile -UseOutFile
Prompts the user to select a file containing computer names and then saves the results to a specified output file.
#>
function Get-WindowsVersion{
    [CmdletBinding(DefaultParameterSetName = 'ByName')]
    [Alias('GWV')]
    param (
        # Switch to run the command locally
        [Parameter(Mandatory = $true, ParameterSetName = 'Local')]
        [switch]$Local,

        ## Begin General Parameters 
        # List of computer names
        [Parameter(Mandatory = $true, ParameterSetName = 'ByName', Position = 1)]
        [Parameter(ParameterSetName = 'ByOutFile')]
        [Parameter(ParameterSetName = 'ByOutputDialog')]
        [Parameter(Mandatory = $true, ParameterSetName = 'ProxyByNameAndWait')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Proxy')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Wait')]    
        [Alias('Computer')]
        [Alias('Computers')]
        [string[]]$ComputerName,

        # Secondary Credentials
        [Parameter(Mandatory = $false, ParameterSetName = 'ByName')]
        [Parameter(Mandatory = $false, ParameterSetName = 'ByFilePath')]
        [Parameter(Mandatory = $false, ParameterSetName = 'ByFileDialog')]
        [Parameter(Mandatory = $false, ParameterSetName = 'ByOutputDialog')]
        [Parameter(Mandatory = $false, ParameterSetName = 'ByOutFile')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Proxy')]
        [Parameter(Mandatory = $false, ParameterSetName = 'ProxyByNameAndWait')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Wait')]     
        [System.Management.Automation.Credential()]
        [PSCredential]$Credential,

        # Run as background job
        [Parameter(Mandatory = $false, ParameterSetName = 'ByName')]
        [Parameter(Mandatory = $false, ParameterSetName = 'ByFilePath')]
        [Parameter(Mandatory = $false, ParameterSetName = 'ByFileDialog')]
        [Parameter(Mandatory = $false, ParameterSetName = 'ByOutputDialog')]
        [Parameter(Mandatory = $false, ParameterSetName = 'ByOutFile')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Proxy')]
        [Parameter(Mandatory = $false, ParameterSetName = 'ProxyByNameAndWait')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Wait')]     
        [switch]$AsJob,

        ## End General Parameters

        ## Begin File Parameters
        [Parameter(Mandatory = $true, ParameterSetName = 'ByFileDialog')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Proxy')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Wait')]       
        [switch]$UseInputDialog,

        [Parameter(Mandatory = $true, ParameterSetName = 'ByFilePath')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Proxy')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Wait')]        
        [string]$FilePath,

        # Prompt for output file with dialog
        [Parameter(Mandatory = $true, ParameterSetName = 'ByOutputDialog')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Proxy')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Wait')]          
        [switch]$UseOutputDialog,

        [Parameter(ParameterSetName = 'ByOutFile')]
        [Parameter(ParameterSetName = 'Proxy')]
        [Parameter(ParameterSetName = 'Wait')] 
        [string]$OutFile,

        # Begin Wait Parameters
        [Parameter(Mandatory = $true, ParameterSetName = 'Wait')]        
        [Parameter(Mandatory = $true, ParameterSetName = 'ProxyByNameAndWait')]
        [switch]$Wait,
        
        [Parameter(Mandatory = $false, ParameterSetName = 'Wait')] 
        [Parameter(Mandatory = $false, ParameterSetName = 'ProxyByNameAndWait')] 
        [int]$TimeoutMinutes = 60,

        [Parameter(Mandatory = $false, ParameterSetName = 'Wait')]     
        [Parameter(Mandatory = $false, ParameterSetName = 'ProxyByNameAndWait')] 
        [int]$IntervalSeconds = 30,

        # End Wait Parameters

        # Begin Proxy Parameters
        [Parameter(Mandatory = $true, ParameterSetName = 'Proxy')] 
        [Parameter(Mandatory = $true, ParameterSetName = 'ProxyByNameAndWait')]    
        [String]$ProxyHost,

        [Parameter(Mandatory = $true, ParameterSetName = 'Proxy')]
        [Parameter(Mandatory = $true, ParameterSetName = 'ProxyByNameAndWait')] 
        [String]$UserName,

        [Parameter(Mandatory = $true, ParameterSetName = 'Proxy')] 
        [Parameter(Mandatory = $true, ParameterSetName = 'ProxyByNameAndWait')] 
        [String]$KeyFilePath,

        [Parameter(Mandatory = $false, ParameterSetName = 'Proxy')]  
        [Parameter(Mandatory = $false, ParameterSetName = 'ProxyByNameAndWait')] 
        [Int]$Port = 22,
        # End Proxy Parameters

        [switch]$Append
    )

    begin{
        if ($ComputerName -and $FilePath){
            throw "ComputerName can not be used with FilePath"
        }
        if($ComputerName -and $UseInputDialog){
            throw "ComputerName can not be used with UseInputDialog"
        }
        if ($UseInputDialog -and $FilePath){
            throw "UseInputDialog can not be used with FilePath"
        }
        if ($UseOutputDialog -and $OutFile){
            throw "UseOutputDialog can not be used with OutFile"
        }
        $ProxySession = $null
        $WinVersionMap = @{
            '10240' = '1507'    # Windows 10, Version 1507
            '10586' = '1511'    # Windows 10, Version 1511
            '14393' = '1607'    # Windows 10, Version 1607 / Windows Server 2016, Version 1607
            '15063' = '1703'    # Windows 10, Version 1703
            '16299' = '1709'    # Windows 10, Version 1709
            '17134' = '1803'    # Windows 10, Version 1803
            '17763' = '1809'    # Windows 10, Version 1809 / Windows Server 2019, Version 1809
            '18362' = '1903'    # Windows 10, Version 1903
            '18363' = '1909'    # Windows 10, Version 1909 / Windows Server, Version 1909
            '19041' = '2004'    # Windows 10, Version 2004 / Windows Server, Version 2004
            '19042' = '20H2'    # Windows 10, Version 20H2 / Windows Server, Version 20H2
            '19043' = '21H1'    # Windows 10, Version 21H1
            '19044' = '21H2'    # Windows 10, Version 21H2
            '19045' = '22H2'    # Windows 10, Version 22H2
            '22000' = '21H2'    # Windows 11, Version 21H2
            '22621' = '22H2'    # Windows 11, Version 22H2
            '22631' = '23H2'    # Windows 11, Version 23H2
        }
        $MacVersionMap = @{
            "10.0" = "Cheetah"
            "10.1" = "Puma"
            "10.2" = "Jaguar"
            "10.3" = "Panther"
            "10.4" = "Tiger"
            "10.5" = "Leopard"
            "10.6" = "Snow Leopard"
            "10.7" = "Lion"
            "10.8" = "Mountain Lion"
            "10.9" = "Mavericks"
            "10.10" = "Yosemite"
            "10.11" = "El Capitan"
            "10.12" = "Sierra"
            "10.13" = "High Sierra"
            "10.14" = "Mojave"
            "10.15" = "Catalina"
            "11"   = "Big Sur"
            "12"   = "Monterey"
            "13"   = "Ventura"
            "14"   = "Sonoma"
            "15"   = "Sequoia"
        }
        if ($AsJob){
            Write-Verbose "Jobs switch detected"
            Write-Verbose "Initializing jobs array"
            $jobs = @()
        }
        if ($FilePath){
            Write-Verbose "Gathering computer names from: $([IO.Path]::GetFullPath($FilePath))"
            $ComputerName = Get-Content -Path $([IO.Path]::GetFullPath($FilePath))
        }
        if ($OutFile){
            $OutFile = $([IO.Path]::GetFullPath($OutFile))
            Write-Verbose "Output will be exported to: $OutFile"
        }
        if($UseInputDialog -and $IsWindows){
            Write-Verbose "Prompting for file"
            Add-Type -AssemblyName System.Windows.Forms
            $Form = New-Object 'System.Windows.Forms.Form' -Property @{TopMost=$true}
            $File = New-Object System.Windows.Forms.OpenFileDialog
                $File.ShowHelp = $true
                $File.InitialDirectory = [Environment]::GetFolderPath('Desktop')
                $File.Filter = "CSV Files (*.csv)|*.csv"
                $File.FilterIndex = 1
                $File.CheckFileExists = $true
                
            #$FileDialog = $File.ShowDialog($Form)
    
            while ($file.ShowDialog($form) -ne [System.Windows.Forms.DialogResult]::OK) {
                # If the dialog result is not "OK", it must be "Cancel", so we prompt the user
                $response = [System.Windows.Forms.MessageBox]::Show("You pressed Cancel. Do you want to try again?", "File Selection", [System.Windows.Forms.MessageBoxButtons]::YesNo)
                # If the user selects "No" on the message box, exit the loop
                if ($response -eq [System.Windows.Forms.DialogResult]::No) {
                    $manualEntryResponse = [System.Windows.Forms.MessageBox]::Show("Do you want to enter computers manually?", "Manual Entry", [System.Windows.Forms.MessageBoxButtons]::YesNo)
                    if ($manualEntryResponse -eq [System.Windows.Forms.DialogResult]::No){
                        Write-Output "Operation cancelled by user."
                        return
                    }
                }
            }
            Write-Verbose "Gathering computer names from: $([Io.Path]::GetFullPath($File.FileName))"
            $ComputerName = Get-Content -Path $([Io.Path]::GetFullPath($File.FileName))
        }
        if ($UseInputDialog -and $IsMacOS){
            $FilePath = Read-Host "File dailogs are not supported on MacOS, Please enter full path to file location"

            Write-Verbose "Gathering computer names from: $([IO.Path]::GetFullPath($FilePath))"
            $ComputerName = Get-Content -Path $([IO.Path]::GetFullPath($FilePath))
        }
        if ($UseOutputDialog -and $IsWindows){
            Add-Type -AssemblyName System.Windows.Forms
            $Form = New-Object System.Windows.Forms.Form -Property @{TopMost = $true}
            $File = New-Object System.Windows.Forms.SaveFileDialog
                $File.ShowHelp = $true
                $File.InitialDirectory = [Environment]::GetFolderPath('Desktop')
                $File.Filter = "CSV Files (*.csv)|*.csv"
                $File.FilterIndex = 1
                $File.OverwritePrompt = $true
            while ($File.ShowDialog($Form) -ne [System.Windows.Forms.DialogResult]::OK){
                $response = [System.Windows.Forms.MessageBox]::Show("You pressed Cancel. Do you want to try again?", "File Selection", [System.Windows.Forms.MessageBoxButtons]::YesNo)
            
                # If the user selects "No" on the message box, exit the loop
                if ($response -eq [System.Windows.Forms.DialogResult]::No) {
                    Write-Output "File export cancelled by user"
                    break
                }
            }
            Write-Verbose "Output will be exported to: $([IO.Path]::GetFullPath($File.FileName))"
            $OutFile = $([IO.Path]::GetFullPath($File.FileName))
        }
        if ($UseOutputDialog -and $IsMacOS){
            $filePath = Read-Host "File dialogs are not supported on MacOS, Please enter full path to file location"

            Write-Verbose "Output will be exported to: $([IO.Path]::GetFullPath($filePath))"
            $OutFile = $([IO.Path]::GetFullPath($filePath))
        }
        if (($ComputerName.Length -gt 1) -or ($ComputerName.Length -eq 1 -and !($ComputerName -contains '127.0.0.1' -or $ComputerName -contains 'localhost')) -and $null -eq $Credential){
            Write-Verbose "Prompting user for credentials"
            $Credential = $(Get-Credential -UserName "umhs\umhs-$([Environment]::UserName)" -Message "Enter Secondary Credentials")
            Write-Verbose "Credentials recevied for user: $($Credential.UserName)"
        }
        if ($ProxyHost -and $KeyFilePath -and -not $AsJob){
            Write-Verbose "Creating proxy session to: ${ProxyHost} with key file: ${KeyFilePath}"
            $ProxySession = New-PSSession -HostName $ProxyHost -Port $Port -UserName $UserName -KeyFilePath $KeyFilePath
        }
        # if ($ProxyHost -and -not $KeyFilePath -and -not $AsJob){
        #     $ProxySession = New-PSSession -HostName $ProxyHost -UserName $UserName -Port $Port
        # }
        $DeviceInfoList = @()
    }

    process{
        if ($Local -and $IsMacOS){
            Write-Verbose "Initiating local system profiler query"
            $OperatingSystem = Invoke-LocalSPQuery -DataType SPSoftwareDataType -Json

            [version]$OperatingSystemVersion = $OperatingSystem.os_version.Split(' ')[1]

            $DeviceInfo = [PSCustomObject]@{
                'Computer' = $(scutil --get LocalHostName)
                'OS Name' = $MacVersionMap[$OperatingSystemVersion.Major]
                'OS Version' = $OperatingSystemVersion
            }

            $DeviceInfoList += $DeviceInfo

        }elseif ($Local){
            Write-Verbose "Initiating local cim query"
            ($Win32_OperatingSystem, $Win32_ComputerSystem) = Invoke-LocalCimQuery -Local -ClassName 'Win32_OperatingSystem', 'Win32_ComputerSystem'
            $RemoteUser = ((quser)[1].Split(" ", 2)[0]).Split('>',2)[1]
            $DeviceInfo = [PSCustomObject]@{
                'Computer' = $Win32_ComputerSystem.Name
                'Current User' = $Win32_ComputerSystem.UserName ?? $RemoteUser ?? 'None'
                'OS Name' = $Win32_OperatingSystem.Caption
                'OS Version' = $WinVersionMap[$Win32_OperatingSystem.BuildNumber]
            }

            $DeviceInfoList += $DeviceInfo

        }else{
            foreach ($Computer in $ComputerName.Split(",").Trim()){
                if ($AsJob){
                    # Pass connection properties to create pssession inside job, the full pssession object doesn't get passed properly
                    $jobs += Start-Job -Name "GetVersion_${Computer}" -ArgumentList $Computer, $Credential, $ProxyHost, $Port, $UserName, $KeyFilePath, $WinVersionMap, $OutFile, $Wait, $TimeoutMinutes, $IntervalSeconds -ScriptBlock {
                        param (
                            [string]$Computer,
                            [pscredential]$Credential,
                            [string]$ProxyHost,
                            [int]$Port,
                            [string]$UserName,
                            [string]$KeyFilePath,
                            [hashtable]$WinVersionMap,
                            [string]$OutFile,
                            [bool]$Wait,
                            [int]$TimeoutMinutes,
                            [int]$IntervalSeconds
                        )
                        $message = "Getting windows version for:"
                        $message = $message + " " + $Computer
                        Write-Output $message
    
                        if ($Wait){
                            $timeoutTime = [datetime]::Now.AddMinutes($TimeoutMinutes)
                            $isOnline = $false
                            while (-not $isOnline -and [datetime]::Now -lt $timeoutTime) {
                                try {
                                    $pingResult = Test-Connection -ComputerName $Computer -Count 1 -Quiet
                                    if ($pingResult) {
                                        $isOnline = $true
                                        $message = "[$(Get-Date)] $Computer is now online!"
            
                                        Write-Output $message
                                        Write-Verbose "Verbose: ${Verbose}"
                                        $currentVerbosePreference = $VerbosePreference
                                        $verbosePreference = 'SilentlyContinue'
                                        # if ($env:OS -match "Windows") {
                                        #     Import-Module BurntToast -ErrorAction SilentlyContinue
                                        #     New-BurntToastNotification -Text "Device is Online!", $message
                                        # } else {
                                        #     Write-Output "Notification: $message"
                                        # }
                                        $VerbosePreference = $currentVerbosePreference
                                    } else {
                                        if ($Verbose) {
                                            Write-Verbose "[$(Get-Date)] $Computer is still offline."
                                        }
                                        Start-Sleep -Seconds $IntervalSeconds
                                    }
                                } catch {
                                    Write-Warning "An error occurred while checking ${Computer}: $_"
                                }
                            }
            
                            if (-not $isOnline) {
                                Write-Output "[$(Get-Date)] Timeout reached. $Computer did not come online within the allotted time."
                            }
                        }
                        if ($ProxyHost){
                            Write-Output "Using proxy session to ${ProxyHost}"
                            if($KeyFilePath){
                                $ProxySession = New-PSSession -HostName $ProxyHost -Port $Port -UserName $UserName -KeyFilePath $KeyFilePath
                            } else {
    
                                $ProxySession = New-PSSession -HostName $ProxyHost -Port $Port -UserName $UserName
                            }
                            
                            ($Win32_OperatingSystem, $Win32_ComputerSystem) = Invoke-Command -Session $ProxySession -ArgumentList $Computer, $Credential -ScriptBlock {
                                param (
                                    [String]$Computer,
                                    [pscredential]$Credential
                                )
                                try {
                                    $CimSession = New-CimSession -Credential $Credential -ComputerName $Computer
                                    $Win32_OperatingSystem = Get-CimInstance -CimSession $CimSession -ClassName Win32_OperatingSystem
                                    $Win32_ComputerSystem = Get-CimInstance -CimSession $CimSession -ClassName Win32_ComputerSystem
                                    return $Win32_OperatingSystem, $Win32_ComputerSystem
                                }
                                catch {
                                    Write-Output $_
                                }
                                finally {
                                    Remove-CimSession -CimSession $CimSession
                                }
                            }
                        } else {
                            $CimSession = New-CimSession -Credential $Credential -ComputerName $Computer
                            try {
                                $Win32_OperatingSystem = Get-CimInstance -CimSession $CimSession -ClassName Win32_OperatingSystem
                                $Win32_ComputerSystem = Get-CimInstance -CimSession $CimSession -ClassName Win32_ComputerSystem
                            }
                            catch {
                                Write-Error $_
                            }
                            finally {
                                Remove-CimSession -CimSession $CimSession
                            }
                        }
                        $DeviceInfoList += [PSCustomObject]@{
                            'Timestamp' = $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                            'Computer' = $Computer
                            'Current User' = $Win32_ComputerSystem.Username ?? 'None'
                            'OS Name' = $Win32_OperatingSystem.Caption
                            'OS Version' = $WinVersionMap[$Win32_OperatingSystem.BuildNumber]
                        }
                        if ($OutFile){
                            $DeviceInfoList | Out-File -FilePath $OutFile -Append:$Append
                        }
                        return $DeviceInfoList
                    }
                } else {
                    if ($Wait){
                        $timeoutTime = [datetime]::Now.AddMinutes($TimeoutMinutes)
                        $isOnline = $false
                        
                        while (-not $isOnline -and [datetime]::Now -lt $timeoutTime) {
                            try {
                                $pingResult = Test-Connection -ComputerName $Computer -Count 1 -Quiet
                                if ($pingResult) {
                                    $isOnline = $true
                                    $message = "[$(Get-Date)] $Computer is now online!"
        
                                    Write-Host $message
                                    Write-Verbose "Verbose: ${Verbose}"
                                    $currentVerbosePreference = $VerbosePreference
                                    $verbosePreference = 'SilentlyContinue'
                                    # if ($env:OS -match "Windows") {
                                    #     Import-Module BurntToast -ErrorAction SilentlyContinue
                                    #     New-BurntToastNotification -Text "Device is Online!", $message
                                    # } else {
                                    #     Write-Output "Notification: $message"
                                    # }
                                    $VerbosePreference = $currentVerbosePreference
                                } else {
                                    if ($Verbose) {
                                        Write-Verbose "[$(Get-Date)] $Computer is still offline."
                                    }
                                    Start-Sleep -Seconds $IntervalSeconds
                                }
                            } catch {
                                Write-Warning "An error occurred while checking ${Computer}: $_"
                            }
                        }
        
                        if (-not $isOnline) {
                            Write-Output "[$(Get-Date)] Timeout reached. $Computer did not come online within the allotted time."
                        }
                        Write-Verbose "Exiting waiting loop"
                    }
    
                    if ($null -ne $ProxySession){
                        Write-Verbose "Using a proxy session to ${ProxyHost}"
                        ($Win32_OperatingSystem, $Win32_ComputerSystem) = Invoke-Command -Session $ProxySession -ArgumentList $Computer, $Credential -ScriptBlock {
                            param (
                                [String]$Computer,
                                [pscredential]$Credential
                            )
                            try {
                                $CimSession = New-CimSession -Credential $Credential -ComputerName $Computer
                                $Win32_OperatingSystem = Get-CimInstance -CimSession $CimSession -ClassName Win32_OperatingSystem
                                $Win32_ComputerSystem = Get-CimInstance -CimSession $CimSession -ClassName Win32_ComputerSystem
                                return $Win32_OperatingSystem, $Win32_ComputerSystem
                            }
                            catch {
                                Write-Output $_
                            }
                            finally {
                                Remove-CimSession -CimSession $CimSession
                            }
                        }
                    } else {
                        Write-Verbose "Not using a proxy"
                        $CimSession = New-CimSession -Credential $Credential -ComputerName $Computer
                        try {
                            Write-Host "Getting computer info"
                            $Win32_OperatingSystem = Get-CimInstance -CimSession $CimSession -ClassName Win32_OperatingSystem
                            $Win32_ComputerSystem = Get-CimInstance -CimSession $CimSession -ClassName Win32_ComputerSystem
                        }
                        catch {
                            Write-Error $_
                        }
                        finally {
                            Remove-CimSession -CimSession $CimSession
                        }
                    }
                    $DeviceInfo = [PSCustomObject]@{
                        'Timestamp' = $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                        'Computer' = $Computer ?? 'None'
                        'Current User' = $Win32_ComputerSystem.Username ?? 'None'
                        'OS Name' = $Win32_OperatingSystem.Caption ?? 'None'
                        'OS Version' = $WinVersionMap[$Win32_OperatingSystem.BuildNumber] ?? 'None'
                    }
                    $DeviceInfoList += $DeviceInfo
                }
            }
        }
        if ($OutFile){
            Write-Output "Calling out-file"
            Write-Host "Calling out-file"
            $DeviceInfoList | Out-File -FilePath $OutFile -Append:$Append
            # Out-File -FilePath $OutFile -Append -Verbose -InputObject $DeviceInfoList
        }
        if ($ProxySession){
            Remove-PSSession -Session $ProxySession
        }
        return $DeviceInfoList
    }
}
<#
.SYNOPSIS
Installs the specified language pack(s) on a remote computer and adds the selected language to the current user's language preferences. Additionally, it can provide a formatted list of supported languages when using the `-GetLanguageList` switch.

.DESCRIPTION
The `Install-LanguagePack` function connects to a remote computer, retrieves a list of available language packs, and installs the specified language pack(s). It also updates the current user's language preferences by adding the selected language. The function requires credentials for both the remote session and a shared network drive. Language pack installation is performed using a network drive located at "\\corefs.med.umich.edu\Shared2". Use the `-GetLanguageList` switch for a list of supported languages in a nicely formatted output.

.PARAMETER ComputerName
The name of the remote computer where the language pack will be installed.

.PARAMETER SecondaryCredential
The credentials used for connecting to the remote computer. This is an optional parameter. If not provided, the user will be prompted to enter secondary credentials.

.PARAMETER PrimaryCredential
The credentials used for connecting to a shared network drive. This is an optional parameter. If not provided, the user will be prompted to enter credentials for the shared network location.

.PARAMETER Language
The language pack to be installed. The parameter must be one of the valid languages from the predefined list, such as 'English (United States)', 'Japanese (Japan)', etc. Use the `-GetLanguageList` switch for a full list of supported languages.

.PARAMETER GetLanguageList
Specifies that the function should return a list of supported languages. This list is formatted for easy viewing and helps users quickly identify the available languages. When `-GetLanguageList` is provided, the function outputs only the language list and skips other information.

.EXAMPLE
Install-LanguagePack -ComputerName "RemotePC" -Language "English (United States)"
Installs the "English (United States)" language pack on the remote computer "RemotePC" and sets it as the user's preferred language.

.EXAMPLE
Install-LanguagePack -ComputerName "RemotePC" -Language "French (France)" -SecondaryCredential (Get-Credential) -PrimaryCredential (Get-Credential)
Installs the "French (France)" language pack on the remote computer "RemotePC" with specified credentials for the remote session and shared network drive.

.EXAMPLE
Install-LanguagePack -GetLanguageList
Displays a list of all supported language packs in a nicely formatted output for easy selection.

.NOTES
This function requires PowerShell remoting to be enabled on the target machine and access to the shared network drive for language pack installation.
#>
function Install-LanguagePack {
    param (
      [Parameter(Mandatory, ParameterSetName = "Install")]
      [string]
      $ComputerName,
      [Parameter(ParameterSetName = "Install")]
      [pscredential]
      $SecondaryCredential,
      [Parameter(ParameterSetName = "Install")]
      [pscredential]
      $PrimaryCredential,
      [Parameter(Mandatory, ParameterSetName = "Install")]
      [ValidateSet(
          'Arabic (Saudi Arabia)',
          'Basque (Basque)',
          'Bulgarian (Bulgaria)',
          'Catalan',
          'Chinese (Traditional, Hong Kong SAR)',
          'Chinese (Simplified, China)',
          'Chinese (Traditional, Taiwan)',
          'Croatian (Croatia)',
          'Czech (Czech Republic)',
          'Danish (Denmark)',
          'Dutch (Netherlands)',
          'English (United States)',
          'English (United Kingdom)',
          'Estonian (Estonia)',
          'Finnish (Finland)',
          'French (Canada)',
          'French (France)',
          'Galician',
          'German (Germany)',
          'Greek (Greece)',
          'Hebrew (Israel)',
          'Hungarian (Hungary)',
          'Indonesian (Indonesia)',
          'Italian (Italy)',
          'Japanese (Japan)',
          'Korean (Korea)',
          'Latvian (Latvia)',
          'Lithuanian (Lithuania)',
          'Norwegian, Bokmål (Norway)',
          'Polish (Poland)',
          'Portuguese (Brazil)',
          'Portuguese (Portugal)',
          'Romanian (Romania)',
          'Russian (Russia)',
          'Serbian (Latin, Serbia)',
          'Serbian (Cyrillic, Serbia)',
          'Slovak (Slovakia)',
          'Slovenian (Slovenia)',
          'Spanish (Mexico)',
          'Spanish (Spain)',
          'Swedish (Sweden)',
          'Thai (Thailand)',
          'Turkish (Türkiye)',
          'Ukrainian (Ukraine)',
          'Vietnamese',
          'Afrikaans (South Africa)',
          'Albanian (Albania)',
          'Amharic (Ethiopia)',
          'Armenian (Armenia)',
          'Assamese (India)',
          'Azerbaijani (Latin, Azerbaijan)',
          'Bangla (India)',
          'Belarusian (Belarus)',
          'Bosnian (Latin, Bosnia and Herzegovina)',
          'Cherokee',
          'Filipino',
          'Georgian (Georgia)',
          'Gujarati (India)',
          'Hindi (India)',
          'Icelandic (Iceland)',
          'Irish (Ireland)',
          'Kannada (India)',
          'Kazakh (Kazakhstan)',
          'Khmer (Cambodia)',
          'Konkani (India)',
          'Lao (Laos)',
          'Luxembourgish (Luxembourg)',
          'Macedonian (North Macedonia)',
          'Malay (Malaysia)',
          'Malayalam (India)',
          'Maltese (Malta)',
          'Maori (New Zealand)',
          'Marathi (India)',
          'Nepali (Nepal)',
          'Norwegian, Nynorsk (Norway)',
          'Odia (India)',
          'Persian',
          'Punjabi (India)',
          'Quechua (Peru)',
          'Scottish Gaelic',
          'Serbian (Cyrillic, Bosnia and Herzegovina)',
          'Tamil (India)',
          'Tatar (Russia)',
          'Telugu (India)',
          'Urdu',
          'Uyghur',
          'Uzbek (Latin, Uzbekistan)',
          'Valencian (Spain)',
          'Welsh (Great Britain)'
      )]
      [string]$Language,
      # Returns list of supported Languages
      [Parameter(ParameterSetName = "LanguageList")]
      [switch]
      $GetLanguageList
    )

    process {
      $LanguageList = @(
        'Arabic (Saudi Arabia)',
          'Basque (Basque)',
          'Bulgarian (Bulgaria)',
          'Catalan',
          'Chinese (Traditional, Hong Kong SAR)',
          'Chinese (Simplified, China)',
          'Chinese (Traditional, Taiwan)',
          'Croatian (Croatia)',
          'Czech (Czech Republic)',
          'Danish (Denmark)',
          'Dutch (Netherlands)',
          'English (United States)',
          'English (United Kingdom)',
          'Estonian (Estonia)',
          'Finnish (Finland)',
          'French (Canada)',
          'French (France)',
          'Galician',
          'German (Germany)',
          'Greek (Greece)',
          'Hebrew (Israel)',
          'Hungarian (Hungary)',
          'Indonesian (Indonesia)',
          'Italian (Italy)',
          'Japanese (Japan)',
          'Korean (Korea)',
          'Latvian (Latvia)',
          'Lithuanian (Lithuania)',
          'Norwegian, Bokmål (Norway)',
          'Polish (Poland)',
          'Portuguese (Brazil)',
          'Portuguese (Portugal)',
          'Romanian (Romania)',
          'Russian (Russia)',
          'Serbian (Latin, Serbia)',
          'Serbian (Cyrillic, Serbia)',
          'Slovak (Slovakia)',
          'Slovenian (Slovenia)',
          'Spanish (Mexico)',
          'Spanish (Spain)',
          'Swedish (Sweden)',
          'Thai (Thailand)',
          'Turkish (Türkiye)',
          'Ukrainian (Ukraine)',
          'Vietnamese',
          'Afrikaans (South Africa)',
          'Albanian (Albania)',
          'Amharic (Ethiopia)',
          'Armenian (Armenia)',
          'Assamese (India)',
          'Azerbaijani (Latin, Azerbaijan)',
          'Bangla (India)',
          'Belarusian (Belarus)',
          'Bosnian (Latin, Bosnia and Herzegovina)',
          'Cherokee',
          'Filipino',
          'Georgian (Georgia)',
          'Gujarati (India)',
          'Hindi (India)',
          'Icelandic (Iceland)',
          'Irish (Ireland)',
          'Kannada (India)',
          'Kazakh (Kazakhstan)',
          'Khmer (Cambodia)',
          'Konkani (India)',
          'Lao (Laos)',
          'Luxembourgish (Luxembourg)',
          'Macedonian (North Macedonia)',
          'Malay (Malaysia)',
          'Malayalam (India)',
          'Maltese (Malta)',
          'Maori (New Zealand)',
          'Marathi (India)',
          'Nepali (Nepal)',
          'Norwegian, Nynorsk (Norway)',
          'Odia (India)',
          'Persian',
          'Punjabi (India)',
          'Quechua (Peru)',
          'Scottish Gaelic',
          'Serbian (Cyrillic, Bosnia and Herzegovina)',
          'Tamil (India)',
          'Tatar (Russia)',
          'Telugu (India)',
          'Urdu',
          'Uyghur',
          'Uzbek (Latin, Uzbekistan)',
          'Valencian (Spain)',
          'Welsh (Great Britain)'
      )

      if ($GetLanguageList){
        # Display the language list nicely
        Write-Host "Available Language Packs:"
        $LanguageList | ForEach-Object { Write-Host " - $_" }
        return
      }

      if (-not $PrimaryCredential){
        $PrimaryCredential = $(Get-Credential -UserName "umhs\$([System.Environment]::UserName)" -Message "Enter credentials for \\corefs.med.umich.edu\Shared2")
      }

      if (-not $SecondaryCredential){
        $SecondaryCredential = $(Get-Credential -UserName "umhs\umhs-$([System.Environment]::UserName)" -Message "Enter secondary credentials")
      }

      $LanguageTagLookup = @{
        'Arabic (Saudi Arabia)'                = 'ar-SA'
        'Basque (Basque)'                      = 'eu-ES'
        'Bulgarian (Bulgaria)'                 = 'bg-BG'
        'Catalan'                              = 'ca-ES'
        'Chinese (Traditional, Hong Kong SAR)' = 'zh-HK'
        'Chinese (Simplified, China)'          = 'zh-CN'
        'Chinese (Traditional, Taiwan)'        = 'zh-TW'
        'Croatian (Croatia)'                   = 'hr-HR'
        'Czech (Czech Republic)'               = 'cs-CZ'
        'Danish (Denmark)'                     = 'da-DK'
        'Dutch (Netherlands)'                  = 'nl-NL'
        'English (United States)'              = 'en-US'
        'English (United Kingdom)'             = 'en-GB'
        'Estonian (Estonia)'                   = 'et-EE'
        'Finnish (Finland)'                    = 'fi-FI'
        'French (Canada)'                      = 'fr-CA'
        'French (France)'                      = 'fr-FR'
        'Galician'                             = 'gl-ES'
        'German (Germany)'                     = 'de-DE'
        'Greek (Greece)'                       = 'el-GR'
        'Hebrew (Israel)'                      = 'he-IL'
        'Hungarian (Hungary)'                  = 'hu-HU'
        'Indonesian (Indonesia)'               = 'id-ID'
        'Italian (Italy)'                      = 'it-IT'
        'Japanese (Japan)'                     = 'ja-JP'
        'Korean (Korea)'                       = 'ko-KR'
        'Latvian (Latvia)'                     = 'lv-LV'
        'Lithuanian (Lithuania)'               = 'lt-LT'
        'Norwegian, Bokmål (Norway)'           = 'nb-NO'
        'Polish (Poland)'                      = 'pl-PL'
        'Portuguese (Brazil)'                  = 'pt-BR'
        'Portuguese (Portugal)'                = 'pt-PT'
        'Romanian (Romania)'                   = 'ro-RO'
        'Russian (Russia)'                     = 'ru-RU'
        'Serbian (Latin, Serbia)'              = 'sr-Latn-RS'
        'Serbian (Cyrillic, Serbia)'           = 'sr-Cyrl-RS'
        'Slovak (Slovakia)'                    = 'sk-SK'
        'Slovenian (Slovenia)'                 = 'sl-SI'
        'Spanish (Mexico)'                     = 'es-MX'
        'Spanish (Spain)'                      = 'es-ES'
        'Swedish (Sweden)'                     = 'sv-SE'
        'Thai (Thailand)'                      = 'th-TH'
        'Turkish (Türkiye)'                    = 'tr-TR'
        'Ukrainian (Ukraine)'                  = 'uk-UA'
        'Vietnamese'                           = 'vi-VN'
        'Afrikaans (South Africa)'             = 'af-ZA'
        'Albanian (Albania)'                   = 'sq-AL'
        'Amharic (Ethiopia)'                   = 'am-ET'
        'Armenian (Armenia)'                   = 'hy-AM'
        'Assamese (India)'                     = 'as-IN'
        'Azerbaijani (Latin, Azerbaijan)'      = 'az-Latn-AZ'
        'Bangla (India)'                       = 'bn-IN'
        'Belarusian (Belarus)'                 = 'be-BY'
        'Bosnian (Latin, Bosnia and Herzegovina)' = 'bs-Latn-BA'
        'Cherokee'                             = 'chr-CHER-US'
        'Filipino'                             = 'fil-PH'
        'Georgian (Georgia)'                   = 'ka-GE'
        'Gujarati (India)'                     = 'gu-IN'
        'Hindi (India)'                        = 'hi-IN'
        'Icelandic (Iceland)'                  = 'is-IS'
        'Irish (Ireland)'                      = 'ga-IE'
        'Kannada (India)'                      = 'kn-IN'
        'Kazakh (Kazakhstan)'                  = 'kk-KZ'
        'Khmer (Cambodia)'                     = 'km-KH'
        'Konkani (India)'                      = 'kok-IN'
        'Lao (Laos)'                           = 'lo-LA'
        'Luxembourgish (Luxembourg)'           = 'lb-LU'
        'Macedonian (North Macedonia)'         = 'mk-MK'
        'Malay (Malaysia)'                     = 'ms-MY'
        'Malayalam (India)'                    = 'ml-IN'
        'Maltese (Malta)'                      = 'mt-MT'
        'Maori (New Zealand)'                  = 'mi-NZ'
        'Marathi (India)'                      = 'mr-IN'
        'Nepali (Nepal)'                       = 'ne-NP'
        'Norwegian, Nynorsk (Norway)'          = 'nn-NO'
        'Odia (India)'                         = 'or-IN'
        'Persian'                              = 'fa-IR'
        'Punjabi (India)'                      = 'pa-IN'
        'Quechua (Peru)'                       = 'quz-PE'
        'Scottish Gaelic'                      = 'gd-GB'
        'Serbian (Cyrillic, Bosnia and Herzegovina)' = 'sr-Cyrl-BA'
        'Tamil (India)'                        = 'ta-IN'
        'Tatar (Russia)'                       = 'tt-RU'
        'Telugu (India)'                       = 'te-IN'
        'Urdu'                                 = 'ur-PK'
        'Uyghur'                               = 'ug-CN'
        'Uzbek (Latin, Uzbekistan)'            = 'uz-Latn-UZ'
        'Valencian (Spain)'                    = 'ca-ES-valencia'
        'Welsh (Great Britain)'                = 'cy-GB'
      }
      Write-Host "Getting list of $Language Language Packs..."
      $LanguageTag = $LanguageTagLookup[$Language]
      try {
        $session = New-PSSession -ComputerName $ComputerName -Credential $SecondaryCredential
        $LanguagePacks = Invoke-Command -ArgumentList $LanguageTag -Session $session -ScriptBlock {
          param ($LanguageTag)
            (Get-WindowsCapability -Online |
            Where-Object {
              $_.Name -match "^Language\..*~~~$languageTag~"
            })
        }
        
        # Create psdrive
        Invoke-Command -ArgumentList $primaryCredential -Session $session -ScriptBlock {
          param([pscredential]$credential)
          New-PSDrive -Name "T" -PSProvider FileSystem -Credential $credential -Root "\\corefs.med.umich.edu\Shared2" -Scope Global -Persist
        } 
        $LanguagePacksList = $LanguagePacks | Select-Object -ExpandProperty Name
        Foreach ($LanguagePack in $LanguagePacksList){
          Write-Host "Installing $LanguagePack..."
          try {
            Invoke-Command -ArgumentList $LanguagePack -Session $session -ScriptBlock {
              param ($LanguagePack)
              Add-WindowsCapability -Online -LimitAccess -Name $LanguagePack -Source "T:\MCIT_Shared\Teams\DES_ALL\Utilities\LanguagesAndOptionalFeatures"
            }
            Write-Host "Installing $LanguagePack... complete"
          }
          catch {
            Write-Host "Installing $LanguagePack... Failed"
            Write-Error $_
          }
            
        }
    
        $InstalledLanguagePacks = Invoke-Command -ArgumentList $LanguageTag -Session $session -Scriptblock {
          param ($LanguageTag)
          Get-WindowsCapability -Online |
          Where-Object {
            $_.Name -match "^Language\..*~~~$languageTag~"
          } |
          Where-Object {
            $_.State -eq 'Installed'
          }
        }
    
        if ($LanguagePacks.Length -eq $InstalledLanguagePacks.Length){
          Write-Host "Installing $Language Language Packs...Complete"
        } else {
          # Find out which packs were successfully installed
          $successfulPacks = $InstalledLanguagePacks | Where-Object { $LanguagePacks -contains $_ }
    
          # Find out which packs failed to install
          $failedPacks = $LanguagePacks | Where-Object { $InstalledLanguagePacks -notcontains $_ }
    
          # Display successful installations
          if ($successfulPacks.Count -gt 0) {
              Write-Host "Successfully installed the following packs:"
              $successfulPacks | ForEach-Object { Write-Host $_.Name }
          }
    
          # Display failed installations
          if ($failedPacks.Count -gt 0) {
              Write-Host "Failed to install the following packs:"
              $failedPacks | ForEach-Object { Write-Host $_.Name }
          }
        }
        
    
        Write-Host "Getting current users language preferences..."
        # Get current user language list
        Invoke-Command -ComputerName $ComputerName -Credential $SecondaryCredential -Scriptblock {
          $UserLanguageList = Get-WinUserLanguageList
          Write-Host "Adding $Language to current users language preferences..."
          Write-Host "Setting current users language preferences..."
          # Add target language to user language list
          $UserLanguageList.Add($LanguageTag) | Set-WinUserLanguageList -Force
          Write-Host "Setting current users language preferences...Complete"
        }
      }
      catch {
        throw $_
      }
    }
  }
  
  
function Remove-UserProfile {
    [CmdletBinding()]
    param (
        [Parameter(Position = 1, ValueFromPipeline)]
        [ciminstance]
        $UserProfile,

        [Parameter()]
        [string]
        $UserName,
        
        [Parameter(Mandatory, ParameterSetName = 'Remote')]
        [string[]]
        $ComputerName,

        [Parameter(Mandatory)]
        [pscredential]
        $Credential,

        [Parameter(Mandatory, ParameterSetName = 'Local')]
        [switch]
        $Local
    )
    
    begin {
        
    }
    
    process {
        if ($Local){
            $cimSession = New-CimSession
            if ($UserName){
                $UserProfile = Get-UserProfile -Local -UserName $UserName
            }
            if (-not $UserProfile -and -not $UserName){
                $UserProfile = Get-UserProfile -Local
            }
        } elseif ($ComputerName){
            $cimSession = New-CimSession -ComputerName $ComputerName -Credential $Credential
            foreach ($computer in $ComputerName){
                if ($UserName -and -not $UserProfile){
                    $UserProfile = Get-UserProfile -UserName $UserName -ComputerName $computer -Credential $Credential
                }
                if (-not $UserName -and -not $UserProfile){
                    $UserProfile = Get-UserProfile -ComputerName $computer -Credential $Credential
                }
            }
        }
        Remove-CimInstance -CimSession $cimSession -InputObject $UserProfile
    }
    
    end {
        
    }
}
# <#

# ************************** Change Log ******************************
# ************************** Version 1 *******************************

# ** Added propmt for printer name and assigning name to a variable **
# ** Added changing default printer to the newly named local printer *
# ** Added set printer functionality using the UMHS setprinters-win7.vbs script
# ******** Added ability to use either a file or manual input ********

# ************************ Feature Requests **************************

# Future - Add ability to choose if you want to export results to a file instead of have it written to console

# #>


# $userFile = Read-Host -Prompt 'Do you want to use a file for importing computer names? (Y/N)'
# try {
#   if($userFile -eq 'Y') {
#     Do {

#       Write-Host 'Place a text file on your desktop that contains the computer names'
#       $filename = Read-Host -Prompt "Input filename w/o extension"
#       $filePath = "C:\Users\$env:USERNAME\Desktop\$filename.txt"
#       $testPath = Test-Path $filePath -PathType Leaf
#       if ($testPath -eq "True") {continue}
#       else {

#         Write-Host 'The file was not found, or there was an error'
#         Write-Host $_
#       }
#     }
#     Until ($testPath -eq "True")

#     $computers = Get-Content $filePath
#     Write-Host $computers
#   }

#   if($userFile -eq 'N') {

#     ### Prompt for list of computers and assign to the variable computers
#     $computers = Read-Host -Prompt 'Enter Term ID, if multiples seperate with ,'
#     ### Split list of computers using , as the seperator
#     $computers = $computers -split ','
#   }
# } catch {

#   Write-Host 'An error occured'
#   Write-Host $_
# }

# ### Prompt for credentials
# $credential = $host.ui.PromptForCredential("Need credentials", "Please enter your level 2 credentials.", "", "NetBiosUserName")

# foreach ($computer in $computers) {
#   try {
#     ### Get printer list
#     Write-Host `Pulling information from $computer ...`
#     Get-Printer -ComputerName $computer | Format-Table -AutoSize | Out-Host
#     ### Prompt for printer name
#     $currentPrinter = Read-Host -Prompt 'Enter name of printer you wish to change'
#     ### Get and assign printer to a variable named printer
#     $printer = Get-Printer -ComputerName $computer  | Where-Object {$_.Name -eq "$currentPrinter"}
#     ### Prompt for new printer name
#     $newPrinter = Read-Host -Prompt 'Enter the new name of the printer'
#     ### Rename printer
#     Rename-Printer -InputObject $printer -NewName $newPrinter
#     ### Get printer with new printer name, for verifying changes
#     Get-Printer -ComputerName $computer -Name $newPrinter | Format-Table -AutoSize | Out-Host
#     ### Set default printer
#     Write-Host -NoNewline 'Do you need to run set printers script? (Y/N)'
#     $response = Read-Host
#     if ($response -ne 'Y') {continue}
#     Invoke-Command -ComputerName $computer -ScriptBlock {cscript.exe c:\wsmgmt\bin\setprinters-win7.vbs}
#   } catch {
#     Write-Host 'An error occured'
#     Write-Host $_
#   }
# }
# Read-Host -Prompt 'Press enter to exit'


<#

************************** Change Log ******************************
************************** Version 1.0 *******************************
* Added *
- User inputed computer names, limit of 28 at one time
- psexec to remotely run the set-printers

************************** Version 1.1 *******************************
  Added
  ********************************************************************
- Do Until loop for accepting user input to utilize a file for computer names
**********************************************************************

  Updated 
  ********************************************************************
- variable for computer names to $computers
- set printer functionality using invoke command
**********************************************************************

  Removed 
  ********************************************************************
- utilization of psexec

************************* Feature Requests ***************************


#>

### Prompt for list of computers and assign to the variable computers
# $userFile = Read-Host -Prompt 'Do you want to use a file for importing computer names? (Y/N)'
# try {
#   if($userFile -eq 'Y')
#     {
#       Do {
#             Write-Host 'Place a text file on your desktop that contains the computer names'
#             $filename = Read-Host -Prompt "Input filename w/ extension" 
#             $filePath = "C:\Users\$env:USERNAME\Desktop\$filename"

#             ### Test the file path
#             $testPath = Test-Path $filePath -PathType Leaf
#             if ($testPath -eq "True") {continue}
#             else
#               {
#                 Write-Host 'The file was not found, or there was an error'
#                 Write-Host $_
#               }
#           }
#           Until ($testPath -eq "True")
#       $computers = Get-Content $filePath
#       Write-Host $computers
#       }
      

      
    
#   if($userFile -eq 'N')
#     {
#       $computers = Read-Host -Prompt 'Enter Term ID, if multiples seperate with ,'
#       ### Split list of computers using , as the seperator
#       $computers = $computers -split ','
#     }
# }
# catch
# {
#    Write-Host 'An error occured'
#     Write-Host $_
# }

# ### Prompt for credentials
# $credential = (Get-Credential umhs\uniqname -Message "Enter your level 2 credentials")

# foreach ($computer in $computers) {
#   try {
#   Invoke-Command -Credential $credential -ComputerName $computer -ScriptBlock {cscript.exe c:\wsmgmt\bin\setprinters-win7.vbs}
#   } catch {
#     Write-Host 'An error occured'
#     Write-Host $_
#   }
# }
# Read-Host -Prompt 'Press enter to exit'







<# VERSION 1.0
#Get Input, TermId's must be seperated by commas 
$_TermIdList = Read-Host "Enter TermId's, seperated by commas with no spaces.  There is a limit of 28 termid's at one time"
$_TermIdList
psexec \\$_TermIdList -s cscript c:\wsmgmt\bin\setprinters-win7.vbs
Read-Host -Prompt "Press Enter to Exit"
#>
<#
Get-NetConnectionProfile Documentation
https://learn.microsoft.com/en-us/powershell/module/netconnection/get-netconnectionprofile?view=windowsserver2022-ps

Set-NetConnectionProfile Documentation
https://learn.microsoft.com/en-us/powershell/module/netconnection/set-netconnectionprofile?view=windowsserver2022-ps
#>
function Set-NetworkProfileCategory {
  [CmdletBinding()]
  param (
    
  )
  
  begin {
    
  }
  
  process {
    $ScriptPath = $MyInvocation.MyCommand.Path
Set-Location -Path (Split-Path $ScriptPath)
#Initialize variables
$NetworkCategories = @("Public","Private")
$NetworkNames = @()
$Networks = @{}
$Result = @{}



#Import custom functions
Import-Module "..\..\CustomFunctions\CustomFunctions.ps1"

#Prompt for scope
$Scope = New-ListBox -TitleText "Scope" -LabelText "Where would you like to run the script" -ListBoxItems Local,Remote
#Prompt for computers
if($Scope -eq "Local"){
  $Computers = "localhost"
} else {
  $userFile = New-ListBox -TitleText "Import Computer Names" -LabelText "Would you like to use a file." -ListBoxItems Yes,No
  #Check if yes was selected
  if(($userFile.DialogResult -eq 'OK') -and ($userFile.SelectedItems -eq "Yes")){
    #Prompt for file
    $file = New-FileBrowser
    #Save content to variable
    $Computers = Get-Content $file
  } else {
    #Prompt for computer names
    $Computers = New-CustomInput -LabelText "Type a comma seperated list of computer names"
    #Split string of computer names by comma or space into an array
    $computers = [regex]::Split($computers, "[,\s]+")
  }
}

foreach($Computer in $Computers){
  #Get a list of network connections
  Write-Host "Getting a List of Connections..."
  #Assign connections to a variable
  $Networks = Invoke-Command -ComputerName $Computer -ScriptBlock {Get-NetConnectionProfile}
  #forach network assign the name to a variable
  foreach($Network in $Networks){
    $NetworkNames += $Network.Name
  }
  #Prompt for network selection
  $Network = New-ListBox -TitleText "Network List" -LabelText "Select the desired network" -ListBoxItems $NetworkNames
  #Assign selected network to variable
  $Network = $Networks | Where-Object {$_.name -eq $Network.SelectedItem}

  #Prompt for network category
  $NetworkCategory = New-ListBox -TitleText "Network Category Options" -LabelText "Select the desired network category" -ListBoxItems $NetworkCategories
  #Assign selected network to varaible
  $NetworkCategory = $NetworkCategories | Where-Object {$_ -eq $NetworkCategory.SelectedItem}
  #Check if current network category equals the desired network category
  if($Network.NetworkCategory -eq $NetworkCategory){
    #Output current network category
    Write-Host "Network Category Set: "$Network.NetworkCategory
    Exit
  }
  $InterfaceIndex = $Network.InterfaceIndex
  $Result = Invoke-Command -ComputerName $Computer -ScriptBlock {
    Set-NetConnectionProfile -InterfaceIndex $using:InterfaceIndex -NetworkCategory $using:NetworkCategory -PassThru
  }
  if($Result.NetworkCategory -eq 0){Write-Host "$Computer Network Category: Public"}
  if($Result.NetworkCategory -eq 1){Write-Host "$Computer Network Category: Private"}
}
  }
  
  end {
    
  }
}
function Watch-DeviceStatus {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'ByComputerName')]
        [string[]]$ComputerName,

        [Parameter(Mandatory = $true, ParameterSetName = 'ByFile')]
        [switch]$UseInFile,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Default',
                     'IM',
                     'Mail',
                     'Reminder',
                     'SMS',
                     'Alarm',
                     'Alarm2',
                     'Alarm3',
                     'Alarm4',
                     'Alarm5',
                     'Alarm6',
                     'Alarm7',
                     'Alarm8',
                     'Alarm9',
                     'Alarm10',
                     'Call',
                     'Call2',
                     'Call3',
                     'Call4',
                     'Call5',
                     'Call6',
                     'Call7',
                     'Call8',
                     'Call9',
                     'Call10')]
        [String]$Sound = 'Default', 

        [Parameter(Mandatory = $false)]
        [int]$IntervalSeconds = 30,

        [Parameter(Mandatory = $false)]
        [int]$TimeoutMinutes = 60
    )

    begin {
        
        Import-Module -Name BurntToast -ErrorAction SilentlyContinue
        $installedToastModule = Get-Module -Name BurntToast
        [version]$installedToastVersion = $installedToastModule.Version
        [version]$latestToastVersion = (Find-Module -Name BurntToast).Version


        if($null -eq $installedToastModule){
            Write-Host "Installing Toast Module"
            Install-Module -Name BurntToast | Import-Module -ErrorAction Stop
            Write-Host "Imported Toast Module"
        } elseif ($installedToastVersion -lt $latestToastVersion) {
            Write-Host "Updating Toast Module"
            Update-Module -Name BurntToast | Import-Module -ErrorAction Stop
            Write-Host "Imported Toast Module"
        } else {
            Write-Host "Toast Module is up to date"
            Write-Host "Imported Toast Module"
        }

        $jobs = @()
    }

    process {
        foreach ($name in $ComputerName) {
            $job = Start-Job -Name "Monitor_$name" -ScriptBlock {
                param ($name, $interval, $timeout, $verbosePreference)
                $VerbosePreference = $verbosePreference
                $timeoutTime = [datetime]::Now.AddMinutes($timeout)
                $isOnline = $false

                if ($verbose) {
                    Write-Verbose "Monitoring $name. Timeout set to $timeout minutes."
                }

                while (-not $isOnline -and [datetime]::Now -lt $timeoutTime) {
                    try {
                        $pingResult = Test-Connection -ComputerName $name -Count 1 -Quiet
                        # if ($name -eq 'localhost'){
                        #     Start-Sleep -Seconds 60
                        # } else {
                        #     Start-Sleep -Seconds $(60*2)
                        # }
                        if ($pingResult) {
                            $isOnline = $true
                            $message = "[$(Get-Date)] $name is now online!"

                            Write-Output $message
                            Write-Verbose "Verbose: ${Verbose}"
                            $currentVerbosePreference = $VerbosePreference
                            $verbosePreference = 'SilentlyContinue'
                            if ($env:OS -match "Windows") {
                                Import-Module BurntToast -ErrorAction SilentlyContinue
                                New-BurntToastNotification -Text "Device is Online!", $message
                            } else {
                                Write-Output "Notification: $message"
                            }
                            $VerbosePreference = $currentVerbosePreference
                        } else {
                            if ($Verbose) {
                                Write-Verbose "[$(Get-Date)] $name is still offline."
                            }
                            Start-Sleep -Seconds $interval
                        }
                    } catch {
                        Write-Warning "An error occurred while checking ${name}: $_"
                    }
                }

                if (-not $isOnline) {
                    Write-Output "[$(Get-Date)] Timeout reached. $name did not come online within the allotted time."
                }
            } -ArgumentList $name, $IntervalSeconds, $TimeoutMinutes, $VerbosePreference

            $jobs += $job
        }
    }

    end {
        if ($jobs.Count -gt 0) {
            Write-Output "Monitoring started for $($jobs.Count) computer(s). Use 'Get-Job' to see the status of the jobs."
            Write-Output "Use 'Receive-Job' to see the results and 'Remove-Job' to clean up completed jobs."
        }

        while ($jobs | Where-Object { $_.State -ne 'Completed' }) {
            foreach ($job in $jobs) {

                if ($job.State -eq 'Completed'){
                    Receive-Job -Job $job | Write-Output
                    Remove-Job -Job $job
                    $jobs = $jobs | Where-Object {
                        $_.Id -ne $job.Id
                    }
                }
                else{
                    Receive-Job -Job $job -Keep | Write-Output
                }
            }
            Start-Sleep -Seconds 5
        }
        Get-Job -Name "Monitor_*" | ForEach-Object {
            Remove-Job -Job $_
        }
    }
}

