function Add-ApplicationShortcut{
    $ScriptPath = $MyInvocation.MyCommand.Path
    Set-Location -Path (Split-Path $ScriptPath)
    $FunctionPath = "..\..\CustomFunctions\CustomFunctions.ps1"
    #Import custom functions
    Import-Module $FunctionPath
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
    foreach($computer in $Computers){
      $s = New-PSSession -ComputerName localhost
      Invoke-Command -Session $s -FilePath $FunctionPath
      $SoftwareList = Invoke-Command -Session $s -ScriptBlock {
        $SoftwareList = @()
        $InstalledSoftware = Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
        foreach($obj in $InstalledSoftware){
          $SoftwareList += $obj.GetValue('DisplayName')
        }
        Return $SoftwareList = $SoftwareList | Where-Object {$_ }
      }
  
        $TargetSoftware = New-ListBox -TitleText "Software List" -LabelText "Select desired software" -ListBoxItems $SoftwareList
  
        $TargetFiles = Invoke-Command -Session $s -ScriptBlock{
          $ProgramName = (Get-ChildItem -Path $Env:ProgramFiles | Where-Object {$using:TargetSoftware -like "*$($_.Name)*"}).Name
          $ProgramName
          $ProgramDirectory = "C:\Program Files\$ProgramName"
          $ProgramDirectory
          Return Get-ChildItem -Recurse -Path $ProgramDirectory
        }
        $TargetFile = New-ListBox -TitleText "File List" -LabelText "Select desired file" -ListBoxItems $TargetFiles.Name
        $TargetFile = ($TargetFiles | Where-Object {$_.Name -eq $TargetFile}).FullName
        Invoke-Command -Session $s -ScriptBlock {
          $TargetDirectory = (Split-Path -Path $using:TargetFile)
          $TargetDirectory
          $WScriptShell = New-Object -ComObject WScript.Shell
          $PublicDesktop = $WScriptShell.SpecialFolders("AllUsersDesktop")
          $Shortcut = $WScriptShell.CreateShortcut($PublicDesktop + "\$ProgramName.lnk")
          $Shortcut.WindowStyle = 1
          $Shortcut.TargetPath = $using:TargetFile
          $Shortcut.WorkingDirectory = $TargetDirectory
          $Shortcut.IconLocation = $using:TargetFile
          $Shortcut.Save()
        }
  
      }
  
    $InstalledSoftware = Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
    $InstalledSoftware = Get-ChildItem "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
    foreach($obj in $InstalledSoftware){write-host $obj.GetValue('DisplayName')}
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

        [Parameter(Mandatory = $true, ParameterSetName = 'ByOutFile')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Proxy')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Wait')]       
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
        [Int]$Port = 22
        # End Proxy Parameters
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
        if ($Local){
            Write-Verbose "Initiating local query"
            Invoke-LocalCimQuery -WinVersionMap $WinVersionMap -MacVersionMap $MacVersionMap
            return
        }
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
                        $DeviceInfoList | Out-File -FilePath $OutFile
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
        if ($OutFile){
            $DeviceInfoList | Out-File -FilePath $OutFile
        }
        if ($ProxySession){
            Remove-PSSession -Session $ProxySession
        }
        return $DeviceInfoList
    }
}
function Install-LanguagePacks {
    param (
      [Parameter(Mandatory = $true)]
      [string]
      $ComputerName,
      [Parameter(Mandatory = $false)]
      [pscredential]
      $Credential,
  
      [Parameter(Mandatory = $true)]
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
      [string]$Language
    )
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
    if ($null -eq $Credential){
      $Credential = $(Get-Credential -UserName "umhs\umhs-$([System.Environment]::UserName)")
    }
    Write-Host "Getting list of $Language Language Packs..."
    $LanguageTag = $LanguageTagLookup[$Language]
    try {
      $LanguagePacks = Invoke-Command -ArgumentList $LanguageTag -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
        param ($LanguageTag)
          (Get-WindowsCapability -Online |
          Where-Object {
            $_.Name -match "^Language\..*~~~$languageTag~"
          })
      }
      $LanguagePacksList = $LanguagePacks | Select-Object -ExpandProperty Name
      Foreach ($LanguagePack in $LanguagePacksList){
        Write-Host "Installing $LanguagePack..."
        try {
          #Copy necessary files to computers temp directory, will be needed if device is not localhost
          $CabFiles = "$PSScriptRoot/LanguagesAndOptionalFeatures"
          Invoke-Command -ArgumentList $CabFiles, $LanguagePack -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
            param ($LanguagePack, $CabFiles)
            Add-WindowsCapability -Online -LimitAccess -Name $LanguagePack -Source $CabFiles
          }
          Write-Host "Installing $LanguagePack... complete"
        }
        catch {
          Write-Host "Installing $LanguagePack... Failed"
          Write-Error $_
        }
          
      }
  
      $InstalledLanguagePacks = Invoke-Command -ArgumentList $LanguageTag -ComputerName $ComputerName -Credential $Credential -Scriptblock {
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
      Invoke-Command -ComputerName $ComputerName -Credential $Credential -Scriptblock {
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
function Invoke-LocalCimQuery{
    param (
        [hashtable]$WinVersionMap = $null,
        [hashtable]$MacVersionMap = $null
    )
    if ($IsWindows){
        $Win32_OperatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem
        $DeviceInfo = [PSCustomObject]@{
            'Computer' = $(Get-CimInstance -ClassName Win32_ComputerSystem).Name
            'OS Name' = $Win32_OperatingSystem.Caption
            'OS Version' = $WinVersionMap[$Win32_OperatingSystem.BuildNumber]
        }
        return $DeviceInfo
    }
    if ($IsMacOS){
        $OperatingSystem = system_profiler SPSoftwareDataType
        $OperatingSystemVersion = $($OperatingSystem | 
                                    Where-Object {$_.Contains('System Version')}).Split(':').Split(' ') | 
                                    Where-Object {$_.Contains('.')}
        
        $DeviceInfo = [PSCustomObject]@{
            'Computer' = $(scutil --get LocalHostName)
            'OS Name' = $MacVersionMap[$OperatingSystemVersion.Split('.')[0]]
            'OS Version' = $OperatingSystemVersion
        }
        return $DeviceInfo
    }
    
}
function New-CustomInput{
    <#
      .SYNOPSIS
      Creates Input Text Box
  
      .DESCRIPTION
      -Creates input text box for getting user input
      .PARAMETER LabelText
      The text box label
      .PARAMETER AsSecureString
      Text as a secure string
      .PARAMETER AsEncryptedString
      Text as an encrypted string
      .NOTES
      Function Returns
      -Default
        Inputed Text
      -AsSecureString
        Returns inputed text as secure string
      -AsEncryptedString
        Returns encryption key and inputed text encrpted string file paths
    #>
    [cmdletbinding(DefaultParameterSetName="plain")]
    [OutputType([system.string],ParameterSetName='plain')]
    [OutputType([system.security.securestring],ParameterSetName='secure')]
  
    Param(
      [Parameter(ParameterSetName = "secure")]
      [Parameter(ParameterSetName = "encrypted")]
      [Parameter(HelpMessage = "Enter the title for the input box.",
      ParameterSetName="plain")]
  
      [ValidateNotNullOrEmpty()]
      [string[]]$LabelText = "Input Text",
  
      [Parameter(HelpMessage = "Use to mask the entry and return a secure string.",
      ParameterSetName = "secure")]
      [switch]$AsSecureString,
  
      [Parameter(HelpMessage = "Use to mask the entry and return an encrypted string.",
      ParameterSetName = "encrypted")]
      [switch]$AsEncryptedString
    )
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
  
    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'Data Entry Form'
    $form.Size = New-Object System.Drawing.Size(300,200)
    $form.StartPosition = 'CenterScreen'
  
    $okButton = New-Object System.Windows.Forms.Button
    $okButton.Location = New-Object System.Drawing.Point(75,120)
    $okButton.Size = New-Object System.Drawing.Size(75,23)
    $okButton.Text = 'OK'
    $okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $form.AcceptButton = $okButton
    $form.Controls.Add($okButton)
  
    $cancelButton = New-Object System.Windows.Forms.Button
    $cancelButton.Location = New-Object System.Drawing.Point(150,120)
    $cancelButton.Size = New-Object System.Drawing.Size(75,23)
    $cancelButton.Text = 'Cancel'
    $cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $form.CancelButton = $cancelButton
    $form.Controls.Add($cancelButton)
  
    $label = New-Object System.Windows.Forms.Label
    $label.Location = New-Object System.Drawing.Point(10,20)
    $label.Size = New-Object System.Drawing.Size(280,20)
    $label.Text = $LabelText
    $form.Controls.Add($label)
  
    if ($AsSecureString -or $AsEncryptedString){
      $textBox = New-Object System.Windows.Forms.MaskedTextBox
      $textBox.PasswordChar = '*'
    } else {
      $textBox = New-Object System.Windows.Forms.TextBox
    }
    $textBox.Location = New-Object System.Drawing.Point(10,40)
    $textBox.Size = New-Object System.Drawing.Size(260,20)
    $form.Controls.Add($textBox)
  
    $form.Topmost = $true
  
    $form.Add_Shown({$textBox.Select()})
    $result = $form.ShowDialog()
    $text = $textBox.Text
    if($result -eq [System.Windows.Forms.DialogResult]::Cancel){
      Write-Host "Cancel was selected, exiting program."
      Start-Sleep -Seconds 3
      exit
    }
  
    if($result -eq [System.Windows.Forms.DialogResult]::OK -and $AsSecureString){
      return ConvertTo-SecureString $text -AsPlainText -Force
    }
    if($result -eq [System.Windows.Forms.DialogResult]::OK -and $AsEncryptedString){
      # New-EncryptionKey -Path "~\encryption.key"
      $EncryptionKey = New-EncryptionKey
      $EncryptedString = ConvertTo-SecureString $text -AsPlainText -Force |
        ConvertFrom-SecureString -Key $EncryptionKey
          # | Out-File -FilePath "~\encryptedstring.encrypted"
      # $EncryptionKey = "~\encryption.key"
      # $EncryptedString = "~\encryptedstring.encrypted"
      Return @{
        EncryptionKey = $EncryptionKey;
        EncryptedString = $EncryptedString
      }
    }
    return $text
  }
function New-ElevatedPrompt{
    <#
      .SYNOPSIS
      Elevates Script in New Powershell Session
  
      .DESCRIPTION
      -Checks to see if script is already running in an elevated session
      -Launches new elevated powershell session and calls script
      .PARAMETER Path
      The path of the script file
  
      .PARAMETER Credentials
      Provided credentials, not currently utilizing
    #>
    param(
      [Parameter(HelpMessage = "The Path For the Current Script File")]
      [string]$ScriptPath,
      [Parameter(HelpMessage = "The Path of Functions to import")]
      [string]$FunctionPath
    )
    #Check if current powershell session is running elevated
    if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
    Write-Host "Prompt is not Elevated, Elevating Prompt.  Enter your secondary credentials in the UAC prompt"
    if ([int](Get-CimInstance -Class Win32_OperatingSystem | Select-Object -ExpandProperty BuildNumber) -ge 6000) {
      $ScriptBlock = {
        <#
        Gets username of the currently logged on user not the one that is running the script.
        This is done to return the primary level-2 account of the currently logged in user,
        as at this point the script will be running with their secondary level-2 account
        #>
        $UserName = (Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object username).username
        # #Get primary level-2 account credentials
        $Credential = Get-Credential -UserName $UserName -Message "'Provide your Level-2 credentials.'"
        <#
        Map share drive with the provided primary level-2 credentials.
        Without this the script won't have access to the share path when the script launches
        #>
        New-PSDrive -Name 'T' -PSProvider 'FileSystem' -Root '\\corefs.med.umich.edu\shared2' -Credential $Credential | Out-Null
      }
      #Specify command line arguments
      $CommandLine = "-NoExit", "-Command $ScriptBlock"
      <#
      Start new elevated powershell process with command line arguments and the script path passed in as arguments
      Im not 100% sure why this works and calls the script?
      Potentially after the command line arguments are called it passes in the full script path which calls then executes the script
      #>
      Start-Process -FilePath PowerShell.exe -Verb Runas -ArgumentList "$CommandLine", "$ScriptPath"
      #Exit current unelevated powershell session
      Exit
    }
  }
}
function New-EncryptionKey{
    <#
      .SYNOPSIS
      Creates new encryption key
  
      .DESCRIPTION
      Creates new encryption key to be passed to the Convert-FromSecureString commandlet
  
      .PARAMETER Path
      The path where the key file is saved
  
      .EXAMPLE
      New-EncryptionKey -Path "~\encryption.key"
    #>
    param(
      [string]$Path
    )
    #Initialize a 32 bit byte array
    $EncryptionKey = New-Object Byte[] 32
    #Create encryption key
    [Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($EncryptionKey)
    #Save encryption key to provided file path
    if($Path){
      $EncryptionKey | Out-File $Path
    } else {
      return $EncryptionKey
    }
  }
function New-FileBrowser{
    <#
      .SYNOPSIS
      Creates New File Browser Window
  
      .DESCRIPTION
      -Prompts with file browser window to get content from a file input
      .PARAMETER InitialDirectory
      The path that opens when the browser window opens, default is current users desktop
      .PARAMETER Filter
      File filter to display only certain types of files, default is text and csv
  
      .EXAMPLE
      New-FileBrowser -InitialDirectory "Documents" -Filter 'CSV Files (*.csv)|*.csv'
    #>
    param (
    [string[]]$InitialDirectory = 'Desktop',
    [string[]]$Filter = 'TXT Files (*.txt)|*.txt|CSV Files (*.csv)|*.csv',
    [string]$Title = 'Select target file',
    [switch]$CheckFileExists,
    [switch]$CheckPathExists,
    [switch]$OkRequiresInteraction,
    [switch]$ShowPinnedPlaces
    )
  
    Add-Type -AssemblyName System.Windows.Forms
    $FileBrowser = New-Object System.Windows.Forms.OpenFileDialog -Property @{
      InitialDirectory = [Environment]::GetFolderPath($InitialDirectory)
      Filter = $Filter
      Title = $Title
      CheckFileExists = $CheckFileExists
      CheckPathExists = $CheckPathExists
      OkRequiresInteraction = $OkRequiresInteraction
      ShowPinnedPlaces = $ShowPinnedPlaces
    }
    $result = $FileBrowser.ShowDialog(
      (New-Object System.Windows.Forms.Form -Property @{TopMost = $true; TopLevel = $true})
    )
  
    if($result -eq [System.Windows.Forms.DialogResult]::Cancel){
      Write-Host "Cancel was selected, exiting program."
      Start-Sleep -Seconds 3
      exit
    }
    return $FileBrowser.FileName
  }
function New-ListBox{
    <#
      .SYNOPSIS
      Creates List Box
  
      .DESCRIPTION
      -Creates list box for getting user selected data
      .PARAMETER TitleText
      The title of the list box
  
      .PARAMETER LabelText
      The description message for the list box
  
      .PARAMETER ListBoxItems
      The items to put in the list box to be selected
  
      .EXAMPLE
      New-ListBox -TitleText "Scope" -LabelText "Where would you like to run the script" -ListBoxItems Local,Remote
    #>
    Param(
      [string[]]$TitleText,
      [string[]]$LabelText,
      [string[]]$ListBoxItems
    )
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
  
    $form = New-Object System.Windows.Forms.Form
    $form.Text = $TitleText
    $form.Size = New-Object System.Drawing.Size(300,200)
    $form.StartPosition = 'CenterScreen'
  
    $okButton = New-Object System.Windows.Forms.Button
    $okButton.Location = New-Object System.Drawing.Point(75,120)
    $okButton.Size = New-Object System.Drawing.Size(75,23)
    $okButton.Text = 'Ok'
    $okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $form.AcceptButton = $okButton
    $form.Controls.Add($okButton)
  
    $cancelButton = New-Object System.Windows.Forms.Button
    $cancelButton.Location = New-Object System.Drawing.Point(150,120)
    $cancelButton.Size = New-Object System.Drawing.Size(75,23)
    $cancelButton.Text = 'Cancel'
    $cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $form.CancelButton = $cancelButton
    $form.Controls.Add($cancelButton)
  
    $label = New-Object System.Windows.Forms.Label
    $label.Location = New-Object System.Drawing.Point(10,20)
    $label.Size = New-Object System.Drawing.Size(280,20)
    $label.Text = $LabelText
    $form.Controls.Add($label)
  
    $listBox = New-Object System.Windows.Forms.ListBox
    $listBox.Location = New-Object System.Drawing.Point(10,40)
    $listBox.Size = New-Object System.Drawing.Size(260,20)
    $listBox.Height = 80
  
    foreach ($ListboxItem in $ListBoxItems) {
      [void] $listBox.Items.Add($ListboxItem)
    }
  
    $form.Controls.Add($listBox)
  
    $form.Topmost = $true
    $result = $form.ShowDialog()
  
    if($result -eq [System.Windows.Forms.DialogResult]::Cancel){
      Write-Host "Cancel was selected, exiting program."
      Start-Sleep -Seconds 3
      exit
    }
  
    return $listBox.SelectedItem
  }
function Update-Dependencies{
    <#
      .SYNOPSIS
      Installs Script Dependencies.
  
      .DESCRIPTION
      Installs or sets the following script dependencies:
        Sets the Execution Policy
        Sets Repository Installation Policy
        Installs/Updates Package Providers
        Installs Modules
        Imports Installed Modules
      Depencies will only be installed if the necessary params are provided
  
      .PARAMETER ExecutionPolicy
      Specifies the execution policy value
  
      .PARAMETER RepositoryName
      Specifies the repository name to set the installation policy for
  
      .PARAMETER RepositoryPolicy
      Specifies the installation policy for the Repository
  
      .PARAMETER ModuleNames
      Specifies the module names to be verified and installed
  
      .PARAMETER PackageProviders
      Specifies the package providers to install or update
    #>
  
    param(
      [string]$ExecutionPolicy,
      [string]$RepositoryName,
      [string]$RepositoryPolicy,
      [string[]]$ModuleNames,
      [string[]]$PackageProviders,
      [switch]$Verbose
    )
    #Check if package provider parameter was provided
    if($PackageProviders){
      $_nugetUrl = "https://api.nuget.org/v3/index.json"
      $packageSources = Get-PackageSource
      if(@($packageSources).Where{$_.location -eq $_nugetUrl}.count -eq 0){
        Register-PackageSource -Name MyNuGet -Location $_nugetUrl -ProviderName NuGet -Force
      }
      # if(!(Get-PackageProvider -Name))
      foreach($PackageProvider in $PackageProviders){
        #Get locally installed provider version
        if($Verbose){
          Write-Host "Package Provider: $PackageProvider"
          Write-Host "Getting locally installed version ..."
        }
        $LocalVersion = Get-PackageProvider -Name $PackageProvider -Force -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Version
        if($Verbose){
          Write-Host "Locally installed version: $LocalVersion ..."
        }
        #Get most recent version from repository
        if($Verbose){
          Write-Host "Getting version from repository..."
        }
        $RepositoryVersion = Find-PackageProvider -Name $PackageProvider -Force | Select-Object -ExpandProperty Version
        if($Verbose){
          Write-Host "Repository version: $RepositoryVersion ..."
        }
        #Check if local version is less than repository version
        if($LocalVersion -lt $RepositoryVersion){
          #Install package provider from repository and save the version to a variable
          if($Verbose){
            Write-Host "Installing package provider version: $RepositoryVersion ..."
          }
          $InstallationVersion = Install-PackageProvider -Name $PackageProvider -Force
          $InstallationVersion
          $InstallationVersion = $InstallationVersion | Select-Object -ExpandProperty Version
          #Display the package provider version that was installed
          if($Verbose){
            Write-Host "$PackageProvider updated to version: $InstallationVersion ..."
            Write-Host "Importing new version ..."
          }
          #Import newly installed package provider and save version to a variable
          $ImportVersion = Import-PackageProvider -Name $PackageProvider -RequiredVersion $RepositoryVersion -Force
          # | Select-Object -ExpandProperty Version
          #Display the package provider version that was imported
          if($Verbose){
            Write-Host "$PackageProvider Version: $ImportVersion imported successfully ..."
          }
        } else {
          #Display installed version
          if($Verbose){
            Write-Host "$PackageProvider Version: $LocalVersion ..."
          }
        }
      }
    }
    #Check if execution policy parameter was provided
    if($ExecutionPolicy){
      # Check if the Execution Policy is alread set to the specified policy
      if((Get-ExecutionPolicy) -ne $ExecutionPolicy){
        #Set execution policy to specified policy
        Set-ExecutionPolicy $ExecutionPolicy -Force -Scope Process
        Write-Host "Execution Policy: $ExecutionPolicy..."
      } else {
        Write-Host "Execution Policy: $ExecutionPolicy ..."
      }
    }
  
    # Check if repository name parameter was provided
    if($RepositoryName){
      # Check if the repository policy is already set to the specified policy
      if((Get-PSRepository -Name $RepositoryName).InstallationPolicy -ne $RepositoryPolicy){
        #Set repository installation policy to the specified policy
        Set-PSRepository -Name $RepositoryName -InstallationPolicy $RepositoryPolicy
        Write-Host "$RepositoryName Installation Policy: $RepositoryPolicy..."
      } else {
        Write-Host "$RepositoryName Installation Policy: $RepositoryPolicy ..."
      }
    }
  
    #Check if Module Name parameter was provided
    if($ModuleNames){
      foreach($ModuleName in $ModuleNames){
        #Check if specified module is already installed
        if(Get-InstalledModule -Name $ModuleName -ErrorAction SilentlyContinue){
          Write-Host "Module Installed: $ModuleName..."
        } else {
          #Install the specified module
          Install-Module -Name $ModuleName -Scope CurrentUser -AcceptLicense
          Write-Host "Module Installed: $ModuleName..."
        }
        # Check if the specified module is already imported
        if(Get-Module -Name $ModuleName){
          Write-Host "Module Imported: $ModuleName..."
        } else {
          #Import the specified module
          Import-Module $ModuleName
          Write-Host "Module Imported: $ModuleName..."
        }
      }
    }
  }

