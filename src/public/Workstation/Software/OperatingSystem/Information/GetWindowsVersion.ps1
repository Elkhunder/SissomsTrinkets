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