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

