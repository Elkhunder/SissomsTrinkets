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