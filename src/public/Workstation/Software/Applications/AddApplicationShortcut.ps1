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
    $Credential

  )
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
          $applicationName = $obj.GetValue('DisplayName')
          if([string]::IsNullOrEmpty($applicationName)){continue}
          $SoftwareList += $applicationName
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