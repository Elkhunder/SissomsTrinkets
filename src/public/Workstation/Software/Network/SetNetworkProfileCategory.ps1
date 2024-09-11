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