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