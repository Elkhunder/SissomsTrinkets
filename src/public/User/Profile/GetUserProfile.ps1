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