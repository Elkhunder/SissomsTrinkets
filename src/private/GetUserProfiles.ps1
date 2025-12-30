function GetUserProfiles {
    [CmdletBinding()]
    param(
        [string]$ComputerName = $env:COMPUTERNAME
    )

    begin {
        Write-Verbose "[$([DateTime]::Now.ToString('HH:mm:ss'))] Begin block started"
    }
    process {
        Write-Verbose "[$([DateTime]::Now.ToString('HH:mm:ss'))] Process block started"
        Write-Verbose "  ComputerName: $ComputerName"

        function GetUserProfilePaths {
            param([string] $Computer)

            if (IsLocal -Name $Computer) {
                Write-Verbose "    Retrieving local user profiles"
                $profiles = Get-CimInstance -ClassName Win32_UserProfile | Where-Object { -not $_.Special } | Select-Object -ExpandProperty LocalPath
            }
            else {
                Write-Verbose "    Retrieving user profiles from remote computer: $Computer"
                $profiles = Invoke-Command -ComputerName $Computer -ScriptBlock {
                    Get-CimInstance -ClassName Win32_UserProfile | Where-Object { -not $_.Special } | Select-Object -ExpandProperty LocalPath
                }
            }

            return $profiles
        }

        $userProfiles = GetUserProfilePaths -Computer $ComputerName
        Write-Output $userProfiles
    }
    end {
        Write-Verbose "[$([DateTime]::Now.ToString('HH:mm:ss'))] End block completed"
    }
}