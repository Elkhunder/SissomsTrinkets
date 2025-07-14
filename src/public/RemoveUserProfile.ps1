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