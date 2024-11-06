function Get-CCMUpdateStatus {
    [CmdletBinding()]
    param (
        # Parameter help description
        [Parameter(Mandatory)]
        [string[]]
        $ComputerName,
        # Secondary Credentials
        [Parameter(Mandatory)]
        [pscredential]
        $Credential
    )
    
    begin {
        
    }
    
    process {
        foreach ($Computer in $ComputerName) {
            $cimSession = New-CimSession -ComputerName $Computer -Credential $Credential
            $ccmUpdates = Get-CimInstance -Namespace root/ccm/SoftwareUpdates/UpdatesStore -ClassName CCM_UpdateStatus -CimSession $cimSession
            $missingCcmUpdates = $ccmUpdates | Where-Object {$_.Status -eq "Missing"}
        }
        
    }
    
    end {
        $missingCcmUpdates
    }
}