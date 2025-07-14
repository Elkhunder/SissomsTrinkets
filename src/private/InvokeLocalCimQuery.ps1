function Invoke-LocalCimQuery{
    param (
        [Parameter(Mandatory, ParameterSetName = 'Local')]
        [Parameter(Mandatory, ParameterSetName = 'Remote')]
        [String[]]
        $ClassName,

        # Could be better to pass in a single computername 
        [Parameter(Mandatory, ParameterSetName = 'Remote')]
        [String[]]
        $ComputerName,

        [Parameter(Mandatory, ParameterSetName = 'Remote')]
        [pscredential]
        $Credential,

        [Parameter(Mandatory, ParameterSetName = 'Local')]
        [switch]
        $Local
    )
    begin{
        $CimInstances = @()
    }
    
    process{
        if ($Local){
            foreach ($Class in $ClassName){
                $CimInstances += Get-CimInstance -ClassName $Class
            }
        } else {
            foreach ($Computer in $ComputerName){
                $CimSession = New-CimSession -ComputerName $Computer -Credential $Credential
                $DeviceCimInstances = @()
                foreach ($Class in $ClassName){
                    $DeviceCimInstances += Get-CimInstance -CimSession $CimSession -ClassName $Class
                }
                $CimInstances += $DeviceCimInstances
                Remove-CimSession -CimSession $CimSession
            }
        }
    }

    end{
        return $CimInstances
    }
}