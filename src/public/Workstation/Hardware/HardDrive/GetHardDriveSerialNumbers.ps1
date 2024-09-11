function Get-HardDriverSerialNumbers {
    [CmdletBinding()]
    param (
        
    )
    
    begin {
        
    }
    
    process {
        Write-Host 'Enter Term ID, if multiples seperate with ,' -NoNewLine
        $computers = Read-Host ' '
        $computers = $computers -split ','

        foreach ($computer in $computers)
        {
        Write-Host `Testing connection to $computer`
        $testConnection = Test-Connection -Quiet $computer

        if ($testConnection)
        {
        try
            {
            Write-Host `Querying $computer for hardware information...`
            Start-Sleep -s 3
            $hardware = Get-CimInstance -OperationTimeoutSec 10 -ComputerName $computer -ClassName Win32_DiskDrive | Select-Object Model,SerialNumber
            Write-Host 'Writing hardware information to console...'
            Start-Sleep -s 3
            $hardware | Format-Table | Out-String | Write-Host
            }
        catch
            {
            Write-Host 'An error occurred:'
            Write-Host $_
            }
        }
        else
        {
        Write-Host `*** $computer is offline ***`
        }
        }
        Read-Host 'Press enter to exit'
    }
    
    end {
        
    }
}