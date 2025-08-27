function Get-DellCommand {
    [CmdletBinding(DefaultParameterSetName = 'Local')]
    param(
        [Parameter(Mandatory, ParameterSetName = "ComputerName")]
        [string[]]$ComputerName,
        
        [Parameter(Mandatory, ParameterSetName = "ComputerName")]
        [pscredential]$Credential,

        [Parameter(Mandatory, ParameterSetName = "PSSession")]
        [System.Management.Automation.Runspaces.PSSession[]]$PSSession
    )

    $dellCommandPaths = @(
        "C:\Program Files (x86)\Dell\CommandUpdate\dcu-cli.exe",
        "C:\Program Files\Dell\CommandUpdate\dcu-cli.exe"
    )

    $checkScript = {
        param($paths)
        foreach ($path in $paths) {
            if (Test-Path $path) { return $true }
        }
        return $false
    }

    $results = @{}

    switch ($PSCmdlet.ParameterSetName) {
        "ComputerName" {
            foreach ($computer in $ComputerName) {
                $status = Invoke-Command -ComputerName $computer -Credential $Credential `
                    -ScriptBlock $checkScript -ArgumentList $dellCommandPaths -ErrorAction SilentlyContinue
                $results[$computer] = [bool]$status
            }
        }
        "PSSession" {
            foreach ($session in $PSSession) {
                $status = Invoke-Command -Session $session `
                    -ScriptBlock $checkScript -ArgumentList $dellCommandPaths -ErrorAction SilentlyContinue
                $results[$session.ComputerName] = [bool]$status
            }
        }
        Default {
            $results["Localhost"] = & $checkScript $dellCommandPaths
        }
    }

    return $results
}
