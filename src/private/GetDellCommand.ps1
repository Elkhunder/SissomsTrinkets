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
            if (Test-Path $path) { return $path }
        }
        return $null
    }

    $results = @()

    switch ($PSCmdlet.ParameterSetName) {
        "ComputerName" {
            foreach ($computer in $ComputerName) {
                $foundPath = Invoke-Command -ComputerName $computer -Credential $Credential `
                    -ScriptBlock $checkScript -ArgumentList $dellCommandPaths -ErrorAction SilentlyContinue
                $results += [pscustomobject]@{
                    ComputerName = $computer
                    Exists       = [bool]$foundPath
                    Path         = $foundPath
                }
            }
        }
        "PSSession" {
            foreach ($session in $PSSession) {
                $foundPath = Invoke-Command -Session $session `
                    -ScriptBlock $checkScript -ArgumentList $dellCommandPaths -ErrorAction SilentlyContinue
                $results += [pscustomobject]@{
                    ComputerName = $session.ComputerName
                    Exists       = [bool]$foundPath
                    Path         = $foundPath
                }
            }
        }
        Default {
            $foundPath = & $checkScript $dellCommandPaths
            $results += [pscustomobject]@{
                ComputerName = "Localhost"
                Exists       = [bool]$foundPath
                Path         = $foundPath
            }
        }
    }

    return $results
}
