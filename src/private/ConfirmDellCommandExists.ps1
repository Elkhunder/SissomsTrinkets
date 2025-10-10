function Confirm-DellCommandExists {
    <#
    .SYNOPSIS
        Ensures that the Dell Command | Update tool is installed on the target computer(s).
    .DESCRIPTION
        Checks if the Dell Command | Update tool is installed on the specified computer(s).
        If it is not installed, downloads and installs the tool.
    .PARAMETER ComputerName
        The name of the target computer(s). Accepts pipeline input.
    .PARAMETER Credential
        Credentials to use for connecting to the target computer.
    .PARAMETER PSSession
        One or more existing PowerShell sessions. Accepts pipeline input.
    .PARAMETER DownloadUrl
        The URL to download the Dell Command | Update installer if missing.
    .OUTPUTS
        System.Management.Automation.PSCustomObject
        Returns objects with the following properties:
        - ComputerName: The name of the computer where Dell Command was checked/installed
        - Exists: Boolean indicating whether Dell Command | Update is present
        - Path: Full path to the dcu-cli.exe executable if found
        - Status: Installation status - "AlreadyPresent", "Installed", or "Failed"
    .EXAMPLE
        Ensure-DellCommandExists -ComputerName "RemotePC" -Credential (Get-Credential)
    .EXAMPLE
        "PC01","PC02" | Ensure-DellCommandExists
    .EXAMPLE
        Get-PSSession | Ensure-DellCommandExists
    #>
    [CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Local')]
    [OutputType([PSCustomObject])]
    param(

        [Parameter(ParameterSetName = "ComputerName", ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias("CN","Name")]
        [string[]]$ComputerName,

        [Parameter(ParameterSetName = "ComputerName")]
        [pscredential]$Credential,

        [Parameter(ParameterSetName = "PSSession", ValueFromPipeline)]
        [System.Management.Automation.Runspaces.PSSession[]]$PSSession,

        [string]$DownloadUrl = "https://dl.dell.com/FOLDER13309338M/2/Dell-Command-Update-Application_Y5VJV_WIN64_5.5.0_A00_01.EXE"
    )

    begin {
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

        $installScript = {
            param($url, $paths)
            $installerPath = "$env:TEMP\DellCommandUpdateInstaller.exe"
            try {
                Invoke-WebRequest -Uri $url -OutFile $installerPath -UseBasicParsing -ErrorAction Stop
                Start-Process -FilePath $installerPath -ArgumentList "/s" -Wait
            } catch {
                Write-Warning "Download or installation failed: $_"
            } finally {
                if (Test-Path $installerPath) { Remove-Item -Path $installerPath -Force }
            }

            foreach ($path in $paths) {
                if (Test-Path $path) { return $path }
            }
            return $null
        }

        $results = @()
    }

    process {
        switch ($PSCmdlet.ParameterSetName) {
            "ComputerName" {
                foreach ($computer in $ComputerName) {
                    $foundPath   = Invoke-Command -ComputerName $computer -Credential $Credential `
                                    -ScriptBlock $checkScript -ArgumentList $dellCommandPaths -ErrorAction SilentlyContinue
                    $wasInstalled = $false

                    if (-not $foundPath -and $PSCmdlet.ShouldProcess($computer, "Install Dell Command | Update")) {
                        $wasInstalled = $true
                        Write-Verbose "Dell Command | Update not found on $computer. Installing..."
                        $foundPath = Invoke-Command -ComputerName $computer -Credential $Credential `
                                        -ScriptBlock $installScript -ArgumentList $DownloadUrl,$dellCommandPaths -ErrorAction SilentlyContinue
                    }

                    $status = if ($foundPath) {
                        if ($wasInstalled) { "Installed" } else { "AlreadyPresent" }
                    } else {
                        "Failed"
                    }

                    $results += [pscustomobject]@{
                        ComputerName = $computer
                        Exists       = [bool]$foundPath
                        Path         = $foundPath
                        Status       = $status
                    }
                }
            }

            "PSSession" {
                foreach ($session in $PSSession) {
                    $foundPath   = Invoke-Command -Session $session `
                                    -ScriptBlock $checkScript -ArgumentList $dellCommandPaths -ErrorAction SilentlyContinue
                    $wasInstalled = $false

                    if (-not $foundPath -and $PSCmdlet.ShouldProcess($session.ComputerName, "Install Dell Command | Update")) {
                        $wasInstalled = $true
                        Write-Verbose "Dell Command | Update not found on $($session.ComputerName). Installing..."
                        $foundPath = Invoke-Command -Session $session `
                                        -ScriptBlock $installScript -ArgumentList $DownloadUrl,$dellCommandPaths -ErrorAction SilentlyContinue
                    }

                    $status = if ($foundPath) {
                        if ($wasInstalled) { "Installed" } else { "AlreadyPresent" }
                    } else {
                        "Failed"
                    }

                    $results += [pscustomobject]@{
                        ComputerName = $session.ComputerName
                        Exists       = [bool]$foundPath
                        Path         = $foundPath
                        Status       = $status
                    }
                }
            }

            Default {
                $foundPath   = & $checkScript $dellCommandPaths
                $wasInstalled = $false

                if (-not $foundPath -and $PSCmdlet.ShouldProcess($env:COMPUTERNAME, "Install Dell Command | Update")) {
                    $wasInstalled = $true
                    Write-Verbose "Dell Command | Update not found on $env:COMPUTERNAME. Installing..."
                    $foundPath = & $installScript $DownloadUrl $dellCommandPaths
                }

                $status = if ($foundPath) {
                    if ($wasInstalled) { "Installed" } else { "AlreadyPresent" }
                } else {
                    "Failed"
                }

                $results += [pscustomobject]@{
                    ComputerName = $env:COMPUTERNAME
                    Exists       = [bool]$foundPath
                    Path         = $foundPath
                    Status       = $status
                }
            }
        }
    }

    end {
        return $results
    }
}
