function Get-CCMClientHealth {
    [CmdletBinding()]
    param (
        # Parameter help description
        [Parameter(Mandatory)]
        [string[]]
        $ComputerName,
        # Parameter help description
        [Parameter(Mandatory)]
        [pscredential]
        $Credential
    )
    
    begin {
            class CCMEval {
                [Client]$Client
                [HealthCheckSummary]$Summary
                [HealthCheckResult[]]$HealthChecks
            
                # Constructor for CCMEval
                CCMEval([CimInstance]$smsClient, [object]$healthCheckSummary, [System.Xml.XmlElement[]]$healthChecks) {
                    # Initialize Client object
                    $this.Client = [Client]::new($smsClient)
            
                    # Initialize HealthCheckSummary object
                    $this.Summary = [HealthCheckSummary]::new($healthCheckSummary)
            
                    # Initialize HealthChecks array with HealthCheckResult objects
                    $this.HealthChecks = $healthChecks | ForEach-Object { [HealthCheckResult]::new($_) }
                }

                # ToString method to format output
                [string] ToString() {
                    $output = @()
                    $output += "Client Info:"
                    $output += "--------------------------"
                    $output += "Computer Name: $($this.Client.ComputerName)"
                    $output += "Client Version: $($this.Client.Version)"
                    $output += "Client Type: $($this.Client.Type)"
                    $output += "Allow Local Admin Override: $($this.Client.AllowLocalAdminOveride)"
                    $output += ""
                    $output += "Health Check Summary:"
                    $output += "--------------------------"
                    $output += "Evaluation Date: $($this.Summary.EvaluationDate)"
                    $output += "Summary Result: $($this.Summary.Result)"
                    $output += "Summary Version: $($this.Summary.Version)"

                    return $output -join "`n"
                }
            }
            class Client {
                [bool]$AllowLocalAdminOveride
                [int]$Type
                [version]$Version
                [bool]$EnableAutoAssignment
                [string]$ComputerName

                Client([CimInstance]$smsClient){
                    $this.AllowLocalAdminOveride = $smsClient.AllowLocalAdminOverride
                    $this.Type = $smsClient.ClientType
                    $this.Version = $smsClient.ClientVersion
                    $this.EnableAutoAssignment = $smsClient.EnableAutoAssignment
                    $this.ComputerName = $smsClient.PSComputerName
                }
            }
            class HealthCheckSummary {
                [datetime]$EvaluationDate
                [version]$Version
                [string]$Result

                HealthCheckSummary([object[]]$healthCheckSummary){
                    $this.EvaluationDate = $healthCheckSummary.EvaluationTime
                    $this.Version = $healthCheckSummary.Version
                    $this.Result = $healthCheckSummary.'#text'
                }
            }
            class HealthCheckResult {
                [string]$ID
                [string]$Description
                [int]$ResultCode
                [int]$ResultType
                [string]$ResultDetail
                [string]$StepDetail
                [string]$ResultStatus

                HealthCheckResult([System.Xml.XmlElement]$healthCheck) {
                    # Extract values from the XML element
                    $this.ID = $healthCheck.ID.'#text'
                    $this.Description = $healthCheck.Description.'#text'
                    $this.ResultCode = [int]$healthCheck.ResultCode.'#text'
                    $this.ResultType = [int]$healthCheck.ResultType.'#text'
                    $this.ResultDetail = $healthCheck.ResultDetail.'#text'
                    $this.StepDetail = $healthCheck.StepDetail.'#text'
                    # Map '#text' to ResultStatus
                    $this.ResultStatus = $healthCheck.'#text'
                }
            }
    }
    
    process {
        foreach ($Computer in $ComputerName) {
            $cimSession = New-CimSession -ComputerName $Computer -Credential $Credential
            $smsClient = (Get-CimInstance -Namespace "root/ccm" -ClassName SMS_Client -CimSession $cimSession)
            $localSMSPath = (Get-ItemProperty("HKLM:\SOFTWARE\Microsoft\SMS\Client\Configuration\Client Properties")).$("Local SMS Path")
            $ccmEvalPath = "${localSMSPath}ccmeval.exe"
            $ccmevalReportPath = "${localSMSPath}CcmEvalReport.xml"

            Invoke-Command -ComputerName $Computer -Credential $Credential -ScriptBlock{(start-process $using:ccmEvalPath)}

            [xml]$ccmEvalReport = (Invoke-Command -ComputerName $Computer -Credential $Credential -ScriptBlock{(Get-Content $using:ccmevalReportPath)})
            [object[]]$ccmHealthChecks = $ccmEvalReport.ClientHealthReport.HealthChecks.HealthCheck
            [object[]]$ccmHealthCheckSummary = $ccmEvalReport.ClientHealthReport.Summary

            [CCMEval]$ccmEval = [CCMEval]::new($smsClient, $ccmHealthCheckSummary, $ccmHealthChecks)

            # # Print client info and summary info
            # Write-Output "Client Info"
            # Write-Output "Computer Name: $($ccmEval.Client.ComputerName)"
            # Write-Output "Client Version: $($ccmEval.Client.Version)"
            # Write-Output "Client Type: $($ccmEval.Client.Type)"
            # Write-Output "Allow Local Admin Override: $($ccmEval.Client.AllowLocalAdminOveride)"
            # Write-Output ""
            # Write-Output "Health Check Summary"
            # Write-Output "Evaluation Date: $($ccmEval.Summary.EvaluationDate)"
            # Write-Output "Summary Result: $($ccmEval.Summary.Result)"
            # Write-Output "Summary Version: $($ccmEval.Summary.Version)"
            # Write-Output ""
            # Write-Output
        }   
    }
    
    end {
        Write-Output $ccmEval.ToString()

        if ($PSCmdlet.MyInvocation.BoundParameters["OutVariable"]) {
            $OutVariableName = $PSCmdlet.MyInvocation.BoundParameters["OutVariable"]
            Set-Variable -Name $OutVariableName -Value $ccmEval -Scope 1 -Option AllScope
        }
    }
}