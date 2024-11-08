function Get-UserLogonHistory {
    [CmdletBinding()]
    param (
        # User name to get history for
        [Parameter(Mandatory)]
        [string]
        $UserName,
        # List of computers to get login history for
        [string[]]
        $ComputerName,
        # Admin credential
        [Parameter(Mandatory)]
        [pscredential]
        $Credential,
        # Parameter for a quick, predefined time range like 'Last24Hours', 'Last7Days', 'Today'
        [ValidateSet('Last24Hours', 'Last7Days', 'ThisWeek', 'ThisMonth', 'Custom')]
        [string]$TimeRange = 'Last7Days',

        # Optional start time for custom date range (used when TimeRange is 'Custom')
        [datetime]$StartTime,

        # Optional end time for custom date range (used when TimeRange is 'Custom')
        [datetime]$EndTime
    )
    
    begin {
        try {
            Get-ADUser -Identity $UserName -ErrorAction Ignore | Out-Null
        }
        catch {
            throw "No user was found in AD with the username '$UserName'"
        }
        # Determine the start and end times based on the selected time range
        switch ($TimeRange) {
            'Last24Hours' {
                $StartTime = (Get-Date).AddDays(-1)
                $EndTime = Get-Date
            }
            'Last7Days' {
                $StartTime = (Get-Date).AddDays(-7).Date
                $EndTime = (Get-Date).Date
            }
            'ThisWeek' {
                $StartTime = (Get-Date).AddDays(-[int](Get-Date).DayOfWeek)
                $EndTime = Get-Date
            }
            'ThisMonth' {
                $StartTime = (Get-Date -Day 1).Date
                $EndTime = Get-Date
            }
            'Custom' {
                # Ensure that the user has provided both $StartTime and $EndTime
                if (-not $StartTime) {
                    throw "When using 'Custom', you must provide a StartTime.  Use the StartTime parameter to add a start time"
                }
                if (-not $EndTime) {
                    $EndTime = $null  # Default to now if EndTime not provided
                }
            }
        }
        Write-Host "EndTime: $EndTime, StartTime: $StartTime"
        if($EndTime){
            $eventFilter = @{
                LogName = 'Security'
                ID = 4624, 4625
                StartTime = $StartTime
                EndTime = $EndTime
            }
        } else {
            $eventFilter = @{
                LogName = 'Security'
                ID = 4624, 4625
                StartTime = $StartTime
            }
        }

        
        $logonTypes = @{
            2  = 'LocalInteractive'         # Local logon, typically for local console
            3  = 'Network'             # Remote logon via network
            4  = 'Batch'               # Logon type for batch processing jobs
            5  = 'Service'             # Logon as a service
            7  = 'Unlock'              # Logon to unlock a workstation
            8  = 'NetworkCleartext'    # Network logon with cleartext credentials
            9  = 'NewCredentials'      # Run-as using new credentials
            10 = 'RemoteInteractive'   # Remote logon using Remote Desktop (RDP)
            11 = 'CachedInteractive'   # Logon with cached credentials
        }

        $eventStatus = @{
            4624 = 'Success'
            4625 = 'Failed'
        }
        $logonHistory = New-Object 'System.Collections.Generic.List[System.Object]'
    }
    
    process {
        foreach ($computer in $ComputerName){
            $logonEvents = Get-WinEvent -ComputerName $computer -Credential $Credential -FilterHashtable $eventFilter

            foreach ($event in $logonEvents){
                # Convert the event to XML format to easily access the data
               $eventXML = [xml]$event.ToXml()

               # Extract the username from the XML (TargetUserName in Security log)
               [string]$targetUserName = $eventXML.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' } | Select-Object -ExpandProperty '#text'
               [string]$targetUserSid = $eventXML.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserSid' } | Select-Object -ExpandProperty '#text'
               # Add a custom property to track a specific condition, e.g., Logon Type description
               [int]$logonType = $eventXML.Event.EventData.Data | Where-Object { $_.Name -eq 'LogonType' } | Select-Object -ExpandProperty '#text'
           
               if($targetUserName -eq $UserName){

                   $logonHistory.Add([PSCustomObject]@{
                       TimeCreated = $event.TimeCreated
                       UserName = $targetUserName
                       UserSid = $targetUserSid
                       LogonStatus = $eventStatus[$event.Id]
                       LogonType = $logonTypes[$logonType]
                       DeviceName = $event.MachineName.Split('.')[0]
                   })
               }
               $logonHistory.Add($eventObject)
           }
        }
            
    }
    
    end {
        $logonHistory | Out-GridView
    }
}

Get-UserLogonHistory -ComputerName "WSRCD011","WSRCD001" -Credential $Credential -UserName 'jsissom'