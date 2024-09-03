function Invoke-LocalCimQuery{
    param (
        [hashtable]$WinVersionMap = $null,
        [hashtable]$MacVersionMap = $null
    )
    if ($IsWindows){
        $Win32_OperatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem
        $DeviceInfo = [PSCustomObject]@{
            'Computer' = $(Get-CimInstance -ClassName Win32_ComputerSystem).Name
            'OS Name' = $Win32_OperatingSystem.Caption
            'OS Version' = $WinVersionMap[$Win32_OperatingSystem.BuildNumber]
        }
        return $DeviceInfo
    }
    if ($IsMacOS){
        $OperatingSystem = system_profiler SPSoftwareDataType
        $OperatingSystemVersion = $($OperatingSystem | 
                                    Where-Object {$_.Contains('System Version')}).Split(':').Split(' ') | 
                                    Where-Object {$_.Contains('.')}
        
        $DeviceInfo = [PSCustomObject]@{
            'Computer' = $(scutil --get LocalHostName)
            'OS Name' = $MacVersionMap[$OperatingSystemVersion.Split('.')[0]]
            'OS Version' = $OperatingSystemVersion
        }
        return $DeviceInfo
    }
    
}