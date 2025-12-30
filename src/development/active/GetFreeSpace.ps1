function Get-FreeSpace {
    [CmdletBinding()]
    param(
        [string]$DriveLetter = 'C'
    )

    $drive = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='$DriveLetter`:'"
    if ($null -eq $drive) {
        throw "Drive $DriveLetter`: not found."
    }

    return "$([math]::Round($drive.FreeSpace / 1GB, 2)) GB"
}