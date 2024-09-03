function Remove-UserProfile{
    $Computer = Read-Host "Please Enter Computer Name: "
    $user = Read-Host "Enter User ID: "

    Invoke-Command -ComputerName $computer -ScriptBlock {
        param($user)
        $localpath = 'c:\users\' + $user
        Get-WmiObject -Class Win32_UserProfile | Where-Object {$_.LocalPath -eq $localpath} |
        Remove-WmiObject
    } -ArgumentList $user
}
