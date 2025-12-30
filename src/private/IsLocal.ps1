function IsLocal {
    param([string]$Name)
    $local = @('localhost', '.', $env:COMPUTERNAME)
    $isLocal = ($local -contains $Name)
    Write-Verbose "    IsLocal: '$Name' = $isLocal"
    return $isLocal
}