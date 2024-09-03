function New-EncryptionKey{
    <#
      .SYNOPSIS
      Creates new encryption key
  
      .DESCRIPTION
      Creates new encryption key to be passed to the Convert-FromSecureString commandlet
  
      .PARAMETER Path
      The path where the key file is saved
  
      .EXAMPLE
      New-EncryptionKey -Path "~\encryption.key"
    #>
    param(
      [string]$Path
    )
    #Initialize a 32 bit byte array
    $EncryptionKey = New-Object Byte[] 32
    #Create encryption key
    [Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($EncryptionKey)
    #Save encryption key to provided file path
    if($Path){
      $EncryptionKey | Out-File $Path
    } else {
      return $EncryptionKey
    }
  }