function New-CustomInput{
    <#
      .SYNOPSIS
      Creates Input Text Box
  
      .DESCRIPTION
      -Creates input text box for getting user input
      .PARAMETER LabelText
      The text box label
      .PARAMETER AsSecureString
      Text as a secure string
      .PARAMETER AsEncryptedString
      Text as an encrypted string
      .NOTES
      Function Returns
      -Default
        Inputed Text
      -AsSecureString
        Returns inputed text as secure string
      -AsEncryptedString
        Returns encryption key and inputed text encrpted string file paths
    #>
    [cmdletbinding(DefaultParameterSetName="plain")]
    [OutputType([system.string],ParameterSetName='plain')]
    [OutputType([system.security.securestring],ParameterSetName='secure')]
  
    Param(
      [Parameter(ParameterSetName = "secure")]
      [Parameter(ParameterSetName = "encrypted")]
      [Parameter(HelpMessage = "Enter the title for the input box.",
      ParameterSetName="plain")]
  
      [ValidateNotNullOrEmpty()]
      [string[]]$LabelText = "Input Text",
  
      [Parameter(HelpMessage = "Use to mask the entry and return a secure string.",
      ParameterSetName = "secure")]
      [switch]$AsSecureString,
  
      [Parameter(HelpMessage = "Use to mask the entry and return an encrypted string.",
      ParameterSetName = "encrypted")]
      [switch]$AsEncryptedString
    )
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
  
    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'Data Entry Form'
    $form.Size = New-Object System.Drawing.Size(300,200)
    $form.StartPosition = 'CenterScreen'
  
    $okButton = New-Object System.Windows.Forms.Button
    $okButton.Location = New-Object System.Drawing.Point(75,120)
    $okButton.Size = New-Object System.Drawing.Size(75,23)
    $okButton.Text = 'OK'
    $okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $form.AcceptButton = $okButton
    $form.Controls.Add($okButton)
  
    $cancelButton = New-Object System.Windows.Forms.Button
    $cancelButton.Location = New-Object System.Drawing.Point(150,120)
    $cancelButton.Size = New-Object System.Drawing.Size(75,23)
    $cancelButton.Text = 'Cancel'
    $cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $form.CancelButton = $cancelButton
    $form.Controls.Add($cancelButton)
  
    $label = New-Object System.Windows.Forms.Label
    $label.Location = New-Object System.Drawing.Point(10,20)
    $label.Size = New-Object System.Drawing.Size(280,20)
    $label.Text = $LabelText
    $form.Controls.Add($label)
  
    if ($AsSecureString -or $AsEncryptedString){
      $textBox = New-Object System.Windows.Forms.MaskedTextBox
      $textBox.PasswordChar = '*'
    } else {
      $textBox = New-Object System.Windows.Forms.TextBox
    }
    $textBox.Location = New-Object System.Drawing.Point(10,40)
    $textBox.Size = New-Object System.Drawing.Size(260,20)
    $form.Controls.Add($textBox)
  
    $form.Topmost = $true
  
    $form.Add_Shown({$textBox.Select()})
    $result = $form.ShowDialog()
    $text = $textBox.Text
    if($result -eq [System.Windows.Forms.DialogResult]::Cancel){
      Write-Host "Cancel was selected, exiting program."
      Start-Sleep -Seconds 3
      exit
    }
  
    if($result -eq [System.Windows.Forms.DialogResult]::OK -and $AsSecureString){
      return ConvertTo-SecureString $text -AsPlainText -Force
    }
    if($result -eq [System.Windows.Forms.DialogResult]::OK -and $AsEncryptedString){
      # New-EncryptionKey -Path "~\encryption.key"
      $EncryptionKey = New-EncryptionKey
      $EncryptedString = ConvertTo-SecureString $text -AsPlainText -Force |
        ConvertFrom-SecureString -Key $EncryptionKey
          # | Out-File -FilePath "~\encryptedstring.encrypted"
      # $EncryptionKey = "~\encryption.key"
      # $EncryptedString = "~\encryptedstring.encrypted"
      Return @{
        EncryptionKey = $EncryptionKey;
        EncryptedString = $EncryptedString
      }
    }
    return $text
  }