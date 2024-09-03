function New-ListBox{
    <#
      .SYNOPSIS
      Creates List Box
  
      .DESCRIPTION
      -Creates list box for getting user selected data
      .PARAMETER TitleText
      The title of the list box
  
      .PARAMETER LabelText
      The description message for the list box
  
      .PARAMETER ListBoxItems
      The items to put in the list box to be selected
  
      .EXAMPLE
      New-ListBox -TitleText "Scope" -LabelText "Where would you like to run the script" -ListBoxItems Local,Remote
    #>
    Param(
      [string[]]$TitleText,
      [string[]]$LabelText,
      [string[]]$ListBoxItems
    )
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
  
    $form = New-Object System.Windows.Forms.Form
    $form.Text = $TitleText
    $form.Size = New-Object System.Drawing.Size(300,200)
    $form.StartPosition = 'CenterScreen'
  
    $okButton = New-Object System.Windows.Forms.Button
    $okButton.Location = New-Object System.Drawing.Point(75,120)
    $okButton.Size = New-Object System.Drawing.Size(75,23)
    $okButton.Text = 'Ok'
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
  
    $listBox = New-Object System.Windows.Forms.ListBox
    $listBox.Location = New-Object System.Drawing.Point(10,40)
    $listBox.Size = New-Object System.Drawing.Size(260,20)
    $listBox.Height = 80
  
    foreach ($ListboxItem in $ListBoxItems) {
      [void] $listBox.Items.Add($ListboxItem)
    }
  
    $form.Controls.Add($listBox)
  
    $form.Topmost = $true
    $result = $form.ShowDialog()
  
    if($result -eq [System.Windows.Forms.DialogResult]::Cancel){
      Write-Host "Cancel was selected, exiting program."
      Start-Sleep -Seconds 3
      exit
    }
  
    return $listBox.SelectedItem
  }