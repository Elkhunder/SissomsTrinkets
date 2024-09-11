<#
      .SYNOPSIS
      Removes a Dell Bios Password using the Dell PowerShell Module

      .DESCRIPTION
        Checks if Bios Password is set
        Removes Bios Password
        Verifies Removal of Bios Password

      .PARAMETER BiosPassword
      The Current Bios Password
      .PARAMETER Scope
      Where the script is being run, Local or Remote
      .PARAMETER Manufacturer
      The Manufacturer of the device
      .NOTES
      Documentation
        Dell:
          Bios Password Features: https://www.dell.com/support/kbdoc/en-us/000146358/dell-command-powershell-provider-bios-passwords-feature
        HP:
          Bios Password Features:
            Clear: https://developers.hp.com/hp-client-management/doc/Clear-HPBIOSSetupPassword
            Get: https://developers.hp.com/hp-client-management/doc/Get-HPBIOSSetupPasswordIsSet
            Set: https://developers.hp.com/hp-client-management/doc/Set-HPBIOSSetupPassword

    #>
    function Clear-BiosPassword {
        [CmdletBinding()]
        param (
          # Parameter help description
          [Parameter()]
          [System.String[]]
          $Computers,
      
          # Parameter help description
          [Parameter()]
          [SecureString]
          $BiosPassword
        )
        # Set listview to visible
        $ListView_Results.Visible = $true
      
        # Initialize counter
        [int]$Counter = 1
        [int]$ProgressBarMin = 1
        [int]$ProgressBarMax = 8
        [int]$ProgressBarStep = 1
      
        # Set status strip to current operation and calculate percentage complete
        Set-StatusStrip `
          -OperationName "Securing Bios Password" `
          -ProgressBarMin $ProgressBarMin `
          -ProgressBarMax $ProgressBarMax `
          -ProgressBarStep $ProgressBarStep `
          -OperationProgress "$(($Counter/$ProgressBarMax).ToString('P0')) Percent Complete" `
          -ProgressBar $Counter
      
        foreach ($Computer in $Computers) {
          try {
            [int]$Counter = 1
            # Set status label to computer name
            $Script:Label_TermId.Text = "Executing on: $($Computer.ToUpper())"
      
            # Increment counter
            $Counter++
      
            # Set status strip to current operation and calculate percentage complete
            Set-StatusStrip `
              -OperationName "Creating PSSession" `
              -OperationProgress "$(($Counter/$ProgressBarMax).ToString('P0')) Percent Complete" `
              -ProgressBar $Counter
      
            # Create PSSession
            $s = New-PSSession -ComputerName $Computer
      
            # Invoke command utilizing local Install-Modules function
            Invoke-Command `
              -Session $s `
              -ScriptBlock ${Function:Install-Modules} `
              -ArgumentList $Counter |
              ForEach-Object {
                # Check if object is an integer
                if ($_ -is [int]) {
                  $Counter = $_
                  # If object is an integer, set value for progress bar and calculate percentage complete
                  Set-StatusStrip `
                    -OperationProgress "$(($Counter/$ProgressBarMax).ToString('P0')) Percent Complete" `
                    -ProgressBar $_
                }
                # Check if object is a string
                if ($_ -is [string]) {
                  # If object is a string, set status strip operation name
                  Set-StatusStrip -OperationName $_
                }
              }
            # Invoke command utlizing local Remove-BiosPassword function
            Invoke-Command `
              -Session $s `
              -ScriptBlock ${Function:Remove-BiosPassword} `
              -ArgumentList $BiosPassword, $Counter |
              ForEach-Object {
                # Check if object is an integer
                if ($_ -is [int]) {
                  $Counter = $_
                  # If object is an integer, set value for progress bar and calculate percentage complete
                  Set-StatusStrip `
                    -OperationProgress "$(($Counter/$ProgressBarMax).ToString('P0')) Percent Complete" `
                    -ProgressBar $Counter
                }
      
                # Check if object is a string
                if ($_ -is [string]) {
                  # If object is a string, set status strip operation name
                  Set-StatusStrip -OperationName $_
                }
                if ($_ -is [System.Management.Automation.PSCustomObject]) {
                  $Script:Result = $_
                }
              }
          } catch {
            <# Do this if a terminating exception happens #>
            return
          }
          # Check if the current progress bar value is less that the maximum value
          If ($Script:StripProgressBar.Value -lt $Script:StripProgressBar.Maximum) {
            # If the progress bar value is less than the maximum
            # Set the progress bar value to the maximum value and calculate the percentage complete
            Set-StatusStrip `
              -OperationProgress "$(($Script:StripProgressBar.Maximum/$ProgressBarMax).ToString('P0')) Percent Complete" `
              -ProgressBar $Script:StripProgressBar.Maximum
          }
          $items = [ordered]@{
            $Computer = [ordered]@{
              'Subitem1' = [string]$Result.BiosPasswordSet
              'Subitem2' = [string]$Result.Result
            }
          }
      
          $headers = [ordered]@{
            'Header1' = 'Term ID'
            'Header2' = 'Bios Password'
            'Header3' = 'Results'
          }
      
          # Update-Results -Headers $headers -Items $items
      
          # Remove PSSession
          Remove-PSSession -Session $s
      
          # Check if the variable BiosPassword exists
          if ($BiosPassword) {
            # Remove bios password variable specifying that the variable is a pscustom object
            Remove-Variable -Name [PSCustomObject]BiosPassword
          }
      
          # Check if the variable EncryptionKey exists
          if ($EncryptionKey) {
            # Remove the variable EncryptionKey
            Remove-Variable -Name EncryptionKey
          }
        }
        Return
      }
      
      #  function Update-Results {
      #    [CmdletBinding()]
      #    param (
      #      #  Value holding the computername the command was run on, expected values: localhost,computername
      #      [Parameter()]
      #      [string]
      #      $ComputerName,
      
      #      #  Value determining if the bios password is set, expected values: True,False
      #      [Parameter()]
      #      [string]
      #      $BiosPasswdSet,
      
      #      #  Value determining if the command ran succesfully, expected values: Successful, Unsuccessful
      #      [Parameter()]
      #      [string]
      #      $Result
      #    )
      #    # Create new list view item
      #    [System.Windows.Forms.ListViewItem]$ListViewItem = `
      #    (New-Object `
      #        -TypeName System.Windows.Forms.ListViewItem `
      #        -ArgumentList @([System.String]$ComputerName), 0)
      
      #    # Add bios password set value as a subitem
      #    $ListViewItem.SubItems.Add([System.String]$BiosPasswdSet)
      
      #    # Add the result as a subitem
      #    $ListViewItem.SubItems.Add([System.String]$Result)
      
      #    # Add the list view item to the list view
      #    $ListView_Results.Items.AddRange($ListViewItem)
      #  }
      
      function Install-Modules {
        [CmdletBinding()]
        Param(
          # Value for counter
          [Parameter()]
          [int]
          $Counter
        )
        $Counter++
        Write-Output $Counter
        Write-Output "Installing Modules"
        # Get manufacturer
        $Manufacturer = (Get-CimInstance -ClassName Win32_ComputerSystem).Manufacturer
        if ($Manufacturer -like 'dell*') { $Manufacturer = 'Dell'; $Script:Modules = 'DellBIOSProvider' }
        if ($Manufacturer -like 'hp*') { $Manufacturer = 'HP'; $Script:Modules = 'HPCMSL' }
      
        # Install Dell PS Module
        foreach ($Module in $Modules) {
          if (!(Get-InstalledModule -Name $Module)) {
      
            # Install Bios Provider
            Write-Output "Installing $Manufacturer BIOS Provider"
            Install-Module $Module -Force -AcceptLicense
            $Counter++
            Write-Output $Counter
          }
      
          $Counter++
          Write-Output $Counter
      
          # Import Bios Provider
          Write-Output "Importing $Manufacturer BIOS Provider"
          Import-Module $Module -Force
        }
      }
      
      function Remove-BiosPassword {
        <#
            .SYNOPSIS
            Removes a Dell Bios Password using the Dell PowerShell Module
      
            .DESCRIPTION
              Checks if Bios Password is set
              Removes Bios Password
              Verifies Removal of Bios Password
      
            .PARAMETER BiosPassword
            The Current Bios Password
            .PARAMETER Scope
            Where the script is being run, Local or Remote
            .PARAMETER Manufacturer
            The Manufacturer of the device
            .NOTES
            Documentation
              Dell:
                Bios Password Features: https://www.dell.com/support/kbdoc/en-us/000146358/dell-command-powershell-provider-bios-passwords-feature
              HP:
                Bios Password Features:
                  Clear: https://developers.hp.com/hp-client-management/doc/Clear-HPBIOSSetupPassword
                  Get: https://developers.hp.com/hp-client-management/doc/Get-HPBIOSSetupPasswordIsSet
                  Set: https://developers.hp.com/hp-client-management/doc/Set-HPBIOSSetupPassword
          #>
      
        [CmdletBinding()]
        param (
          [Parameter()]
          [securestring]
          $BiosPassword,
          # [Parameter(Position = 1)]
          # [array]
          # $EncryptionKey,
          # [Parameter(Position = 2)]
          # [string]
          # $Manufacturer,
          [Parameter()]
          [int]
          $Counter,
          [Parameter()]
          [string]
          $Scope
      
        )
        # Get manufacturer
        $Manufacturer = (Get-CimInstance -ClassName Win32_ComputerSystem).Manufacturer
      
        # Check manufacturer
        if ($Manufacturer -like "dell*") {
          # Set location to the dell ps module ps drive
          Set-Location DellSMBios:
      
          # Check to see if bios password is set and save to variable
          Write-Output "Getting current bios password value"
          # Convert value to boolean
          $BiosPasswordSet = [System.Convert]::ToBoolean($(Get-Item DellSmbios:\Security\IsAdminPasswordSet).CurrentValue)
      
          # Increment counter
          $Counter++
          Write-Output $Counter
      
          # If bios password is set
          if ($BiosPasswordSet.CurrentValue -eq "True") {
            Write-Output "Bios Password is set, Attempting to remove bios password ..."
      
            # Remove bios password by setting to an empty string
            Set-Item DellSmbios:\Security\AdminPassword -Value ""  -PasswordSecure $BiosPassword
      
            # Increment counter
            $Counter++
            Write-Output $Counter
      
            # Re-Check if bios password is set to confirm removal
            Write-Output "Getting current bios password value"
            # Convert value to boolean
            $BiosPasswordSet = [System.Convert]::ToBoolean($(Get-Item DellSmbios:\Security\IsAdminPasswordSet).CurrentValue)
          }
        }
      
        if ($Manufacturer -like "hp*") {
          # Convert bios password from secure string to plaintext
          $BiosPasswordPlainText = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($BiosPassword))
      
          # Get current value
          $BiosPasswordSet = Get-HPBIOSSetupPasswordIsSet
      
          # Check if bios password is set
          if ($BiosPasswordSet) {
            Write-Output "Bios Password is set, Attempting to remove bios password ..."
      
            # Increment counter
            $Counter++
            Write-Output $Counter
      
            # Remove bios password
            Clear-HPBIOSSetupPassword -Password $BiosPasswordPlainText
      
            # Re-Check if bios password is set to confirm removal
            $BiosPasswordSet = Get-HPBIOSSetupPasswordIsSet
      
            # Increment counter
            $Counter++
            Write-Output $Counter
          }
        }
        # Increment counter
        $Counter++
        Write-Output $Counter
      
        Write-Output "Bios Password is set: $BiosPasswordSet"
        $Result = $null
        if ($BiosPasswordSet) { $Result = 'Unsuccessful' }
        if (!$BiosPasswordSet) { $Result = 'Successful' }
        # Return result
        Return [PSCustomObject]@{
          BiosPasswordSet = $BiosPasswordSet
          Result          = $Result
        }
      
        # Clean up variables
        if ($EncryptionKey) {
          Remove-Variable -Name EncryptionKey
        }
        if ($BiosPasswordPlainText) {
          Remove-Variable -Name BiosPasswordPlainText
        }
        if ($BiosPassword) {
          Remove-Variable -Name BiosPassword
        }
      }