# # This file was generated at 9/3/2024 11:56:11 PM
# # Manually editing this file may result in issues with the designer
# $Window = [Terminal.Gui.Window]::new()
# $Window.Id = 'Window'
# $Window.Title = 'Installed Software'
# $Window.X = 0
# $Window.Y = 0
# $Window.Width = [Terminal.Gui.Dim]::Fill()
# $Window.Height = [Terminal.Gui.Dim]::Fill()
# $Label = [Terminal.Gui.Label]::new()
# $Label.Width = 30
# $Label.Height = 5
# $Cancel_Button = [Terminal.Gui.Button]::new()
# $Cancel_Button.Text = 'Cancel'
# $Cancel_Button.IsDefault = $False
# $Cancel_Button.HotKey = 'C'
# $Cancel_Button.AutoSize = $False
# $Cancel_Button.Shortcut = 'Null'
# $Cancel_Button.TabIndex = 1
# $Cancel_Button.TabStop = $False
# $Cancel_Button.CanFocus = $True
# $Cancel_Button.Id = 'Cancel_Button'
# $Cancel_Button.WantMousePositionReports = $False
# $Cancel_Button.WantContinuousButtonPressed = $False
# $Cancel_Button.LayoutStyle = 'Computed'
# $Cancel_Button.X = [Terminal.Gui.Pos]::At(50)
# $Cancel_Button.Y = [Terminal.Gui.Pos]::At(25)
# $Cancel_Button.Width = [Terminal.Gui.Dim]::Sized(10)
# $Cancel_Button.Height = [Terminal.Gui.Dim]::Sized(1)
# $Cancel_Button.TextAlignment = 'Centered'
# $Cancel_Button.VerticalTextAlignment = 'Top'
# $Cancel_Button.TextDirection = 'LeftRight_TopBottom'
# $Cancel_Button.IsInitialized = $True
# $Cancel_Button.Enabled = $True
# $Cancel_Button.Visible = $True
# $Window.Add($Cancel_Button)
# $OK_Button = [Terminal.Gui.Button]::new()
# $OK_Button.Text = 'Ok'
# $OK_Button.IsDefault = $False
# $OK_Button.HotKey = 'O'
# $OK_Button.AutoSize = $False
# $OK_Button.Shortcut = 'Null'
# $OK_Button.TabIndex = 2
# $OK_Button.TabStop = $True
# $OK_Button.CanFocus = $True
# $OK_Button.Id = 'OK_Button'
# $OK_Button.WantMousePositionReports = $False
# $OK_Button.WantContinuousButtonPressed = $False
# $OK_Button.LayoutStyle = 'Computed'
# $OK_Button.X = [Terminal.Gui.Pos]::At(42)
# $OK_Button.Y = [Terminal.Gui.Pos]::At(25)
# $OK_Button.Width = [Terminal.Gui.Dim]::Sized(8)
# $OK_Button.Height = [Terminal.Gui.Dim]::Sized(1)
# $OK_Button.TextAlignment = 'Centered'
# $OK_Button.VerticalTextAlignment = 'Top'
# $OK_Button.TextDirection = 'LeftRight_TopBottom'
# $OK_Button.IsInitialized = $True
# $OK_Button.Enabled = $True
# $OK_Button.Visible = $True
# $Window.Add($OK_Button)
# $ListView = [Terminal.Gui.ListView]::new()
# $ListView.AllowsMarking = $False
# $ListView.AllowsMultipleSelection = $False
# $ListView.TopItem = 0
# $ListView.LeftItem = 0
# $ListView.SelectedItem = 0
# $ListView.HotKey = 'Null'
# $ListView.Shortcut = 'Null'
# $ListView.TabIndex = 3
# $ListView.TabStop = $True
# $ListView.CanFocus = $True
# $ListView.Id = 'ListView'
# $ListView.WantMousePositionReports = $False
# $ListView.WantContinuousButtonPressed = $False
# $ListView.LayoutStyle = 'Computed'
# $ListView.X = [Terminal.Gui.Pos]::At(0)
# $ListView.Y = [Terminal.Gui.Pos]::At(0)
# $ListView.Width = [Terminal.Gui.Dim]::Fill()
# $ListView.Height = [Terminal.Gui.Dim]::Fill()
# $ListView.Text = ''
# $ListView.AutoSize = $False
# $ListView.TextAlignment = 'Left'
# $ListView.VerticalTextAlignment = 'Top'
# $ListView.TextDirection = 'LeftRight_TopBottom'
# $ListView.IsInitialized = $True
# $ListView.Enabled = $True
# $ListView.Visible = $True
# $ListView.SetSource(@(
#     'Microsoft 365 Apps for enterprise - en-us',
#     'Microsoft OneDrive',
#     'CrowdStrike Sensor Platform',
#     '64 Bit HP CIO Components Installer',
#     'Microsoft Visual C++ 2010  x64 Redistributable - 10.0.40219',
#     'Configuration Manager Client',
#     'Zoom (64-bit)',
#     'Microsoft Visual C++ 2012 x64 Additional Runtime - 11.0.61030',
#     'Microsoft Visual C++ 2022 X64 Additional Runtime - 14.32.31326',
#     'CyberArk Endpoint Privilege Manager Agent',
#     'Synergy (64-bit)',
#     'CrowdStrike Firmware Analysis',
#     'Google Chrome',
#     'Office 16 Click-to-Run Licensing Component',
#     'Office 16 Click-to-Run Extensibility Component',
#     'Microsoft Visual C++ 2013 x64 Additional Runtime - 12.0.21005',
#     'CrowdStrike Device Control',
#     'Microsoft Visual C++ 2013 x64 Minimum Runtime - 12.0.21005',
#     'MDOP MBAM',
#     '1E Client x64',
#     'PowerShell 7-x64',
#     'Microsoft Visual C++ 2022 X64 Minimum Runtime - 14.32.31326',
#     'Windows Admin Center',
#     'Microsoft Policy Platform',
#     'Microsoft Visual C++ 2012 x64 Minimum Runtime - 11.0.61030',
#     'Adobe CCDA'
#     ))
# $ListView.add_SelectedItemChanged({$Window.Title = $ListView.SelectedItem})

# $Window.Add($Label)
# $Window.Add($ListView)
# $Window
