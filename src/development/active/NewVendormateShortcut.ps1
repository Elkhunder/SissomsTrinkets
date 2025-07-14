function New-VendormateShortcut {
    param(
        [Parameter(Mandatory)]
        [string]$UserName,

        [Parameter(Mandatory)]
        [string]$Url,

        [ValidateSet("Fullscreen", "Kiosk")]
        [string]$Mode = "Fullscreen",

        [string]$ShortcutName = "Vendormate.lnk",

        [string]$ChromePath = "C:\Program Files\Google\Chrome\Application\chrome.exe"
    )

    # Determine the Startup path for the given user
    $startupPath = "C:\Users\$UserName\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\$ShortcutName"

    # Build argument string based on mode
    $arguments = switch ($Mode) {
        "Fullscreen" { "--start-fullscreen $Url" }
        "Kiosk"      { "--kiosk $Url" }
    }

    # Create the shortcut
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($startupPath)
    $shortcut.TargetPath = $ChromePath
    $shortcut.Arguments = $arguments
    $shortcut.WorkingDirectory = Split-Path $ChromePath
    $shortcut.IconLocation = $ChromePath
    $shortcut.WindowStyle = 1
    $shortcut.Save()

    Write-Host "✅ Shortcut created at: $startupPath"
    Write-Host "🖥️ Launch command: $ChromePath $arguments"
}
