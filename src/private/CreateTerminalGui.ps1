# https://blog.ironmansoftware.com/tui-powershell/#:~:text=Terminal.Gui%20is%20a%20.NET%20library%20for%20creating%20robust%20TUIs.%20It%E2%80%99s#:~:text=Terminal.Gui%20is%20a%20.NET%20library%20for%20creating%20robust%20TUIs.%20It%E2%80%99s



<# SYNOPSIS
    Initializes and sets up a terminal graphical user interface (GUI) window using the Microsoft.PowerShell.ConsoleGuiTools module.

SYNTAX
    Initialize-TerminalGuiWindow

DESCRIPTION
    The Initialize-TerminalGuiWindow function checks for the presence of the Microsoft.PowerShell.ConsoleGuiTools module, installs or updates it if necessary,
    and initializes a terminal GUI application. It returns an instance of a Terminal.Gui.Window.

    This function is designed to simplify the process of creating terminal-based graphical interfaces within PowerShell scripts.

EXAMPLES
    Example 1:
    ---------
    PS C:\> Initialize-TerminalGuiWindow
    Initializes the terminal GUI application and returns a Terminal.Gui.Window object.

NOTES
    Author: Jonathon Sissom
    Date: 2024/09/03

BEGIN BLOCK
    1. Declare variables for error handling and module versioning.
    2. Check if Microsoft.PowerShell.ConsoleGuiTools module is available.
    3. Install or update the module if necessary.
    4. Add the Terminal.Gui.dll assembly to the session.

PROCESS BLOCK
    1. Initialize the Terminal GUI application.
    2. Return a new instance of Terminal.Gui.Window.
#>
function Initialize-TerminalGuiApp {
    [CmdletBinding()]
    param()

    begin {
        $module = Get-Module -Name Microsoft.PowerShell.ConsoleGuiTools -ErrorAction SilentlyContinue
        [version]$latestVersion = $(Find-Module -Name Microsoft.PowerShell.ConsoleGuiTools).Version
        [version]$installedVersion = $module.Version

        if ($null -eq $module){
            Install-Module Microsoft.PowerShell.ConsoleGuiTools
            Import-Module -Name Microsoft.PowerShell.ConsoleGuiTools
        } elseif ($installedVersion -lt $latestVersion){
            Update-Module -Name Microsoft.PowerShell.ConsoleGuiTools
            Import-Module -Name Microsoft.PowerShell.ConsoleGuiTools -Force
        }

        $module = (Get-Module -Name Microsoft.PowerShell.ConsoleGuiTools -ListAvailable).ModuleBase
        Add-Type -Path (Join-Path $module Terminal.Gui.dll)
    }
    
    process {
        [Terminal.Gui.Application]::Init()
    }
}

function Initialize-TerminalGuiWindow{
    return [Terminal.Gui.Window]::new()
}

function Set-GuiWindowTitle {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Title,

        [Parameter(Mandatory)]
        [Terminal.Gui.Window]$GuiWindow
    )
    $GuiWindow.Title = $Title
}


function Set-GuiWindowItemList {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [System.Collections.Generic.List[string]]
        $ListItems,

        # Gui Window
        [Parameter(Mandatory, ValueFromPipeline)]
        [Terminal.Gui.Window]
        $GuiWindow
    )
    $ListView = [Terminal.Gui.ListView]::new()
    $ListView.SetSource($ListItems)
    $ListView.Width = [Terminal.Gui.Dim]::Fill()
    $ListView.Height = [Terminal.Gui.Dim]::Fill()
    $ListView.add_SelectedItemChanged({
        param($sender, $e)
        Write-Host "Selected item changed to: $($e.ItemIndex)"
    })
    $GuiWindow.Add($ListView)
}

function Show-TerminalGuiWindow {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [Terminal.Gui.Window]$GuiWindow
    )

    # Adding the window to the application
    [Terminal.Gui.Application]::Top.Add($GuiWindow)
    
    # Running the application
    [Terminal.Gui.Application]::Run()
}