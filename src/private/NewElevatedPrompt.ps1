function New-ElevatedPrompt{
    <#
      .SYNOPSIS
      Elevates Script in New Powershell Session
  
      .DESCRIPTION
      -Checks to see if script is already running in an elevated session
      -Launches new elevated powershell session and calls script
      .PARAMETER Path
      The path of the script file
  
      .PARAMETER Credentials
      Provided credentials, not currently utilizing
    #>
    param(
      [Parameter(HelpMessage = "The Path For the Current Script File")]
      [string]$ScriptPath,
      [Parameter(HelpMessage = "The Path of Functions to import")]
      [string]$FunctionPath
    )
    #Check if current powershell session is running elevated
    if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
    Write-Host "Prompt is not Elevated, Elevating Prompt.  Enter your secondary credentials in the UAC prompt"
    if ([int](Get-CimInstance -Class Win32_OperatingSystem | Select-Object -ExpandProperty BuildNumber) -ge 6000) {
      $ScriptBlock = {
        <#
        Gets username of the currently logged on user not the one that is running the script.
        This is done to return the primary level-2 account of the currently logged in user,
        as at this point the script will be running with their secondary level-2 account
        #>
        $UserName = (Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object username).username
        # #Get primary level-2 account credentials
        $Credential = Get-Credential -UserName $UserName -Message "'Provide your Level-2 credentials.'"
        <#
        Map share drive with the provided primary level-2 credentials.
        Without this the script won't have access to the share path when the script launches
        #>
        New-PSDrive -Name 'T' -PSProvider 'FileSystem' -Root '\\corefs.med.umich.edu\shared2' -Credential $Credential | Out-Null
      }
      #Specify command line arguments
      $CommandLine = "-NoExit", "-Command $ScriptBlock"
      <#
      Start new elevated powershell process with command line arguments and the script path passed in as arguments
      Im not 100% sure why this works and calls the script?
      Potentially after the command line arguments are called it passes in the full script path which calls then executes the script
      #>
      Start-Process -FilePath PowerShell.exe -Verb Runas -ArgumentList "$CommandLine", "$ScriptPath"
      #Exit current unelevated powershell session
      Exit
    }
  }
}