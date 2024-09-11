<#

************************** Change Log ******************************
************************** Version 1.0 *******************************
* Added *
- User inputed computer names, limit of 28 at one time
- psexec to remotely run the set-printers

************************** Version 1.1 *******************************
  Added
  ********************************************************************
- Do Until loop for accepting user input to utilize a file for computer names
**********************************************************************

  Updated 
  ********************************************************************
- variable for computer names to $computers
- set printer functionality using invoke command
**********************************************************************

  Removed 
  ********************************************************************
- utilization of psexec

************************* Feature Requests ***************************


#>

### Prompt for list of computers and assign to the variable computers
# $userFile = Read-Host -Prompt 'Do you want to use a file for importing computer names? (Y/N)'
# try {
#   if($userFile -eq 'Y')
#     {
#       Do {
#             Write-Host 'Place a text file on your desktop that contains the computer names'
#             $filename = Read-Host -Prompt "Input filename w/ extension" 
#             $filePath = "C:\Users\$env:USERNAME\Desktop\$filename"

#             ### Test the file path
#             $testPath = Test-Path $filePath -PathType Leaf
#             if ($testPath -eq "True") {continue}
#             else
#               {
#                 Write-Host 'The file was not found, or there was an error'
#                 Write-Host $_
#               }
#           }
#           Until ($testPath -eq "True")
#       $computers = Get-Content $filePath
#       Write-Host $computers
#       }
      

      
    
#   if($userFile -eq 'N')
#     {
#       $computers = Read-Host -Prompt 'Enter Term ID, if multiples seperate with ,'
#       ### Split list of computers using , as the seperator
#       $computers = $computers -split ','
#     }
# }
# catch
# {
#    Write-Host 'An error occured'
#     Write-Host $_
# }

# ### Prompt for credentials
# $credential = (Get-Credential umhs\uniqname -Message "Enter your level 2 credentials")

# foreach ($computer in $computers) {
#   try {
#   Invoke-Command -Credential $credential -ComputerName $computer -ScriptBlock {cscript.exe c:\wsmgmt\bin\setprinters-win7.vbs}
#   } catch {
#     Write-Host 'An error occured'
#     Write-Host $_
#   }
# }
# Read-Host -Prompt 'Press enter to exit'







<# VERSION 1.0
#Get Input, TermId's must be seperated by commas 
$_TermIdList = Read-Host "Enter TermId's, seperated by commas with no spaces.  There is a limit of 28 termid's at one time"
$_TermIdList
psexec \\$_TermIdList -s cscript c:\wsmgmt\bin\setprinters-win7.vbs
Read-Host -Prompt "Press Enter to Exit"
#>