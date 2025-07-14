# <#

# ************************** Change Log ******************************
# ************************** Version 1 *******************************

# ** Added propmt for printer name and assigning name to a variable **
# ** Added changing default printer to the newly named local printer *
# ** Added set printer functionality using the UMHS setprinters-win7.vbs script
# ******** Added ability to use either a file or manual input ********

# ************************ Feature Requests **************************

# Future - Add ability to choose if you want to export results to a file instead of have it written to console

# #>


# $userFile = Read-Host -Prompt 'Do you want to use a file for importing computer names? (Y/N)'
# try {
#   if($userFile -eq 'Y') {
#     Do {

#       Write-Host 'Place a text file on your desktop that contains the computer names'
#       $filename = Read-Host -Prompt "Input filename w/o extension"
#       $filePath = "C:\Users\$env:USERNAME\Desktop\$filename.txt"
#       $testPath = Test-Path $filePath -PathType Leaf
#       if ($testPath -eq "True") {continue}
#       else {

#         Write-Host 'The file was not found, or there was an error'
#         Write-Host $_
#       }
#     }
#     Until ($testPath -eq "True")

#     $computers = Get-Content $filePath
#     Write-Host $computers
#   }

#   if($userFile -eq 'N') {

#     ### Prompt for list of computers and assign to the variable computers
#     $computers = Read-Host -Prompt 'Enter Term ID, if multiples seperate with ,'
#     ### Split list of computers using , as the seperator
#     $computers = $computers -split ','
#   }
# } catch {

#   Write-Host 'An error occured'
#   Write-Host $_
# }

# ### Prompt for credentials
# $credential = $host.ui.PromptForCredential("Need credentials", "Please enter your level 2 credentials.", "", "NetBiosUserName")

# foreach ($computer in $computers) {
#   try {
#     ### Get printer list
#     Write-Host `Pulling information from $computer ...`
#     Get-Printer -ComputerName $computer | Format-Table -AutoSize | Out-Host
#     ### Prompt for printer name
#     $currentPrinter = Read-Host -Prompt 'Enter name of printer you wish to change'
#     ### Get and assign printer to a variable named printer
#     $printer = Get-Printer -ComputerName $computer  | Where-Object {$_.Name -eq "$currentPrinter"}
#     ### Prompt for new printer name
#     $newPrinter = Read-Host -Prompt 'Enter the new name of the printer'
#     ### Rename printer
#     Rename-Printer -InputObject $printer -NewName $newPrinter
#     ### Get printer with new printer name, for verifying changes
#     Get-Printer -ComputerName $computer -Name $newPrinter | Format-Table -AutoSize | Out-Host
#     ### Set default printer
#     Write-Host -NoNewline 'Do you need to run set printers script? (Y/N)'
#     $response = Read-Host
#     if ($response -ne 'Y') {continue}
#     Invoke-Command -ComputerName $computer -ScriptBlock {cscript.exe c:\wsmgmt\bin\setprinters-win7.vbs}
#   } catch {
#     Write-Host 'An error occured'
#     Write-Host $_
#   }
# }
# Read-Host -Prompt 'Press enter to exit'

