# <#

# ************************** Change Log ******************************
# ************************** Version 1 *******************************

# ** Initial Commit **

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
# $output = foreach ($computer in $computers) {
#   try {
#     $reachable = Test-Connection -Cn $computer -BufferSize 16 -Count 1 -ea 0 -quiet
#     $output = @()
#     ### Check to see if computer is reachable
#     if ($reachable)
#     {
#         ### Get printer list
#         Write-Host `Pulling information from $computer ...`
#         $printerList = Get-Printer -ComputerName $computer -Name "LOCAL"| Select-Object Name
#         $details = "information pulled from $computer successfully"
#     }
#     else
#     {
#         $details = `-$computer is not online, no information was gathered`
#     }

#     ### Store the information in an array
#     New-Object -TypeName PSObject -Property @{
#         TermID = $computer
#         Online = $reachable
#         Printer = $printerlist
#         Details = $details
#     } | Select-Object TermID, Online, Printer, Details


#     }catch{
#         Write-Host 'An error occured'
#         Write-Host $_
#         }
# }
# $output | Export-Csv "C:\Users\$env:USERNAME\Desktop\ListPrinters-Results.csv"
# Read-Host -Prompt "Script has finished, please check output files"