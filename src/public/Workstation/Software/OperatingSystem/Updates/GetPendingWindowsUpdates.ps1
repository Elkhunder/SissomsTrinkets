# $u = New-Object -ComObject Microsoft.Update.Session
# $u.ClientApplicationID = 'MSDN Sample Script'
# $s = $u.CreateUpdateSearcher()
# #$r = $s.Search("IsInstalled=0 and Type='Software' and IsHidden=0")
# $r = $s.Search('IsInstalled=0')
# $r.updates|select -ExpandProperty Title

# Invoke-Command -Session $s -ScriptBlock {

# }
# Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force