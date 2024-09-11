Import-Module Pester
$env:PSModulePath = $env:PSModulePath + ";$($(Get-Location).Path)"

Describe "Install-LanguagePacks" {
    $password = ConvertTo-SecureString "Test1234!" -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential('TestUser', $password)
    Mock Get-Credential { $cred }
    Mock Invoke-Command {
        param ($ArgumentList, $ComputerName, [pscredential]$cred, $ScriptBlock)
        if ($ScriptBlock -like "*Get-WindowsCapability*") {
            return @(
                @{ Name = "Language.Arab~~~ar-SA~"; State = "NotPresent" },
                @{ Name = "Language.Pack~~~ar-SA~"; State = "NotPresent" }
            )
        }
        elseif ($ScriptBlock -like "*Set-WinUserLanguageList*") {
            return $null
        }
    }

    it 'Should install specified language pack' {
        # Arrange
        $params = @{
            ComputerName = 'TestComputer'
            Language     = 'Arabic (Saudi Arabia)'
        }

        Mock Add-WindowsCapability { }

        # Act
        Install-LanguagePacks @params

        # Assert - Check that Add-WindowsCapability was called with the right arguments
        Assert-MockCalled -ModuleName $null -CommandName Add-WindowsCapability -Exactly 1 -Times 2
    }

    it 'Should add language to current user language preferences' {
        # Arrange
        $params = @{
            ComputerName = 'TestComputer'
            Language     = 'Arabic (Saudi Arabia)'
        }

        # Act
        Install-LanguagePacks @params

        # Assert - Check that Set-WinUserLanguageList was called
        Assert-MockCalled -ModuleName $null -CommandName Invoke-Command -Exactly 1 -Times 1 -ScriptBlockContains "Set-WinUserLanguageList"
    }

    it 'Should handle errors during installation' {
        # Arrange
        $params = @{
            ComputerName = 'TestComputer'
            Language     = 'Arabic (Saudi Arabia)'
        }

        Mock Invoke-Command {
            param ($ArgumentList, $ComputerName, $Credential, $ScriptBlock)
            if ($ScriptBlock -like "*Add-WindowsCapability*") {
                throw "Error installing capability"
            }
        }

        # Act & Assert
        { Install-LanguagePacks @params } | Should -Throw
    }
}