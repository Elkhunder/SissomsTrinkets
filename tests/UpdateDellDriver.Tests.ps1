# DellCommandFunctions.Tests.ps1
Import-Module Pester
Write-Host $PWD
Import-Module ..\dist\SissomsTrinkets -Force

Describe "Confirm-DellCommandExists" {
    BeforeEach {
        # Mock external dependencies
        Mock Test-Path { $false } -ParameterFilter { $Path -like "*dcu-cli.exe" }
        Mock Invoke-Command { $null }
        Mock Invoke-WebRequest { }
        Mock Start-Process { }
        Mock Remove-Item { }
        Mock Write-Verbose { }
        Mock Write-Warning { }
    }

    Context "Local execution (Default parameter set)" {
        It "Should return DellCommandResult object with correct type" {
            Mock Test-Path { $true } -ParameterFilter { $Path -eq "C:\Program Files\Dell\CommandUpdate\dcu-cli.exe" }

            $result = Confirm-DellCommandExists

            $result | Should -BeOfType [DellCommandResult]
            $result.ComputerName | Should -Be $env:COMPUTERNAME
            $result.Exists | Should -Be $true
            $result.Status | Should -Be ([DellCommandStatus]::Present)
        }

        It "Should attempt installation when Dell Command not found" {
            Mock Test-Path { $false }
            Mock Invoke-WebRequest { }
            Mock Start-Process { }
            Mock Test-Path { $true } -ParameterFilter { $Path -eq "C:\Program Files\Dell\CommandUpdate\dcu-cli.exe" }

            $result = Confirm-DellCommandExists -WhatIf

            Should -Invoke Invoke-WebRequest -Times 0
            $result.Status | Should -Be ([DellCommandStatus]::Failed)
        }
    }

    Context "Remote execution (ComputerName parameter set)" {
        It "Should handle single computer name" {
            Mock Invoke-Command { "C:\Program Files\Dell\CommandUpdate\dcu-cli.exe" }

            $result = Confirm-DellCommandExists -ComputerName "TestPC"

            $result | Should -BeOfType [DellCommandResult]
            $result.ComputerName | Should -Be "TestPC"
            $result.Status | Should -Be ([DellCommandStatus]::Present)
            Should -Invoke Invoke-Command -Times 1
        }

        It "Should handle multiple computer names" {
            Mock Invoke-Command { "C:\Program Files\Dell\CommandUpdate\dcu-cli.exe" }

            $results = Confirm-DellCommandExists -ComputerName @("PC1", "PC2")

            $results | Should -HaveCount 2
            $results[0].ComputerName | Should -Be "PC1"
            $results[1].ComputerName | Should -Be "PC2"
            Should -Invoke Invoke-Command -Times 2
        }
    }

    Context "PSSession parameter set" {
        It "Should work with PSSession objects" {
            $mockSession = [PSCustomObject]@{
                ComputerName = "SessionPC"
            }
            Mock Invoke-Command { "C:\Program Files\Dell\CommandUpdate\dcu-cli.exe" }

            $result = Confirm-DellCommandExists -PSSession $mockSession

            $result.ComputerName | Should -Be "SessionPC"
        }
    }

    Context "Parameter validation" {
        It "Should accept custom download URL" {
            $customUrl = "https://custom.url/installer.exe"
            Mock Test-Path { $true } -ParameterFilter { $Path -eq "C:\Program Files\Dell\CommandUpdate\dcu-cli.exe" }

            $result = Confirm-DellCommandExists -DownloadUrl $customUrl

            $result | Should -Not -BeNullOrEmpty
        }

        It "Should accept custom Dell Command version" {
            Mock Test-Path { $true } -ParameterFilter { $Path -eq "C:\Program Files\Dell\CommandUpdate\dcu-cli.exe" }

            $result = Confirm-DellCommandExists -DellCommandVersion "6.0.0"

            $result | Should -Not -BeNullOrEmpty
        }
    }
}

Describe "Get-DellUpdateStatus" {
BeforeEach {
Mock Confirm-DellCommandExists {
return [DellCommandResult]::new("TestPC", $true, "C:\Program Files\Dell\CommandUpdate\dcu-cli.exe", [DellCommandStatus]::Present)
}
Mock Test-Path { $true }
Mock New-Item { }
Mock Invoke-WebRequest { }
Mock Start-Process { }
Mock Get-Content { '<updates><update name="Test Update" type="driver"/></updates>' }
Mock Remove-Item { }
Mock Write-Host { }
Mock Write-Error { }
        # Mock external executable calls using Start-Process instead of call operator
        Mock Start-Process { 
            $global:LASTEXITCODE = 0 
            return "Mock DCU output"
        } -ParameterFilter { $FilePath -like "*dcu-cli.exe*" }
    }

    Context "Basic functionality" {
        It "Should process categories correctly" {

$result = Get-DellUpdateStatus -Categories @([DellCommandCategory]::BIOS, [DellCommandCategory]::Network)

# Should call Confirm-DellCommandExists
Should -Invoke Confirm-DellCommandExists -Times 1
}

It "Should handle missing Categories parameter gracefully" {
            { Get-DellUpdateStatus } | Should -Not -Throw
        }
    }

    Context "XML parsing" {
        It "Should parse XML scan results" {
            $mockXml = @'
<updates>
    <update name="Test BIOS Update" version="1.0" type="BIOS" urgency="Recommended"/>
    <update name="Test Driver Update" version="2.0" type="Driver" urgency="Optional"/>
</updates>
'@
            Mock Get-Content { $mockXml }

            { Get-DellUpdateStatus -Categories @([DellCommandCategory]::BIOS) } | Should -Not -Throw
        }
    }

    Context "Update application" {
        It "Should apply updates when ApplyUpdates switch is used" {
            # Set LASTEXITCODE for successful execution
            $global:LASTEXITCODE = 0

            { Get-DellUpdateStatus -ApplyUpdates -Categories @([DellCommandCategory]::BIOS) } | Should -Not -Throw
        }
    }
}

Describe "Update-DellDrivers" {
BeforeEach {
Mock Get-DellUpdateStatus { }
Mock Test-Path { $true }
        Mock Write-Host { }
        Mock Write-Error { }
        # Set LASTEXITCODE for successful execution scenarios
        $global:LASTEXITCODE = 0
        # Mock external executable calls
        Mock Start-Process { 
            $global:LASTEXITCODE = 0
            return "Mock DCU output" 
        } -ParameterFilter { $FilePath -like "*dcu-cli.exe*" }
    }

    Context "Parameter validation" {
        It "Should accept valid categories" {
$validCategories = @("BIOS", "Chipset", "Network", "Video", "Audio", "Storage", "Application", "Security", "Other")

foreach ($category in $validCategories) {
{ Update-DellDrivers -Category $category } | Should -Not -Throw
}
}

It "Should reject invalid categories" {
{ Update-DellDrivers -Category "InvalidCategory" } | Should -Throw
}
}

Context "Category mapping" {
It "Should map categories correctly" {
Mock Get-DellUpdateStatus { } -ParameterFilter { $Category -eq "BIOS" }

Update-DellDrivers -Category "BIOS"

Should -Invoke Get-DellUpdateStatus
}
}

Context "Dell Command Update presence" {
It "Should check for Dell Command Update installation" {
Mock Test-Path { $false } -ParameterFilter { $Path -eq "C:\Program Files (x86)\Dell\CommandUpdate\dcu-cli.exe" }

Update-DellDrivers -Category "BIOS"

Should -Invoke Write-Error -ParameterFilter { $Message -like "*not installed*" }
}

It "Should proceed when Dell Command Update is found" {
            Mock Test-Path { $true }
            # Mock successful execution
            $global:LASTEXITCODE = 0

            Update-DellDrivers -Category "Network"

            Should -Invoke Write-Host -ParameterFilter { $Object -like "*Checking for Dell updates*" }
        }
    }

Context "Switch parameters" {
It "Should pass switch parameters to Get-DellUpdateStatus" {
Update-DellDrivers -Category "BIOS" -UninstallWhenDone -RebootWhenFinished -Intune -ClassicCore

Should -Invoke Get-DellUpdateStatus -ParameterFilter {
$UninstallWhenDone -and $RebootWhenFinished -and $Intune -and $ClassicCore
}
}
}
}

Describe "Integration Tests" {
Context "End-to-end workflow" {
        BeforeEach {
            Mock Test-Path { $true }
            Mock Invoke-Command { "C:\Program Files\Dell\CommandUpdate\dcu-cli.exe" }
            $global:LASTEXITCODE = 0
            Mock Get-Content { '<updates><update name="Test Update" type="driver"/></updates>' }
            Mock Write-Host { }
        }

It "Should complete full workflow without errors" {
# This tests the integration between all functions
Mock Confirm-DellCommandExists {
return [DellCommandResult]::new("TestPC", $true, "C:\Program Files\Dell\CommandUpdate\dcu-cli.exe", [DellCommandStatus]::Present)
}

{
$confirmed = Confirm-DellCommandExists -ComputerName "TestPC"
Get-DellUpdateStatus -Categories @([DellCommandCategory]::Network)
Update-DellDrivers -Category "Network"
} | Should -Not -Throw
}
}
}

Describe "Error Handling" {
Context "Network failures" {
It "Should handle download failures gracefully" {
Mock Invoke-WebRequest { throw "Network error" }
Mock Test-Path { $false }

$result = Confirm-DellCommandExists

$result.Status | Should -Be ([DellCommandStatus]::Failed)
Should -Invoke Write-Warning -ParameterFilter { $Message -like "*Download or installation failed*" }
}
}

Context "File system errors" {
It "Should handle missing temp directory" {
Mock Test-Path { $false } -ParameterFilter { $Path -eq "C:\Temp\" }
Mock New-Item { }

{ Get-DellUpdateStatus -Categories @([DellCommandCategory]::BIOS) } | Should -Not -Throw
Should -Invoke New-Item -ParameterFilter { $ItemType -eq "Directory" }
}
}
}