# Requires Pester 5.0 or higher
Import-Module Pester
Import-Module .\dist\SissomsTrinkets -Force

Describe 'Get-WindowsVersion' {

    BeforeAll {
        # Mock the dependencies
        Mock -CommandName 'New-CimSession' -Verifiable
        Mock -CommandName 'Get-CimInstance' -Verifiable
        Mock -CommandName 'Remove-CimSession' -MockWith {}
        Mock -CommandName 'Out-File' -MockWith { param($InputObject, $FilePath) }
        Mock -CommandName 'Test-Connection' -MockWith { return $true }
        Mock -CommandName 'New-PSSession' -MockWith { return $null }
        Mock -CommandName 'Invoke-Command' -MockWith {
            return @(@{
                Caption = "Microsoft Windows 10 Pro"
                BuildNumber = "19041"
                Username = "testuser"
            }, @{})
        }
    }

    It 'Should retrieve Windows version information for specified computers' {
        $result = Get-WindowsVersion -ComputerName 'localhost'

        $result | Should -Not -BeNullOrEmpty
        $result | Should -HaveCount 1
        $result[0].Computer | Should -Be 'localhost'
        $result[0].'OS Name' | Should -Be 'Microsoft Windows 11 Enterprise'
        $result[0].'OS Version' | Should -Be '22H2'
        $result[0].'Current User' | Should -Be 'none'
    }

    It 'Should handle local queries' {
        $result = Get-WindowsVersion -Local

        $result | Should -Not -BeNullOrEmpty
        $result[0].'OS Name' | Should -Be 'Microsoft Windows 11 Enterprise'
    }

    It 'Should save results to a file when UseOutFile is specified' {
        $testPath = "$TestDrive\output.txt"
        Get-WindowsVersion -ComputerName 'localhost' -OutFile $testPath
        if (Test-Path -Path $testPath){
            Write-Host "Path exists"
            $content = Get-Content -Path $testPath

            # Initialize an empty hashtable to store the parsed properties
            $properties = @{}

            # Iterate over each line in the content
            foreach ($line in $content) {
                # Split the line at the first occurrence of ':'
                $parts = $line -split ':\s+', 2

                # Ensure there are exactly two parts (a key and a value)
                if ($parts.Count -eq 2) {
                    # Store the key-value pair in the hashtable
                    $properties[$parts[0].Trim()] = $parts[1].Trim()
                }
            }

            # Convert the hashtable to a PSCustomObject
            $psCustomObject = [PSCustomObject]$properties

            $psCustomObject.Computer | Should -Be 'localhost'
            $psCustomObject.'OS Name' | Should -Be 'Microsoft Windows 11 Enterprise'
            $psCustomObject.'OS Version' | Should -Be '22H2'
            $psCustomObject.'Current User' | Should -Be 'None'
        }
    }

    It 'Should throw an error if both ComputerName and UseInFile are provided' {
        { Get-WindowsVersion -ComputerName 'Server1' -UseInFile } | Should -Throw
    }
}
