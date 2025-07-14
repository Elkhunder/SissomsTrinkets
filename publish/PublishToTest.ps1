function Publish-ToTest {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateSet(
            "Major",
            "Minor",
            "Patch"
        )]
        [string] $VersionLabelToIncrement
    )
    
    begin {
        $VerbosePreference = 'Continue'
        # Check for production repository
        $repositoryName = 'MMTest'
        $testRepositoryPath = "C:\Users\jsissom\Development\PowerShell\PSRepository"
        $testRepository = Get-PSRepository -Name $repositoryName

        if( -not $testRepository){
            $testRepositoryInfo = [PSCustomObject]@{
                Name = $repositoryName
                Path = $testRepositoryPath
            }
            Write-Verbose "Test repository is not set"
            Write-Verbose "Setting test repository:$([Environment]::NewLine) $($testRepositoryInfo | Out-String)"
            $testRepositoryInfo | Format-Table | Out-String | Write-Verbose
            Register-PSRepository -Name $repositoryName -PublishLocation $testRepositoryPath -SourceLocation $testRepositoryPath -InstallationPolicy Trusted -Verbose
        } else {
            Write-Verbose "Production repository exists, continuing to deployment"
        }
    }
    
    process {
        Update-MTModuleVersion -Label $VersionLabelToIncrement -Verbose
        Invoke-MTBuild -Verbose
        Publish-Module -Name "C:\Users\jsissom\Development\PowerShell\SissomsTrinkets\dist\SissomsTrinkets\SissomsTrinkets.psd1" -Repository $repositoryName -Verbose
    }
    
    end {
        
    }
}