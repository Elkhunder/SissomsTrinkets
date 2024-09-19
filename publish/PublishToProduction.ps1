function Publish-ToProduction {
    [CmdletBinding()]
    param (
        
    )
    
    begin {
        # Check for production repository
        $productionRepositoryPath = "\\corefs.med.umich.edu\Shared2\MCIT_Shared\Teams\DES_ALL\PowerShell\PSRepository"
        $productionRepository = Get-PSRepository -Name MMProd

        if( -not $productionRepository){
            $productionRepositoryInfo = [PSCustomObject]@{
                Name = "MMProd"
                Path = $productionRepositoryPath
            }
            Write-Verbose "Production repository is not set"
            Write-Verbose "Setting production repository:$([Environment]::NewLine) $($productionRepositoryInfo | Out-String)"
            $productionRepositoryInfo | Format-Table | Out-String | Write-Verbose
            
            Register-PSRepository -Name MMProd -PublishLocation $productionRepositoryPath -SourceLocation $productionRepositoryPath -InstallationPolicy Trusted -Verbose
        } else {
            Write-Verbose "Production repository exists, continuing to deployment"
        }
    }
    
    process {
        Publish-Module -Name "C:\Users\jsissom\Development\PowerShell\SissomsTrinkets\dist\SissomsTrinkets\SissomsTrinkets.psd1" -Repository MMProd -Verbose
    }
    
    end {
        
    }
}