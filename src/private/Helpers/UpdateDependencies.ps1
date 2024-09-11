function Update-Dependencies{
    <#
      .SYNOPSIS
      Installs Script Dependencies.
  
      .DESCRIPTION
      Installs or sets the following script dependencies:
        Sets the Execution Policy
        Sets Repository Installation Policy
        Installs/Updates Package Providers
        Installs Modules
        Imports Installed Modules
      Depencies will only be installed if the necessary params are provided
  
      .PARAMETER ExecutionPolicy
      Specifies the execution policy value
  
      .PARAMETER RepositoryName
      Specifies the repository name to set the installation policy for
  
      .PARAMETER RepositoryPolicy
      Specifies the installation policy for the Repository
  
      .PARAMETER ModuleNames
      Specifies the module names to be verified and installed
  
      .PARAMETER PackageProviders
      Specifies the package providers to install or update
    #>
  
    param(
      [string]$ExecutionPolicy,
      [string]$RepositoryName,
      [string]$RepositoryPolicy,
      [string[]]$ModuleNames,
      [string[]]$PackageProviders,
      [switch]$Verbose
    )
    #Check if package provider parameter was provided
    if($PackageProviders){
      $_nugetUrl = "https://api.nuget.org/v3/index.json"
      $packageSources = Get-PackageSource
      if(@($packageSources).Where{$_.location -eq $_nugetUrl}.count -eq 0){
        Register-PackageSource -Name MyNuGet -Location $_nugetUrl -ProviderName NuGet -Force
      }
      # if(!(Get-PackageProvider -Name))
      foreach($PackageProvider in $PackageProviders){
        #Get locally installed provider version
        if($Verbose){
          Write-Host "Package Provider: $PackageProvider"
          Write-Host "Getting locally installed version ..."
        }
        $LocalVersion = Get-PackageProvider -Name $PackageProvider -Force -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Version
        if($Verbose){
          Write-Host "Locally installed version: $LocalVersion ..."
        }
        #Get most recent version from repository
        if($Verbose){
          Write-Host "Getting version from repository..."
        }
        $RepositoryVersion = Find-PackageProvider -Name $PackageProvider -Force | Select-Object -ExpandProperty Version
        if($Verbose){
          Write-Host "Repository version: $RepositoryVersion ..."
        }
        #Check if local version is less than repository version
        if($LocalVersion -lt $RepositoryVersion){
          #Install package provider from repository and save the version to a variable
          if($Verbose){
            Write-Host "Installing package provider version: $RepositoryVersion ..."
          }
          $InstallationVersion = Install-PackageProvider -Name $PackageProvider -Force
          $InstallationVersion
          $InstallationVersion = $InstallationVersion | Select-Object -ExpandProperty Version
          #Display the package provider version that was installed
          if($Verbose){
            Write-Host "$PackageProvider updated to version: $InstallationVersion ..."
            Write-Host "Importing new version ..."
          }
          #Import newly installed package provider and save version to a variable
          $ImportVersion = Import-PackageProvider -Name $PackageProvider -RequiredVersion $RepositoryVersion -Force
          # | Select-Object -ExpandProperty Version
          #Display the package provider version that was imported
          if($Verbose){
            Write-Host "$PackageProvider Version: $ImportVersion imported successfully ..."
          }
        } else {
          #Display installed version
          if($Verbose){
            Write-Host "$PackageProvider Version: $LocalVersion ..."
          }
        }
      }
    }
    #Check if execution policy parameter was provided
    if($ExecutionPolicy){
      # Check if the Execution Policy is alread set to the specified policy
      if((Get-ExecutionPolicy) -ne $ExecutionPolicy){
        #Set execution policy to specified policy
        Set-ExecutionPolicy $ExecutionPolicy -Force -Scope Process
        Write-Host "Execution Policy: $ExecutionPolicy..."
      } else {
        Write-Host "Execution Policy: $ExecutionPolicy ..."
      }
    }
  
    # Check if repository name parameter was provided
    if($RepositoryName){
      # Check if the repository policy is already set to the specified policy
      if((Get-PSRepository -Name $RepositoryName).InstallationPolicy -ne $RepositoryPolicy){
        #Set repository installation policy to the specified policy
        Set-PSRepository -Name $RepositoryName -InstallationPolicy $RepositoryPolicy
        Write-Host "$RepositoryName Installation Policy: $RepositoryPolicy..."
      } else {
        Write-Host "$RepositoryName Installation Policy: $RepositoryPolicy ..."
      }
    }
  
    #Check if Module Name parameter was provided
    if($ModuleNames){
      foreach($ModuleName in $ModuleNames){
        #Check if specified module is already installed
        if(Get-InstalledModule -Name $ModuleName -ErrorAction SilentlyContinue){
          Write-Host "Module Installed: $ModuleName..."
        } else {
          #Install the specified module
          Install-Module -Name $ModuleName -Scope CurrentUser -AcceptLicense
          Write-Host "Module Installed: $ModuleName..."
        }
        # Check if the specified module is already imported
        if(Get-Module -Name $ModuleName){
          Write-Host "Module Imported: $ModuleName..."
        } else {
          #Import the specified module
          Import-Module $ModuleName
          Write-Host "Module Imported: $ModuleName..."
        }
      }
    }
  }