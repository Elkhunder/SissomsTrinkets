# SissomsTrinkets

[![GitHub Release](https://img.shields.io/github/v/release/Elkhunder/SissomsTrinkets?display_name=release&style=flat&label=Latest%20Release&color=blue)](https://github.com/Elkhunder/SissomsTrinkets/releases/latest)  ![GitHub Release](https://img.shields.io/github/v/release/Elkhunder/SissomsTrinkets?style=flat&label=Module%20Version&color=blue)   ![GitHub Release Date](https://img.shields.io/github/release-date/Elkhunder/SissomsTrinkets?display_date=published_at&style=flat&label=Last%20Updated&color=blue)

## Table of Contents

- [Overview](readme.md#-overview)
- [Getting Started](/docs/GettingStarted.md#getting-started)

## 💫 Overview

The **SissomsTrinkets** PowerShell module provides a set of functions designed for remotely managing computers. It includes a range of capabilities, such as managing user profiles, working with BIOS passwords, retrieving system, and user information like Windows version and the currently logged on user. Whether you're automating administrative tasks or handling remote management scenarios, this module offers a streamlined way to perform a variety of operations from a PowerShell console.

## 🔑 Key Features

- **Manage User Profiles**: Add and remove user profiles remotely.

- **BIOS Password Management**: Clear and remove BIOS passwords.

- **System Information Retrieval**: Gather system and hardware details like Windows version, driver info, and hard drive serial numbers.

- **Printer Management**: Query installed printers.

## Getting Started

### Prerequisites

- **PowerShell version 7** or higher is required to use this module.
- **Module Repository**: The module is hosted in a private PowerShell repository located at `\\corefs.med.umich.edu\Shared2\MCIT_Shared\Teams\DES_ALL\PowerShell\PSRepository`.

### Installation

#### Registering the PowerShell Repository

To begin, you’ll need to register the PowerShell repository if you haven’t already. Run the following command to add the repository:

```powershell
Register-PSRepository -Name MMProd -SourceLocation '\\corefs.med.umich.edu\Shared2\MCIT_Shared\Teams\DES_ALL\PowerShell\PSRepository' -InstallationPolicy Trusted
```

This will register the repository, allowing you to install the SissomsTrinkets module from it.

#### Installing the Module

Once the repository is registered, you can install the SissomsTrinkets module using the following command:

```powershell
Install-Module -Name SissomsTrinkets -Repository MMProd -Verbose
```

The `-Verbose` flag will provide detailed output during installation, helping you track the process.

#### Using the Module

Once installed, you can start using the functions within the module. Here’s a quick example of how to view all available functions:

```powershell
Get-Command -Module SissomsTrinkets
```

This will display a list of all the functions included in the module.

#### Getting help

You can access detailed help documentation for any function in the **SissomsTrinkets** module using the `Get-Help` cmdlet. This will provide you with information on function syntax, parameters, and examples.

##### Example: Get Help for a Specific Function

To get help on the **Get-WindowsVersion** function, use the following command:

```powershell
Get-Help Get-WindowsVersion -Full
```

The `-Full` parameter will provide you with complete documentation, including descriptions of the parameters, syntax, and usage examples.

### Functions Overview

The following functions are included in the **SissomsTrinkets** module:

- **Invoke-LocalSPQuery** (Alias)
- **Add-ApplicationShortcut**
- **Clear-BiosPassword**
- **Get-CurrentUser**
- **Get-Driver**
- **Get-HardDriverSerialNumbers**
- **Get-InstalledPrinter**
- **Get-UserProfile**
- [**Get-WindowsVersion**](docs/functions/getwindowsversion.md)
- **Install-Modules**
- **Remove-BiosPassword**
- **Remove-UserProfile**
- **Set-NetworkProfileCategory**
- [**Watch-DeviceStatus**](docs/functions/watchdevicestatus.md)

Each function is designed to support remote management scenarios, from managing user profiles to retrieving system details.

#### Example: Get-WindowsVersion

To retrieve the Windows version of a remote computer, use the following command:

```powershell
Get-WindowsVersion -ComputerName 'RemotePC'
```

This function will return the Windows version details of the specified remote computer.

### Troubleshooting

If you encounter issues with module installation or execution, ensure you have PowerShell version 7 or higher. Additionally, verify that the repository is correctly registered by running:

```powershell
Get-PSRepository
```

<!-- ## 📑 Wiki pages

| Work Area          | Status      | Category      | Owner            | Last Updated |
|--------------------|-------------|---------------|------------------|--------------|
| Getting Started    | In Progress | Documentation | Sissom, Jonathon | 11/07/2024   |
| Functions Overview | In Progress | Documentation | Sissom, Jonathon | 11/07/2024   | -->

<!-- ## 🔗 Relevant links -->
