# Get-WindowsVersion

_The `Get-WindowsVersion` function gathers information about the Windows operating system and build versions from specified computers. It allows users to provide a list of computer names directly, or through a file. The function handles local and remote computer queries, supports secondary credentials for remote access, and offers options to output results either to a file or the console._

#### Parameters

- **ComputerName**
  - **Description**: Specifies a list of computer names that the script will operate on. This parameter accepts an array of strings, allowing you to provide multiple computer names to be processed.
  - **Type**: [`String[]`](https://learn.microsoft.com/en-us/powershell/scripting/lang-spec/chapter-04?view=powershell-7.4#431-strings) - An array of string objects
  - **Mandatory**: `True`
- **Credential**
  - **Description**: Provides the credentials used for authentication when connecting to remote computers. This parameter accepts a PSCredential object, which typically includes a username and password.  See Microsoft's docs for [`Get-Credential`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/get-credential?view=powershell-7.4) for more info.  If you attempt to access a remote device without providing a credential, you will be prompted to enter one.
  - **Type**: [`PSCredential`](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.pscredential?view=powershellsdk-7.4.0) - Securely stores a username and password
  - **Mandatory**: `False`
- **UseInFile**
  - **Description**: Indicates that a file containing the list of computer names should be used instead of specifying them directly. Prompts the user to select a file if this switch is used.
  - **Type**: [`Switch`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_functions_advanced_parameters?view=powershell-7.4#switch-parameters) - Boolean flag that is either true when specified or false when omitted
  - **Mandatory**: `True`
- **UseOutFile**
  - **Description**: Indicates that output should be save to a file instead of printed to the console.
  - **Type**: [`Switch`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_functions_advanced_parameters?view=powershell-7.4#switch-parameters) - Boolean flag that is either true when specified or false when omitted
  - **Mandatory**: `False`

#### Examples

- Specify Computer Names

```powershell
Get-WindowsVersion -ComputerName 'Computer1','Computer2','Computer3'
```

- Use a File for Computer Names

```powershell
Get-WindowsVersion -UseInFile
```

- Save the Results to a File

```powershell
Get-WindowsVersion -ComputerName 'Computer1' -UseOutFile
```

- Use a File for Computer Names and Save the Output

```powershell
Get-WindowsVersion -UseInFile -UseOutFile
```

- Get information for localhost

```powershell
Get-WindowsVersion -ComputerName 'localhost'
```