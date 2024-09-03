# Watch-DeviceStatus

_The `Watch-DeviceStatus` function monitors the online status of specified computers and sends a notification when a device comes online. It allows users to specify a list of computer names directly or prompt for a file containing computer names. The function runs in the background, continuously checking each device's status at specified intervals and timing out after a set period._

#### Parameters

- **ComputerName**
  - **Description**: Specifies a list of computer names to be monitored. This parameter is mandatory unless the `UseInFile` switch is specified. It accepts an array of strings, allowing multiple computer names to be monitored simultaneously.
  - **Type**: [`String[]`](https://learn.microsoft.com/en-us/powershell/scripting/lang-spec/chapter-04?view=powershell-7.4#431-strings) - An array of string objects.
  - **Mandatory**: `True`

- **UseInFile**
  - **Description**: Indicates that a file containing the list of computer names should be used instead of specifying them directly. Prompts the user to select a file if this switch is used. When this switch is used, the `ComputerName` parameter is bypassed.
  - **Type**: [`Switch`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_functions_advanced_parameters?view=powershell-7.4#switch-parameters) - A Boolean flag that is either true when specified or false when omitted.
  - **Mandatory**: `True`

- **Sound**
  - **Description**: Specifies the type of sounds to be used for the toast notification.  One of the predefined sound types listed in the ValidateSet attribute must be used. This restriction ensures that only valid sound types are assigned to the parameter, helping to prevent errors and maintain consistency.
  - **Type**: [`String`](https://learn.microsoft.com/en-us/powershell/scripting/lang-spec/chapter-04?view=powershell-7.4#431-strings) - An array of string objects.
  - **Default Value**: `'Default'`
  - **Mandatory**: `False`
  - **Accepted Values**
    - `'Default'`
    - `'IM'`
    - `'Mail'`
    - `'Reminder'`
    - `'SMS'`
    - `'Alarm'`
    - `'Alarm2'`
    - `'Alarm3'`
    - `'Alarm4'`
    - `'Alarm5'`
    - `'Alarm6'`
    - `'Alarm7'`
    - `'Alarm8'`
    - `'Alarm9'`
    - `'Alarm10'`
    - `'Call'`
    - `'Call2'`
    - `'Call3'`
    - `'Call4'`
    - `'Call5'`
    - `'Call6'`
    - `'Call7'`
    - `'Call8'`
    - `'Call9'`
    - `'Call10'`

- **IntervalSeconds**
  - **Description**: Specifies the interval, in seconds, between each status check for the computers. This parameter is optional, with a default value of 30 seconds.
  - **Type**: [`Int`](https://learn.microsoft.com/en-us/powershell/scripting/lang-spec/chapter-04?view=powershell-7.4#423-integer) - An integer representing the number of seconds between checks.
  - **Default Value**: `30`
  - **Mandatory**: `False`

- **TimeoutMinutes**
  - **Description**: Specifies the maximum time, in minutes, to wait for a computer to come online before timing out. This parameter is optional, with a default value of 60 minutes.
  - **Type**: [`Int`](https://learn.microsoft.com/en-us/powershell/scripting/lang-spec/chapter-04?view=powershell-7.4#423-integer) - An integer representing the number of minutes to wait before timing out.
  - **Default Value**: `60`
  - **Mandatory**: `False`

#### Examples

1. **Monitor Specific Computers**

   Monitors the online status of the specified computers, checking every 30 seconds, with a timeout of 60 minutes:

   ```powershell
   Watch-DeviceStatus -ComputerName 'Computer1', 'Computer2'
   ```

2. **Use a File for Computer Names**

    Prompts the user to select a file containing the list of computers to monitor:

    ```powershell
    Watch-DeviceStatus -UseInFile
    ```

3. **Specify Custom Interval and Timeout**

    Monitors the online status of the specified computers, checking every 10 seconds, with a timeout of 30 minutes:

    ```powershell
    Watch-DeviceStatus -ComputerName 'Computer1' -IntervalSeconds 10 -TimeoutMinutes 30
    ```

4. **Monitor Computers with a File and Custom Settings**

    Prompts the user to select a file containing the list of computers, checking every 20 seconds, with a timeout of 45 minutes:

    ```powershell
    Watch-DeviceStatus -UseInFile -IntervalSeconds 20 -TimeoutMinutes 45
    ```

<!-- 5. **Managing Jobs Created by Watch-DeviceStatus**

Since Watch-DeviceStatus runs in the background using jobs, you can manage these jobs with the following cmdlets:

- **View Active Jobs**: List all active jobs create by `Watch-DeviceStatus`

    ```powershell
    Get-Job -Name "Monitor_*"
    ```

- **View Job Details**: Get detailed information about a specific job

    ```powershell
    Get-Job -Name "Monitor_Computer1" | Format-List *
    ```

- **Receive Job Output**: Retrieve the output of a completed job

    ```powershell
    Receive-Job -Name "Monitor_Computer1"
    ```

    **Note**: If you want to retrieve the output without clearing it from the job, use the `-Keep` parameter

    ```powershell
    Receive-Job -Name "Monitor_Computer1" -Keep
    ```

- **Stop a Running Job**: If you need to stop a monitoring job before it completes

    ```powershell
    Stop-Job -Name "Monitor_Computer1"
    ```

- **Remove Completed Jobs**: Clean up jobs that have finished

    ```powershell
    Get-Job -Name "Monitor_*" | Where-Object { $_.State -eq 'Completed'} | Remove-Job
    ```

- **Wait for Job to Complete and Automate Cleanup**: Wait for a job to complete, write it's output to the console, and cleanup the completed job

    ```powershell
    Get-Job -Name 'Monitor_Computer1' | Receive-Job -Wait -AutoRemove | Write-Output
    ```

- **Wait for Job to Complete and Automate Cleanup for All Jobs**: Get all jobs, wait for all jobs to complete, write it's output to the console and cleanup the completed job

    ```powershell
    Get-Job -Name 'Monitor_*' | Foreach-Object {
        Receive-Job -Job $_ -Wait -AutoRemove | Write-Output
    }
    ``` -->

#### Notes

- The function runs in the background using jobs, allowing you to monitor multiple devices simultaneously.
- Notifications are sent using the BurntToast module on Windows systems. On non-Windows systems, the notification message is written to the console.
- Use Get-Job to view the status of the monitoring jobs, Receive-Job to retrieve the results, and Remove-Job to clean up completed jobs.