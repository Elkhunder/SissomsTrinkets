function Invoke-LocalSystemProfilerQuery{
    [Alias('Invoke-LocalSPQuery')]
    # Man Page - https://ss64.com/mac/system_profiler.html
    <#
    system_profiler
    Report system hardware and software configuration.
    Syntax
        system_profiler [-usage]

        system_profiler [-listDataTypes]

        system_profiler [-xml] dataType1 ... dataTypeN

        system_profiler [-xml] [-detailLevel level]

    Key:
    -xml                Generate a report in XML format.  If the XML report
                        is redirected to a file with a ".spx" suffix that
                        file can be opened with System Profiler.app.

    -listDataTypes      List the available datatypes.

    -detailLevel level  The level of detail for the report:

                            mini       report with no personal information
                            basic      basic hardware and network information
                            full       all available information

    -usage              Print usage info and examples.
    system_profiler is a replacement for /usr/sbin/AppleSystemProfiler.
    Examples
    Generate a text report with the standard detail level:
    $ system_profiler
    Generate a report of all 32 bit software and save to a text file on the desktop:
    $ system_profiler SPApplicationsDataType | grep -B 6 -A 2 "(Intel): No" > ~/Desktop/non64bit.txt
    Generate a short report containing no personal information:
    $ system_profiler -detailLevel mini
    Show a list of the available data types:
    $ system_profiler -listDataTypes
    Generate a text report containing only software and network data:
    $ system_profiler SPSoftwareDataType SPNetworkDataType
    Create an XML file which can be opened by System Profiler.app:
    $ system_profiler -xml > MyReport.spx
    #>
    [CmdletBinding()]
    param (
        # The data type to retrieve
        [Parameter(ParameterSetName = 'Json')]
        [Parameter(ParameterSetName = 'Xml')]
        [ValidateSet(
            'SPParallelATADataType',
            'SPUniversalAccessDataType',
            'SPSecureElementDataType',
            'SPApplicationsDataType',
            'SPAudioDataType',
            'SPBluetoothDataType',
            'SPCameraDataType',
            'SPCardReaderDataType',
            'SPiBridgeDataType',
            'SPDeveloperToolsDataType',
            'SPDiagnosticsDataType',
            'SPDisabledSoftwareDataType',
            'SPDiscBurningDataType',
            'SPEthernetDataType',
            'SPExtensionsDataType',
            'SPFibreChannelDataType',
            'SPFireWireDataType',
            'SPFirewallDataType',
            'SPFontsDataType',
            'SPFrameworksDataType',
            'SPDisplaysDataType',
            'SPHardwareDataType',
            'SPInstallHistoryDataType',
            'SPInternationalDataType',
            'SPLegacySoftwareDataType',
            'SPNetworkLocationDataType',
            'SPLogsDataType',
            'SPManagedClientDataType',
            'SPMemoryDataType',
            'SPNVMeDataType',
            'SPNetworkDataType',
            'SPPCIDataType',
            'SPParallelSCSIDataType',
            'SPPowerDataType',
            'SPPrefPaneDataType',
            'SPPrintersSoftwareDataType',
            'SPPrintersDataType',
            'SPConfigurationProfileDataType',
            'SPRawCameraDataType',
            'SPSASDataType',
            'SPSerialATADataType',
            'SPSPIDataType',
            'SPSmartCardsDataType',
            'SPSoftwareDataType',
            'SPStartupItemDataType',
            'SPStorageDataType',
            'SPSyncServicesDataType',
            'SPThunderboltDataType',
            'SPUSBDataType',
            'SPNetworkVolumeDataType',
            'SPWWANDataType',
            'SPAirPortDataType'
        )]
        [string]
        $DataType,

        # The level of detail for the report
        [Parameter(ParameterSetName = 'Json')]
        [Parameter(ParameterSetName = 'Xml')]
        [ValidateSet(
            'Mini',
            'Basic',
            'Full'
        )]
        [string]
        $DetailLevel,

        # Lists the available data types
        [Parameter()]
        [switch]
        $ListDataTypes,

        # Prints usage info and examples
        [Parameter()]
        [switch]
        $Usage,

        # Generate a report in XML format
        [Parameter(ParameterSetName = 'Xml')]
        [switch]
        $Xml,

        [Parameter(ParameterSetName = 'Json')]
        [switch]
        $Json,

        [Parameter(ParameterSetName = 'Json')]
        [switch]
        $AsHashTable
    )
    if ($IsWindows){
        throw "This function is only supported on MacOS"
    } elseif ($DataType -and -not $DetailLevel -and -not $Xml -and -not $Json){
        return system_profiler $DataType
    } elseif ($DataType -and $DetailLevel -and -not $Xml -and -not $Json){
        return system_profiler $DataType -DetailLevel $DetailLevel
    } elseif (-not $DataType -and -not $DetailLevel -and $Xml -and -not $Json){
        return (system_profiler -Xml)
    } elseif ($DataType -and -not $DetailLevel -and $Xml -and -not $Json){
        return (system_profiler $DataType -Xml) 
    } elseif (-not $DataType -and $DetailLevel -and $Xml -and -not $Json){
        return (system_profiler -DetailLevel $DetailLevel -Xml)
    } elseif ($DataType -and $DetailLevel -and $Xml -and -not $Json){
        return (system_profiler $DataType -DetailLevel $DetailLevel -Xml)
    } elseif (-not $DataType -and -not $DetailLevel -and -not $Xml -and $Json){
        return (system_profiler -Json | ConvertFrom-Json -AsHashtable:$AsHashTable).$DataType
    } elseif (-not $DataType -and $DetailLevel -and -not $Xml -and $Json){
        return (system_profiler -DetailLevel $DetailLevel -Json | ConvertFrom-Json -AsHashtable:$AsHashTable).$DataType
    } elseif ($DataType -and -not $DetailLevel -and -not $Xml -and $Json){
        return (system_profiler $DataType -Json | ConvertFrom-Json -AsHashtable:$AsHashTable).$DataType
    } elseif ($DataType -and $DetailLevel -and -not $Xml -and $Json){
        return (system_profiler $DataType -DetailLevel $DetailLevel -Json | ConvertFrom-Json -AsHashtable:$AsHashTable).$DataType
    } elseif ($ListDataTypes){
        return system_profiler -ListDataTypes
    } elseif ($Usage){
        return system_profiler -Usage
    }  else {
        return system_profiler
    }
}