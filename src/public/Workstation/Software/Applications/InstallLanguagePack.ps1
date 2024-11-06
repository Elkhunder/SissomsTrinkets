<#
.SYNOPSIS
Installs the specified language pack(s) on a remote computer and adds the selected language to the current user's language preferences. Additionally, it can provide a formatted list of supported languages when using the `-GetLanguageList` switch.

.DESCRIPTION
The `Install-LanguagePack` function connects to a remote computer, retrieves a list of available language packs, and installs the specified language pack(s). It also updates the current user's language preferences by adding the selected language. The function requires credentials for both the remote session and a shared network drive. Language pack installation is performed using a network drive located at "\\corefs.med.umich.edu\Shared2". Use the `-GetLanguageList` switch for a list of supported languages in a nicely formatted output.

.PARAMETER ComputerName
The name of the remote computer where the language pack will be installed.

.PARAMETER SecondaryCredential
The credentials used for connecting to the remote computer. This is an optional parameter. If not provided, the user will be prompted to enter secondary credentials.

.PARAMETER PrimaryCredential
The credentials used for connecting to a shared network drive. This is an optional parameter. If not provided, the user will be prompted to enter credentials for the shared network location.

.PARAMETER Language
The language pack to be installed. The parameter must be one of the valid languages from the predefined list, such as 'English (United States)', 'Japanese (Japan)', etc. Use the `-GetLanguageList` switch for a full list of supported languages.

.PARAMETER GetLanguageList
Specifies that the function should return a list of supported languages. This list is formatted for easy viewing and helps users quickly identify the available languages. When `-GetLanguageList` is provided, the function outputs only the language list and skips other information.

.EXAMPLE
Install-LanguagePack -ComputerName "RemotePC" -Language "English (United States)"
Installs the "English (United States)" language pack on the remote computer "RemotePC" and sets it as the user's preferred language.

.EXAMPLE
Install-LanguagePack -ComputerName "RemotePC" -Language "French (France)" -SecondaryCredential (Get-Credential) -PrimaryCredential (Get-Credential)
Installs the "French (France)" language pack on the remote computer "RemotePC" with specified credentials for the remote session and shared network drive.

.EXAMPLE
Install-LanguagePack -GetLanguageList
Displays a list of all supported language packs in a nicely formatted output for easy selection.

.NOTES
This function requires PowerShell remoting to be enabled on the target machine and access to the shared network drive for language pack installation.
#>
function Install-LanguagePack {
    param (
      [Parameter(Mandatory, ParameterSetName = "Install")]
      [string]
      $ComputerName,
      [Parameter(ParameterSetName = "Install")]
      [pscredential]
      $SecondaryCredential,
      [Parameter(ParameterSetName = "Install")]
      [pscredential]
      $PrimaryCredential,
      [Parameter(Mandatory, ParameterSetName = "Install")]
      [ValidateSet(
          'Arabic (Saudi Arabia)',
          'Basque (Basque)',
          'Bulgarian (Bulgaria)',
          'Catalan',
          'Chinese (Traditional, Hong Kong SAR)',
          'Chinese (Simplified, China)',
          'Chinese (Traditional, Taiwan)',
          'Croatian (Croatia)',
          'Czech (Czech Republic)',
          'Danish (Denmark)',
          'Dutch (Netherlands)',
          'English (United States)',
          'English (United Kingdom)',
          'Estonian (Estonia)',
          'Finnish (Finland)',
          'French (Canada)',
          'French (France)',
          'Galician',
          'German (Germany)',
          'Greek (Greece)',
          'Hebrew (Israel)',
          'Hungarian (Hungary)',
          'Indonesian (Indonesia)',
          'Italian (Italy)',
          'Japanese (Japan)',
          'Korean (Korea)',
          'Latvian (Latvia)',
          'Lithuanian (Lithuania)',
          'Norwegian, Bokmål (Norway)',
          'Polish (Poland)',
          'Portuguese (Brazil)',
          'Portuguese (Portugal)',
          'Romanian (Romania)',
          'Russian (Russia)',
          'Serbian (Latin, Serbia)',
          'Serbian (Cyrillic, Serbia)',
          'Slovak (Slovakia)',
          'Slovenian (Slovenia)',
          'Spanish (Mexico)',
          'Spanish (Spain)',
          'Swedish (Sweden)',
          'Thai (Thailand)',
          'Turkish (Türkiye)',
          'Ukrainian (Ukraine)',
          'Vietnamese',
          'Afrikaans (South Africa)',
          'Albanian (Albania)',
          'Amharic (Ethiopia)',
          'Armenian (Armenia)',
          'Assamese (India)',
          'Azerbaijani (Latin, Azerbaijan)',
          'Bangla (India)',
          'Belarusian (Belarus)',
          'Bosnian (Latin, Bosnia and Herzegovina)',
          'Cherokee',
          'Filipino',
          'Georgian (Georgia)',
          'Gujarati (India)',
          'Hindi (India)',
          'Icelandic (Iceland)',
          'Irish (Ireland)',
          'Kannada (India)',
          'Kazakh (Kazakhstan)',
          'Khmer (Cambodia)',
          'Konkani (India)',
          'Lao (Laos)',
          'Luxembourgish (Luxembourg)',
          'Macedonian (North Macedonia)',
          'Malay (Malaysia)',
          'Malayalam (India)',
          'Maltese (Malta)',
          'Maori (New Zealand)',
          'Marathi (India)',
          'Nepali (Nepal)',
          'Norwegian, Nynorsk (Norway)',
          'Odia (India)',
          'Persian',
          'Punjabi (India)',
          'Quechua (Peru)',
          'Scottish Gaelic',
          'Serbian (Cyrillic, Bosnia and Herzegovina)',
          'Tamil (India)',
          'Tatar (Russia)',
          'Telugu (India)',
          'Urdu',
          'Uyghur',
          'Uzbek (Latin, Uzbekistan)',
          'Valencian (Spain)',
          'Welsh (Great Britain)'
      )]
      [string]$Language,
      # Returns list of supported Languages
      [Parameter(ParameterSetName = "LanguageList")]
      [switch]
      $GetLanguageList
    )

    process {
      $LanguageList = @(
        'Arabic (Saudi Arabia)',
          'Basque (Basque)',
          'Bulgarian (Bulgaria)',
          'Catalan',
          'Chinese (Traditional, Hong Kong SAR)',
          'Chinese (Simplified, China)',
          'Chinese (Traditional, Taiwan)',
          'Croatian (Croatia)',
          'Czech (Czech Republic)',
          'Danish (Denmark)',
          'Dutch (Netherlands)',
          'English (United States)',
          'English (United Kingdom)',
          'Estonian (Estonia)',
          'Finnish (Finland)',
          'French (Canada)',
          'French (France)',
          'Galician',
          'German (Germany)',
          'Greek (Greece)',
          'Hebrew (Israel)',
          'Hungarian (Hungary)',
          'Indonesian (Indonesia)',
          'Italian (Italy)',
          'Japanese (Japan)',
          'Korean (Korea)',
          'Latvian (Latvia)',
          'Lithuanian (Lithuania)',
          'Norwegian, Bokmål (Norway)',
          'Polish (Poland)',
          'Portuguese (Brazil)',
          'Portuguese (Portugal)',
          'Romanian (Romania)',
          'Russian (Russia)',
          'Serbian (Latin, Serbia)',
          'Serbian (Cyrillic, Serbia)',
          'Slovak (Slovakia)',
          'Slovenian (Slovenia)',
          'Spanish (Mexico)',
          'Spanish (Spain)',
          'Swedish (Sweden)',
          'Thai (Thailand)',
          'Turkish (Türkiye)',
          'Ukrainian (Ukraine)',
          'Vietnamese',
          'Afrikaans (South Africa)',
          'Albanian (Albania)',
          'Amharic (Ethiopia)',
          'Armenian (Armenia)',
          'Assamese (India)',
          'Azerbaijani (Latin, Azerbaijan)',
          'Bangla (India)',
          'Belarusian (Belarus)',
          'Bosnian (Latin, Bosnia and Herzegovina)',
          'Cherokee',
          'Filipino',
          'Georgian (Georgia)',
          'Gujarati (India)',
          'Hindi (India)',
          'Icelandic (Iceland)',
          'Irish (Ireland)',
          'Kannada (India)',
          'Kazakh (Kazakhstan)',
          'Khmer (Cambodia)',
          'Konkani (India)',
          'Lao (Laos)',
          'Luxembourgish (Luxembourg)',
          'Macedonian (North Macedonia)',
          'Malay (Malaysia)',
          'Malayalam (India)',
          'Maltese (Malta)',
          'Maori (New Zealand)',
          'Marathi (India)',
          'Nepali (Nepal)',
          'Norwegian, Nynorsk (Norway)',
          'Odia (India)',
          'Persian',
          'Punjabi (India)',
          'Quechua (Peru)',
          'Scottish Gaelic',
          'Serbian (Cyrillic, Bosnia and Herzegovina)',
          'Tamil (India)',
          'Tatar (Russia)',
          'Telugu (India)',
          'Urdu',
          'Uyghur',
          'Uzbek (Latin, Uzbekistan)',
          'Valencian (Spain)',
          'Welsh (Great Britain)'
      )

      if ($GetLanguageList){
        # Display the language list nicely
        Write-Host "Available Language Packs:"
        $LanguageList | ForEach-Object { Write-Host " - $_" }
        return
      }

      if (-not $PrimaryCredential){
        $PrimaryCredential = $(Get-Credential -UserName "umhs\$([System.Environment]::UserName)" -Message "Enter credentials for \\corefs.med.umich.edu\Shared2")
      }

      if (-not $SecondaryCredential){
        $SecondaryCredential = $(Get-Credential -UserName "umhs\umhs-$([System.Environment]::UserName)" -Message "Enter secondary credentials")
      }

      $LanguageTagLookup = @{
        'Arabic (Saudi Arabia)'                = 'ar-SA'
        'Basque (Basque)'                      = 'eu-ES'
        'Bulgarian (Bulgaria)'                 = 'bg-BG'
        'Catalan'                              = 'ca-ES'
        'Chinese (Traditional, Hong Kong SAR)' = 'zh-HK'
        'Chinese (Simplified, China)'          = 'zh-CN'
        'Chinese (Traditional, Taiwan)'        = 'zh-TW'
        'Croatian (Croatia)'                   = 'hr-HR'
        'Czech (Czech Republic)'               = 'cs-CZ'
        'Danish (Denmark)'                     = 'da-DK'
        'Dutch (Netherlands)'                  = 'nl-NL'
        'English (United States)'              = 'en-US'
        'English (United Kingdom)'             = 'en-GB'
        'Estonian (Estonia)'                   = 'et-EE'
        'Finnish (Finland)'                    = 'fi-FI'
        'French (Canada)'                      = 'fr-CA'
        'French (France)'                      = 'fr-FR'
        'Galician'                             = 'gl-ES'
        'German (Germany)'                     = 'de-DE'
        'Greek (Greece)'                       = 'el-GR'
        'Hebrew (Israel)'                      = 'he-IL'
        'Hungarian (Hungary)'                  = 'hu-HU'
        'Indonesian (Indonesia)'               = 'id-ID'
        'Italian (Italy)'                      = 'it-IT'
        'Japanese (Japan)'                     = 'ja-JP'
        'Korean (Korea)'                       = 'ko-KR'
        'Latvian (Latvia)'                     = 'lv-LV'
        'Lithuanian (Lithuania)'               = 'lt-LT'
        'Norwegian, Bokmål (Norway)'           = 'nb-NO'
        'Polish (Poland)'                      = 'pl-PL'
        'Portuguese (Brazil)'                  = 'pt-BR'
        'Portuguese (Portugal)'                = 'pt-PT'
        'Romanian (Romania)'                   = 'ro-RO'
        'Russian (Russia)'                     = 'ru-RU'
        'Serbian (Latin, Serbia)'              = 'sr-Latn-RS'
        'Serbian (Cyrillic, Serbia)'           = 'sr-Cyrl-RS'
        'Slovak (Slovakia)'                    = 'sk-SK'
        'Slovenian (Slovenia)'                 = 'sl-SI'
        'Spanish (Mexico)'                     = 'es-MX'
        'Spanish (Spain)'                      = 'es-ES'
        'Swedish (Sweden)'                     = 'sv-SE'
        'Thai (Thailand)'                      = 'th-TH'
        'Turkish (Türkiye)'                    = 'tr-TR'
        'Ukrainian (Ukraine)'                  = 'uk-UA'
        'Vietnamese'                           = 'vi-VN'
        'Afrikaans (South Africa)'             = 'af-ZA'
        'Albanian (Albania)'                   = 'sq-AL'
        'Amharic (Ethiopia)'                   = 'am-ET'
        'Armenian (Armenia)'                   = 'hy-AM'
        'Assamese (India)'                     = 'as-IN'
        'Azerbaijani (Latin, Azerbaijan)'      = 'az-Latn-AZ'
        'Bangla (India)'                       = 'bn-IN'
        'Belarusian (Belarus)'                 = 'be-BY'
        'Bosnian (Latin, Bosnia and Herzegovina)' = 'bs-Latn-BA'
        'Cherokee'                             = 'chr-CHER-US'
        'Filipino'                             = 'fil-PH'
        'Georgian (Georgia)'                   = 'ka-GE'
        'Gujarati (India)'                     = 'gu-IN'
        'Hindi (India)'                        = 'hi-IN'
        'Icelandic (Iceland)'                  = 'is-IS'
        'Irish (Ireland)'                      = 'ga-IE'
        'Kannada (India)'                      = 'kn-IN'
        'Kazakh (Kazakhstan)'                  = 'kk-KZ'
        'Khmer (Cambodia)'                     = 'km-KH'
        'Konkani (India)'                      = 'kok-IN'
        'Lao (Laos)'                           = 'lo-LA'
        'Luxembourgish (Luxembourg)'           = 'lb-LU'
        'Macedonian (North Macedonia)'         = 'mk-MK'
        'Malay (Malaysia)'                     = 'ms-MY'
        'Malayalam (India)'                    = 'ml-IN'
        'Maltese (Malta)'                      = 'mt-MT'
        'Maori (New Zealand)'                  = 'mi-NZ'
        'Marathi (India)'                      = 'mr-IN'
        'Nepali (Nepal)'                       = 'ne-NP'
        'Norwegian, Nynorsk (Norway)'          = 'nn-NO'
        'Odia (India)'                         = 'or-IN'
        'Persian'                              = 'fa-IR'
        'Punjabi (India)'                      = 'pa-IN'
        'Quechua (Peru)'                       = 'quz-PE'
        'Scottish Gaelic'                      = 'gd-GB'
        'Serbian (Cyrillic, Bosnia and Herzegovina)' = 'sr-Cyrl-BA'
        'Tamil (India)'                        = 'ta-IN'
        'Tatar (Russia)'                       = 'tt-RU'
        'Telugu (India)'                       = 'te-IN'
        'Urdu'                                 = 'ur-PK'
        'Uyghur'                               = 'ug-CN'
        'Uzbek (Latin, Uzbekistan)'            = 'uz-Latn-UZ'
        'Valencian (Spain)'                    = 'ca-ES-valencia'
        'Welsh (Great Britain)'                = 'cy-GB'
      }
      Write-Host "Getting list of $Language Language Packs..."
      $LanguageTag = $LanguageTagLookup[$Language]
      try {
        $session = New-PSSession -ComputerName $ComputerName -Credential $SecondaryCredential
        $LanguagePacks = Invoke-Command -ArgumentList $LanguageTag -Session $session -ScriptBlock {
          param ($LanguageTag)
            (Get-WindowsCapability -Online |
            Where-Object {
              $_.Name -match "^Language\..*~~~$languageTag~"
            })
        }
        
        # Create psdrive
        Invoke-Command -ArgumentList $primaryCredential -Session $session -ScriptBlock {
          param([pscredential]$credential)
          New-PSDrive -Name "T" -PSProvider FileSystem -Credential $credential -Root "\\corefs.med.umich.edu\Shared2" -Scope Global -Persist
        } 
        $LanguagePacksList = $LanguagePacks | Select-Object -ExpandProperty Name
        Foreach ($LanguagePack in $LanguagePacksList){
          Write-Host "Installing $LanguagePack..."
          try {
            Invoke-Command -ArgumentList $LanguagePack -Session $session -ScriptBlock {
              param ($LanguagePack)
              Add-WindowsCapability -Online -LimitAccess -Name $LanguagePack -Source "T:\MCIT_Shared\Teams\DES_ALL\Utilities\LanguagesAndOptionalFeatures"
            }
            Write-Host "Installing $LanguagePack... complete"
          }
          catch {
            Write-Host "Installing $LanguagePack... Failed"
            Write-Error $_
          }
            
        }
    
        $InstalledLanguagePacks = Invoke-Command -ArgumentList $LanguageTag -Session $session -Scriptblock {
          param ($LanguageTag)
          Get-WindowsCapability -Online |
          Where-Object {
            $_.Name -match "^Language\..*~~~$languageTag~"
          } |
          Where-Object {
            $_.State -eq 'Installed'
          }
        }
    
        if ($LanguagePacks.Length -eq $InstalledLanguagePacks.Length){
          Write-Host "Installing $Language Language Packs...Complete"
        } else {
          # Find out which packs were successfully installed
          $successfulPacks = $InstalledLanguagePacks | Where-Object { $LanguagePacks -contains $_ }
    
          # Find out which packs failed to install
          $failedPacks = $LanguagePacks | Where-Object { $InstalledLanguagePacks -notcontains $_ }
    
          # Display successful installations
          if ($successfulPacks.Count -gt 0) {
              Write-Host "Successfully installed the following packs:"
              $successfulPacks | ForEach-Object { Write-Host $_.Name }
          }
    
          # Display failed installations
          if ($failedPacks.Count -gt 0) {
              Write-Host "Failed to install the following packs:"
              $failedPacks | ForEach-Object { Write-Host $_.Name }
          }
        }
        
    
        Write-Host "Getting current users language preferences..."
        # Get current user language list
        Invoke-Command -ComputerName $ComputerName -Credential $SecondaryCredential -Scriptblock {
          $UserLanguageList = Get-WinUserLanguageList
          Write-Host "Adding $Language to current users language preferences..."
          Write-Host "Setting current users language preferences..."
          # Add target language to user language list
          $UserLanguageList.Add($LanguageTag) | Set-WinUserLanguageList -Force
          Write-Host "Setting current users language preferences...Complete"
        }
      }
      catch {
        throw $_
      }
    }
  }
  
  