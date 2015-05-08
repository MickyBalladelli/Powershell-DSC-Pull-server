$DscServiceModules = "$env:ProgramFiles\WindowsPowershell\DscService\Modules"
New-DscCheckSum -ConfigurationPath $DscServiceModules -OutPath $DscServiceModules -Verbose -Force
