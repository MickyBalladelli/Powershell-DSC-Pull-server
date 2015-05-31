<#  
.SYNOPSIS  
	Publish-ServerConfigurations

    Generates and deploys MOF configuration files to given servers 

.DESCRIPTION  

	This script generates MOF files and uses Powershell DSC to distribute configurations to given servers
	
	This script contains two cmdlets:
        New-ServerConfigurations
        Export-ServerConfigurations

    This script is generally executed from a DSC enabled PULL server.
	Configuration files will be copied to $env:SystemDrive\Program Files\WindowsPowershell\DscService\Configuration

.PARAMETER Servers
    Array list of target servers that will receive the new configurations

.PARAMETER Thumbprint
    Thumbprint of the Certificate that will be used to decrypt the MOF files, the certificate of this thumbprint must be stored in cert:\LocalMachine\My
    This script will deploy and import the certificate.

.PARAMETER Path
    Working Path where all the temporary files will be created prior to deploying them to their final location. Generally C:\DSC.

.PARAMETER PublicKey
    Name of the Public Key file. Generally a .cer file. This file is expected to be stored in the $Path folder.

.PARAMETER PrivateKey
    Name of the Private Key file. Generally a .pfx file. This file is expected to be stored in the $Path folder.
    To generate the proper certificate, make a copy of the Computer template, and ensure that the Private Key can be exported. 

.PARAMETER PassFile
    A file containing the encrypted password to be used to import the certificate (pfx file defined in PrivateKey) on the target server.
    You can use the following code to generate the password file:

        Function New-PasswordTextFile{
            param([string] $filename)
            read-host -assecurestring | convertfrom-securestring | out-file $filename
        }

        New-PasswordTextFile -filename "c:\dsc\certpass.txt"


.PARAMETER Credential
    Credential used in the MOF configuration file. These credentials will be encrypted in the MOF file and decrypted by the target server.

.NOTES  
	Filename	: Generate-ServerConfigurations.ps1
    Author(s)  	: Micky Balladelli
				  Mehdi Jerbi
.LINK  
    
#> 

Param( [String[]]$Servers = @("DC3"),
       [String]$Thumbprint = "412952E8227BB605417FEB072F4C2F517817B010",
       [String]$ServerURL = "https://pull.ad.local:8080/PSDSCPullServer.svc",
       [String]$Path = "C:\DSC",
       [String]$PublicKey = "PULLPublicKey.cer",
       [String]$Privatekey = "PULLprivatekey.pfx",
       [String]$PassFile = "c:\dsc\certpass.txt",
       [PsCredential]$Credential)

$certPass = get-content $passFile | convertto-securestring 

if ($Credential -eq $null)
{
    $credential = Get-Credential -Message "Please enter credentials required in the configuration" -username "$($ENV:userdomain)\$($ENV:username)"
    if ($credential -eq $null)
    {
        return
    }

}


Configuration ServerConfig {
 
    Param( [String]$GUID,
           [PsCredential]$Credential)
    
    Import-DSCResource -ModuleName cDisk

    Node $AllNodes.NodeName
    {

        LocalConfigurationManager 
        { 
             CertificateId = $node.Thumbprint
             RebootNodeIfNeeded = $false
        } 
                     

		Script GetOSVersion
		{
		    TestScript = {   
                $version = (Get-CimInstance Win32_OperatingSystem).version
				return ([Version] 6.3 -le $version)
			}
		    GetScript = { 
				return @{}
            }
            SetScript = {$a = 1}
   		}
		Registry DisableIPV6
        {
            Ensure = "Present"  
            Key = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\TCPIP6\Parameters"
            ValueName = "DisabledComponents"
            ValueData = "255"
            ValueType = "Dword"
			DependsOn = "[Script]GetOSVersion"
        }
		
		Registry SetNSPIMaxConnections
        {
            Ensure = "Present"  
            Key = "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\NTDS"
            ValueName = "NSPI max sessions per user"
            ValueData = "256"
            ValueType = "Dword"
			DependsOn = "[Script]GetOSVersion"
        }
        Service ShellHWDetection
        {
            Name = "ShellHWDetection"
            StartupType = "Manual"
            State = "Stopped"
            DependsOn = "[Registry]SetNSPIMaxConnections"
        }
        cWaitforDisk Disk0
        {
             DiskNumber = 0
             RetryIntervalSec = 60
             RetryCount = 2
             DependsOn = "[Service]ShellHWDetection"
        }
        cDisk RVolume
        {
             DiskNumber = 0
             DriveLetter = 'R'
             DependsOn = "[cWaitforDisk]Disk0"
        }
        Group Admins
        {
            GroupName = "Administrators"
            MembersToInclude = "Ad\Enterprise Admins"
            Credential = $Credential
        }
        Registry RDPnotDenied
        {
            Ensure = "Present"  
            Key = "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Terminal Server"
            ValueName = "fDenyTSConnections"
            ValueData = "0"
            ValueType = "Dword"
        }
        Registry RDPonlySecureConnections
        {
            Ensure = "Present"  
            Key = "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
            ValueName = "UserAuthentication"
            ValueData = "1"
            ValueType = "Dword"
        }
		Script RDPenableFirewallRules
		{
		    TestScript = { return $true }
		    GetScript = { 
				return @{}
            }
            SetScript = {Enable-NetFirewallRule -DisplayGroup "Remote Desktop"}
   		}
        WindowsFeature WSB
        { 
            Ensure = "Present" 
            Name = "Windows-Server-Backup" 
        }

	}
}

function New-ServerConfigurations
{
    [CmdletBinding()]
    Param( $Path  = "C:\DSC",
           [String[]]$Servers,
           [switch]$Force,
           [PSCredential]$Credential,
           $Thumbprint,
           $Publickey)
    begin
    {
        $configurationsPath = "$path\Configurations"
        $configGenerated = $false
        $targetFiles = "$env:SystemDrive\Program Files\WindowsPowershell\DscService\Configuration"
        
        $dataArray = @()
        if (test-path "$configurationsPath\servers.csv")
        {
            $dataArray += import-csv "$configurationsPath\servers.csv"
        }
    }
    
    process
    {        
        foreach ($server in $Servers)
        { 
            $foundAndDoNotForce = $false
            $superseed = $false
            # Only check if the configuration for the given server has been created if the Force param is not present.
            # If Force is present, always generate new configurations
            if($Force.IsPresent -eq $false)
            {
                foreach ($elem in $dataArray)
                {
                    if ($server -eq $elem.server)
                    {
                        Write-Verbose "Server $server already has a configuration file, use -Force to generate a new file"
                        $foundAndDoNotForce = $true
                        break
                    }
                }
            }
            else
            {
                foreach ($elem in $dataArray)
                {
                    if ($server -eq $elem.server)
                    {
                        Write-Verbose "Found a configuration for $server superseeding with new config file"
                        Remove-Item "$targetFiles\$($elem.guid).mof*" -ErrorAction SilentlyContinue
                        $superseed = $true
                        break
                    }
                }
            }

            
            if ($foundAndDoNotForce -eq $false)
            {
                Write-host "Creating MOF files for $server"

                $GUID = [guid]::NewGuid().ToString()
                
                $strPath = "$Path\$publickey"
 
                $ConfigData = @{
                    AllNodes = @(    
                                    @{  
                                        NodeName = "*"
                                        CertificateFile = "$strPath"
                                        Thumbprint = $thumbprint
                                    },
                                    @{
                                        NodeName=$GUID
                                        CertificateFile = "$strPath"
                                        Thumbprint = $thumbprint
                                    }
                                )
                }
                if ($superseed)
                {
                    foreach ($elem in $dataArray)
                    {
                        if ($server -eq $elem.server)
                        {
                            $elem.GUID = $GUID;
                            break
                        }
                    }
                }
                else
                {
                    $serverData = New-Object PSCustomObject -Property @{
                        GUID = $GUID;
                        Server = $server
                    }
                    $dataArray += $serverData
                }
                $result = ServerConfig -GUID $Guid -Output "$configurationsPath\ServerConfig" -Credential $credential -ConfigurationData $ConfigData
                $serverConfig = "$configurationsPath\ServerConfig"
                $configGenerated = $true        
 
                $result = New-DSCCheckSum -ConfigurationPath $serverConfig -OutPath $serverConfig -Force -Verbose
 
            }
        }
 
    }
    end
    {
        if ($configGenerated)
        {
            Write-Verbose "Copying configurations to DSC service configuration store..."
            $sourceFiles = "$configurationsPath\ServerConfig\*.mof*"
            Move-Item $sourceFiles $targetFiles -Force -Verbose
            Remove-Item $sourceFiles 
        }
        $dataArray | select Server, GUID | Export-Csv "$configurationsPath\Servers.csv" -NoTypeInformation

        return [array]$dataArray
    }
}
 

function Export-ServerConfigurations
{
    [CmdletBinding()]
    Param( $path = "C:\DSC",
           [String[]]$servers,
           $CertPass,
           $thumbprint,
           $privatekey,
           [array]$configurations,
           $serverURL)
    begin
    {
    }
    process
    {
        # Distribute the new configurations
        foreach ($server in $servers)
        {
            $alive = Test-connection $server -Quiet -Count 1

            if ($alive)
            {
                write-host "Deploying configuration to $server"
                # Ensure the certificate is installed on the remote server
                [array] $Thumbprints = Invoke-Command -ComputerName $server -ArgumentList @($thumbprint) -ScriptBlock {
                    $thumbprint = $args[0]
                    (dir Cert:\LocalMachine\My) | %{
                                         # Verify the certificate is for Encryption and valid
                                         if ($_.thumbprint -eq $thumbprint)
                                         {
                                             $_.Thumbprint
                                         }
                                     }
                }

                $Thumbprints
                $found = $Thumbprints | ? { $_ -eq $thumbprint}
 
                if ($found -eq $null)
                {
                    write-host "Certificate (thumbprint: $thumbprint) required to decrypt the configuration file is missing on $server, copying file"
 
                    copy-Item "$path\$privatekey" "\\$server\c$\temp\$privatekey"
                    Invoke-Command -ComputerName $server -ArgumentList @($privatekey,$certpass) -ScriptBlock  {
                        $cert = $args[0]
                        $pass = $args[1]
                        Import-PfxCertificate –FilePath "c:\temp\$cert" cert:\localMachine\my -Password $pass
                    }
                    Remove-Item "\\$server\c$\temp\$privatekey"
                }
 
                $GUID = ($configurations | where-object {$_."Server" -eq $server}).GUID
                Write-Verbose "Configuration ID for $Server is $GUID"

                Invoke-Command -ComputerName $server -ArgumentList @($GUID,$thumbprint,$serverURL) -ScriptBlock {
                    Configuration DiscoverConfigurationForPull
                    {
 
                        Param([String]$GUID,
                              [String]$thumbprint,
                              [String]$serverURL)
                    
                        $serverURLhashtable = @{ServerUrl = "$serverURL"}
                        LocalConfigurationManager
                        {
                            ConfigurationID = $GUID;
                            CertificateId = $thumbprint;
                            RefreshMode = "PULL";
                            DownloadManagerName = "WebDownloadManager";
                            RebootNodeIfNeeded = $true;
                            RefreshFrequencyMins = 30;
                            ConfigurationModeFrequencyMins = 30;
                            ConfigurationMode = "ApplyAndAutoCorrect";
                            DownloadManagerCustomData = @{ServerUrl = "$serverURL"}
                        }
                    }  
 
                    $GUID = $args[0]
                    $thumbprint = $args[1]
                    $serverURL = $args[2]

                    $localConfig = Get-DscLocalConfigurationManager
                    if ($localconfig.ConfigurationID -ne $GUID)
                    {
                        $result = DiscoverConfigurationForPull -GUID $GUID -thumbprint $thumbprint -serverURL $serverURL -Output "."
                        $FilePath = (Get-Location -PSProvider FileSystem).Path + "\DiscoverConfigurationForPull"
                
                        Set-DscLocalConfigurationManager -ComputerName "localhost" -Path $FilePath -Verbose    
                    }
                    else
                    {
                        Write-Error "This configuration is already deployed (Configuration ID = $GUID)"
                    }
                }
            }
            else
            {
                write-host "Server $server is not reachable" -foreground red 
            }
        }
    }
    end
    {
    }
}
 
[array] $configurations = New-ServerConfigurations -path $path -Servers $Servers -Credential $credential -thumbprint $thumbprint -publickey $publicKey -Verbose -Force
 
Export-ServerConfigurations -path $path -Servers $Servers -thumbprint $thumbprint -configurations $configurations -privatekey $privatekey -CertPass $certPass -serverURL $serverURL -Verbose
