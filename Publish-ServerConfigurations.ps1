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

Param( [String[]]$Servers = @("DC2","DC3"),
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
}


Configuration ServerConfig {
 
    Param( [String]$GUID,
           [PsCredential]$Credential)
    
    Import-DSCResource -ModuleName xNetworking

    Node $AllNodes.NodeName
    {

        LocalConfigurationManager 
        { 
             CertificateId = $node.Thumbprint
        } 

        File CopyFile 
        {
            Ensure = "Present"
            Type = "Directory"
            Recurse = $True
            SourcePath = "\\pull.ad.local\DSC\Sources"
            DestinationPath = "C:\Temp\DSCTest"
            Credential = $Credential
        }

        Log AfterCopyFile
        {
            # The message below gets written to the Microsoft-Windows-Desired State Configuration/Analytic log
            Message = "DSC Resource with ID - exampleFile - is DONE"
            DependsOn = "[File]CopyFile" 
        }
                     
        xFirewall Firewall 
        { 
            Name                  = "Micky" 
            DisplayName           = "Firewall Rule for my Special App" 
            DisplayGroup          = "Special App Rule Group" 
            Ensure                = "Present" 
            Access                = "Allow" 
            State                 = "Enabled" 
            Profile               = ("Domain", "Private") 
            Direction             = "Inbound"
            RemotePort            = ("8080", "8081") 
            LocalPort             = ("9080", "9081")          
            Protocol              = "TCP" 
            Description           = "Firewall Rule for Special App"   
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
		Script TestPorts
		{
		    TestScript = { return $true # for now

				$tcpports = @(135,137,139,389,636,3268,3269,53,88,445,42,1512)
				$udpports = @(137,138,139,389,53,88,1512,123)
				
				foreach ($port in $tcpports)
				{
    				$Socket = New-Object Net.Sockets.TcpClient
					$Socket.Connect("localhost", $port)
					if ($Socket.Connected -eq $false)
					{
						return $false
					}
					else
					{
						$Socket.Close()
					}
				}
				foreach ($port in $udpports)
				{
    				$Socket = New-Object Net.Sockets.UdpClient
					$Socket.Connect("localhost", $port)
					if ($Socket.Connected -eq $false)
					{
						return $false
					}
					else
					{
						$Socket.Close()
					}
				}
				return $true
    
			}
		    GetScript = { 
				return @{}
            }

            SetScript = { $a = 1 }
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
	    
        if ($Force)
        {
            Write-Verbose "Cleaning up old config files"
            Remove-Item "$targetFiles\*.mof*" -ErrorAction SilentlyContinue
            if (test-path "$configurationsPath\servers.csv")
		    {
		        remove-item "$configurationsPath\servers.csv"
		    }
            $dataArray = @()
        }
        else
        {
            if (test-path "$configurationsPath\servers.csv")
		    {
		        $dataArray = import-csv "$configurationsPath\servers.csv" -header("Server","GUID")
		    }
        }
	}
	
	process
	{		 
		foreach ($server in $Servers)
		{
    		Write-host "Creating MOF files for $server"

			$found = $false
			# Only check if the configuration for the given server has been created if the Force param is not present.
			# If Force is present, always generate new configurations
			if($Force -eq $false)
			{
				foreach ($elem in $dataArray)
				{
					if ($server -eq $elem.server)
					{
                        Write-Verbose "Server $server already has a configuration file, use -Force to generate a new file"
						$found = $true
						break
					}
				}
			}
			
			if ($found -eq $false)
			{
			    $GUID = [guid]::NewGuid().ToString()
                
                $strPath = "$Path\$publickey"

                $ConfigData = @{ 
                    AllNodes = @(     
                                    @{  
                                        NodeName = "*"
                                        CertificateFile = "$strPath"
                                        Thumbprint = $thumbprint 
                                    } 
                                    @{ 
                                        NodeName=$GUID 
                                        CertificateFile = "$strPath"
                                        Thumbprint = $thumbprint 
                                    } 
                                ) 
                } 
                $serverData = New-Object PSCustomObject -Property @{
                    GUID = $newGUID;
                    Server = $server
                }
			    $newLine = "{0},{1}" -f $server,$newGUID
			    $result = ServerConfig -GUID $newGuid -Output "$configurationsPath\ServerConfig" -Credential $credential -ConfigurationData $ConfigData
			    $newLine | add-content -path "$configurationsPath\Servers.csv"
		        $serverConfig = "$configurationsPath\ServerConfig"
                $configGenerated = $true		 

		        $result = New-DSCCheckSum -ConfigurationPath $serverConfig -OutPath $serverConfig -Force -Verbose

                $dataArray += $serverData
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

            return [array]$dataArray
        }
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
            write-host "Deploying configuration to $server"
            # Ensure the certificate is installed on the remote server
            [array] $Thumbprints = Invoke-Command -ComputerName $server -ScriptBlock {
                (dir Cert:\LocalMachine\My) | %{
                                     # Verify the certificate is for Encryption and valid
                                     if ($_.subject -eq "CN=PULL.ad.local" -and $_.Verify())
                                     {
                                         return $_.Thumbprint
                                     }
                                 }
            }
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
                $result = DiscoverConfigurationForPull -GUID $GUID -thumbprint $thumbprint -serverURL $serverURL -Output "."
                $FilePath = (Get-Location -PSProvider FileSystem).Path + "\DiscoverConfigurationForPull"
                
                Set-DscLocalConfigurationManager -ComputerName "localhost" -Path $FilePath -Verbose    
            }
        }
    }
    end 
    {
    }
}

[array] $configurations = Generate-ServerConfigurations -path $path -Servers $Servers -Force -Credential $credential -thumbprint $thumbprint -publickey $publicKey

Export-ServerConfigurations -path $path -Servers $newServers -thumbprint $thumbprint -configurations $configurations -privatekey $privatekey -CertPass $certPass -serverURL $serverURL -Verbose 

