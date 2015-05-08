<#  
.SYNOPSIS  
	Connect to the PSDSCComplianceService and generate a report in HTML format 
.DESCRIPTION  

.EXAMPLE
.NOTES  
	Filename	: Generate-ServerConfigurations.ps1
    Author(s)  	: Micky Balladelli
				  Mehdi Jerbi
.LINK  
    
#> 

function Get-ComplianceReport
{
  	Param ( [string] $Server = "localhost",
			[string] $Path = ".",
            $credential)

	$Uri = "http://$($server):9080/PSDSCComplianceServer.svc/Status"

	$response = Invoke-WebRequest -Uri $Uri -Method Get -ContentType "application/json" -Headers @{Accept = "application/json"}

	if($response.StatusCode -ne 200)
	{
		Write-Host "Node information was not retrieved." -ForegroundColor Red
	}

	$jsonResponse = ConvertFrom-Json $response.Content
	
	$report = @()
	foreach ($elem in $jsonResponse.value)
	{
		switch ($elem.statuscode)
		{
			0 	{ $status = "Pull operation was successful"}
			1	{ $status = "Download Manager initialization failure"}
			2	{ $status = "Get configuration command failure"}
			3	{ $status = "Unexpected get configuration response from pull server"}
			4	{ $status = "Configuration checksum file read failure"}
			5	{ $status = "Configuration checksum validation failure"}
			6	{ $status = "Invalid configuration file"}
			7	{ $status = "Available modules check failure"}
			8	{ $status = "Invalid configuration Id In meta-configuration"}
			9	{ $status = "Invalid DownloadManager CustomData in meta-configuration"}
			10	{ $status = "Get module command failure"}
			11	{ $status = "Get Module Invalid Output"}
			12	{ $status = "Module checksum file not found"}
			13	{ $status = "Invalid module file"}
			14	{ $status = "Module checksum validation failure"}
			15	{ $status = "Module extraction failed"}
			16	{ $status = "Module validation failed"}
			17	{ $status = "Downloaded module is invalid"}
			18	{ $status = "Configuration file not found"}
			19	{ $status = "Multiple configuration files found"}
			20	{ $status = "Configuration checksum file not found"}
			21	{ $status = "Module not found"}
			22	{ $status = "Invalid module version format"}
			23	{ $status = "Invalid configuration Id format"}
			24	{ $status = "Get Action command failed"}
			25	{ $status = "Invalid checksum algorithm"}
			26	{ $status = "Get Lcm Update command failed"}
			27	{ $status = "Unexpected Get Lcm Update response from pull server"}
			28	{ $status = "Invalid Refresh Mode in meta-configuration"}
			29	{ $status = "Invalid Debug Mode in meta-configuration"}
			default { $status = "Error Code not found"}
		}
		$o = New-Object PSCustomObject -Property @{
				TargetName = $elem.targetname;
				NodeCompliant = $elem.nodecompliant;
				LastComplianceTime = $elem.LastComplianceTime;
                LastHeartBeat = $elem.LastHeartbeatTime;
                Dirty = $elem.dirty;
				Status = $status;
				ConfigurationId = $elem.ConfigurationId;
				ServerChecksum = $elem.ServerChecksum;
			}	
		$report += $o
	}
	
	$head = @'
<style>
BODY{background-color:white;}
TABLE{border-width: 1px;border-style: solid;border-color: black;border-collapse: collapse;}
TH{border-width: 1px;font-family:calibri;font-size:10pt;padding: 3px;border-style: solid;border-color: black;background-color:DarkBlue;color:white}
TD{border-width: 1px;padding: 3px;font-family:calibri;font-size:10pt;border-style: solid;border-color: black;}
</style>
<p>DSC Compliance report</p>
'@
	$html = $report | Select-Object TargetName, NodeCompliant, LastComplianceTime, LastHeartBeat, Dirty, Status, ConfigurationId | Convertto-HTML -Head $head

	$html | %{ 
		if ($_.contains('<td>Not Reachable</td>') -or $_.contains('<td>online</td>') -or $_.contains('<td>OK</td>'))
		{
			$str = $_.replace('<td>Not Reachable</td>','<td bgcolor="#FF0000">Not Reachable</td>') 
			$str = $str.replace('<td>NOT OK</td>','<td bgcolor="#FF0000">NOT OK</td>') 
			$str = $str.replace('<td>offline</td>','<td bgcolor="#FF0000">Offline</td>') 
			$str = $str.replace('<td>online</td>','<td bgcolor="#00FF00">Online</td>') 
			$str.replace('<td>OK</td>','<td bgcolor="#00FF00">OK</td>') 
		}
		else
		{
			$_
		}
		
	} | Out-File "$path\Compliance.html"


} 

#$creds = Get-Credential

Get-ComplianceReport -Server localhost -path "c:\DSC"