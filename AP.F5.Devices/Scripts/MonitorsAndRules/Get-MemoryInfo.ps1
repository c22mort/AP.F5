#==================================================================================
# Script: 	Get-MemoryInfo.ps1
# Date:		01/04/19
# Author: 	Andi Patrick
# Purpose:	Gets F5 Device Memory Info via SNMP returns all as Property Bag
#==================================================================================

# Get the named parameters
Param(
	$Debug,
	$SharpSnmpLocation,
	$SNMPAddress,
	$PortNumber,
	$SNMPVersion,
	$SNMPv3UserName,
	$SNMPv3AuthProtocol,
	$SNMPv3AuthPassword,
	$SNMPv3PrivProtocol,
	$SNMPv3PrivPassword,
	$SNMPv3ContextName,
	$CommunityString
)

# Get Start Time For Script
$StartTime = (GET-DATE)

# SNMP Timeout Value
$Timeout = 10000

#Constants used for event logging
$SCRIPT_NAME			= 'Get-MemoryInfo.ps1'
$EVENT_LEVEL_ERROR      = 1
$EVENT_LEVEL_WARNING    = 2
$EVENT_LEVEL_INFO       = 4

$SCRIPT_STARTED             = 14611
$SCRIPT_PROPERTYBAG_CREATED	= 14612
$SCRIPT_EVENT               = 14613
$SCRIPT_ERROR               = 14614
$SCRIPT_ENDED               = 14615

#==================================================================================
# Function:	Get-SnmpV2
# Purpose:	Gets a single SNMP Value
#			Returns  ObjectIdentifier (Id & Data)
#==================================================================================
function Get-SnmpV2
{
    param(
        $reciever,
        [Lextm.SharpSnmpLib.ObjectIdentifier]$oid
    )
    Try {
        # Use SNMP v2
        $ver = [Lextm.SharpSnmpLib.VersionCode]::V2

        # Create OID List
        $oidList = New-Object 'System.Collections.Generic.List[Lextm.SharpSnmpLib.Variable]'                        
        $oidList.Add($oid)

        # Get SNMP Results
    	$results = [Lextm.SharpSnmpLib.Messaging.Messenger]::Get($ver, $reciever, $CommunityString, $oidList, $Timeout)
        $results    


    } Catch {
		# Write Error to Event Log
        $message = "SNMP Error : " + $_
   		Log-Event $SCRIPT_ERROR $EVENT_LEVEL_ERROR $message $true
	}
}

#==================================================================================
# Function:	Get-SnmpV3
# Purpose:	Gets a single SNMP Value
#			Returns Single ObjectIdentifier (Id & Data)
#==================================================================================
function Get-SnmpV3
{
    param(
        $reciever,
        [Lextm.SharpSnmpLib.ObjectIdentifier]$oid
    )
    Try {
        # Use SNMP v3
        $ver = [Lextm.SharpSnmpLib.VersionCode]::V3

        # Create OID List
        $oidList = New-Object 'System.Collections.Generic.List[Lextm.SharpSnmpLib.Variable]'                        
        $oidList.Add($oid)

        # Set SNMP Authorization and Privacy (Currently AES Only)
				Switch ($SNMPv3AuthProtocol)
				{
					'None' {
						$auth = new-object Lextm.SharpSnmpLib.Security.DefaultAuthenticationProvider($SNMPv3AuthPassword)
					}
					'MD5' {
						$auth = new-object Lextm.SharpSnmpLib.Security.MD5AuthenticationProvider($SNMPv3AuthPassword)			
					}
					'SHA' {	
						$auth = new-object Lextm.SharpSnmpLib.Security.SHA1AuthenticationProvider($SNMPv3AuthPassword)			
					}
				}
				Switch ($SNMPv3PrivProtocol)
				{
					'None' {
						$priv = new-object Lextm.SharpSnmpLib.Security.DefaultPrivacyProvider($auth)
					}
					'AES' 
					{
						$priv = new-object Lextm.SharpSnmpLib.Security.AESPrivacyProvider($SNMPv3PrivPassword,$auth)
					}
					'DES' 
					{
						$priv = new-object Lextm.SharpSnmpLib.Security.DESPrivacyProvider($SNMPv3PrivPassword,$auth)
					}
				}

        # Create discovery and Report
        $discovery =  [Lextm.SharpSnmpLib.Messaging.Messenger]::GetNextDiscovery([Lextm.SharpSnmpLib.SnmpType]::GetRequestPdu)
        $report = $discovery.GetResponse($Timeout, $reciever)

        # Create Message Variables
        $NextMessageId = [Lextm.SharpSnmpLib.Messaging.Messenger]::NextMessageId
        $NextRequestId = [Lextm.SharpSnmpLib.Messaging.Messenger]::NextRequestId
        $MaxMessageSize = [Lextm.SharpSnmpLib.Messaging.Messenger]::MaxMessageSize

        # Perform SNMP Request
        [Lextm.SharpSnmpLib.Messaging.ISnmpMessage]$request = New-Object Lextm.SharpSnmpLib.Messaging.GetRequestMessage($ver, $NextMessageId, $NextRequestId, $SNMPv3UserName, $SNMPv3ContextName, $oidList, $priv, $MaxMessageSize, $report)
        # Get Results
        $reply = [Lextm.SharpSnmpLib.Messaging.SnmpMessageExtension]::GetResponse($request, 3500, $reciever)

        # As Long as ther are no errors
        If ($reply.Scope.Pdu.ErrorStatus -eq 0) {
            $reply.Scope.Pdu.Variables
        }               
        # Perform SNMP Request
        [Lextm.SharpSnmpLib.Messaging.ISnmpMessage]$request = New-Object Lextm.SharpSnmpLib.Messaging.GetRequestMessage($ver, $NextMessageId, $NextRequestId, $SNMPv3UserName, $SNMPv3ContextName, $oidList, $priv, $MaxMessageSize, $report)
        
        # Get Results
        $reply = [Lextm.SharpSnmpLib.Messaging.SnmpMessageExtension]::GetResponse($request, 3500, $reciever)
    } Catch {
    	# Write Error to Event Log
        $message = "SNMP Error : " + $_
   		Log-Event $SCRIPT_ERROR $EVENT_LEVEL_ERROR $message $true
    }
}

#==================================================================================
# Sub:		LogEvent
# Purpose:	Logs an informational event to the Operations Manager event log
#			$writeevent by default is debug value
#==================================================================================
function Log-Event
{
	param(
    $eventNo,
    $eventLevel,
    $message,
    $writeEvent = $Debug
    )

	$message = $SNMPAddress + "`r`n" + $message + $option
	if ($writeEvent -eq $true)
	{
		$api.LogScriptEvent($SCRIPT_NAME,$eventNo,$eventLevel,$message)
	}
}

#Start by setting up API object.
$api = New-Object -comObject 'MOM.ScriptAPI'

# Log Startup Message
Log-Event $SCRIPT_STARTED $EVENT_LEVEL_INFO "Collecting Memory Info from F5 Device"

# Load SharpSNMPLib
[void][reflection.assembly]::LoadFrom( (Resolve-Path $SharpSnmpLocation) )
$walkMode = [Lextm.SharpSnmpLib.Messaging.WalkMode]::WithinSubtree

# Create endpoint for SNMP server
$connection = New-Object System.Net.IpEndPoint ([System.Net.IPAddress]::Parse($SNMPAddress), $PortNumber)

# bigipTrafficMgmt.bigipSystem.sysSystem.sysSystemName
$sysSystemName =  New-Object Lextm.SharpSnmpLib.ObjectIdentifier(".1.3.6.1.4.1.3375.2.1.6.1.0")
# bigipTrafficMgmt.bigipSystem.sysHostInfoStat.sysHostMemory.sysHostMemoryTotal
$sysHostMemoryTotal = New-Object Lextm.SharpSnmpLib.ObjectIdentifier(".1.3.6.1.4.1.3375.2.1.7.1.1.0")
# bigipTrafficMgmt.bigipSystem.sysHostInfoStat.sysHostMemory.sysHostMemoryUsed
$sysHostMemoryUsed = New-Object Lextm.SharpSnmpLib.ObjectIdentifier(".1.3.6.1.4.1.3375.2.1.7.1.2.0")

# Get SNMP Data (Version Dependant)
If ($SNMPVersion -eq "3") {
	Try {
		
        # Try To get System Name
        $sysName = (Get-SnmpV3 $connection $sysSystemName).Data
        # Did we Get a Reply
        If ($sysName -eq $null) {

            # Write Warning to Event Log
            Log-Event $SCRIPT_ERROR $EVENT_LEVEL_WARNING "No SNMP Response" $true
		}
		else{
			# Get memory Counters
			$UsedMemorySNMP = Get-SnmpV3 $connection $sysHostMemoryUsed
			$TotalMemorySNMP = Get-SnmpV3 $connection $sysHostMemoryTotal
			# Work If Counter64 or 32
			If ($TotalMemorySNMP.Data.TypeCode -eq "Counter64") {
				$UsedMemory = $UsedMemorySNMP.Data.ToUInt64()
				$TotalMemory = $TotalMemorySNMP.Data.ToUInt64()
			} 
			else 
			{
				$UsedMemory = $UsedMemorySNMP.Data.ToUInt32()
				$TotalMemory = $TotalMemorySNMP.Data.ToUInt32()		
			}
			# Calculate Used Memory Percentage
			[Double]$UsedPercentage = [Math]::Round(($UsedMemory / $TotalMemory) * 100, 1)
			# Write Log message
			$message = "Created Memory Info Property Bag;`r`n"
			$message = $message + "Memory Percentage : " + $UsedPercentage.ToString() + "`r`n"
			Log-Event $SCRIPT_PROPERTYBAG_CREATED $EVENT_LEVEL_INFO $message
			# Create Property Bag
			$bag = $api.CreatePropertyBag()
			$bag.AddValue("TotalMemory", $TotalMemory)
			$bag.AddValue("UsedMemory", $UsedMemory)
			$bag.AddValue("UsedPercentage", $UsedPercentage)
			$bag
		
		}

	} Catch {
		# Log Finished Message
		$message = "SNMPv3 Error : " + $_
		Log-Event $SCRIPT_ERROR $EVENT_LEVEL_ERROR $message $true
	}
} else {
	Try
	{
        # Try To get System Name
        $sysName = (Get-SnmpV2 $connection $sysSystemName).Data
        # Did we Get a Reply
        If ($sysName -eq $null) {

            # Write Warning to Event Log
            Log-Event $SCRIPT_ERROR $EVENT_LEVEL_WARNING "No SNMP Response" $true
		}
		else{
			# Get memory Counters
			$UsedMemorySNMP = Get-SnmpV2 $connection $sysHostMemoryUsed
			$TotalMemorySNMP = Get-SnmpV2 $connection $sysHostMemoryTotal
			# Work If Counter64 or 32
			If ($TotalMemorySNMP.Data.TypeCode -eq "Counter64") {
				$UsedMemory = $UsedMemorySNMP.Data.ToUInt64()
				$TotalMemory = $TotalMemorySNMP.Data.ToUInt64()
			} 
			else 
			{
				$UsedMemory = $UsedMemorySNMP.Data.ToUInt32()
				$TotalMemory = $TotalMemorySNMP.Data.ToUInt32()		
			}
			# Calculate Used Memory Percentage
			[Double]$UsedPercentage = [Math]::Round(($UsedMemory / $TotalMemory) * 100, 1)
			# Write Log message
			$message = "Created Memory Info Property Bag;`r`n"
			$message = $message + "Memory Percentage : " + $UsedPercentage.ToString() + "`r`n"
			Log-Event $SCRIPT_PROPERTYBAG_CREATED $EVENT_LEVEL_INFO $message
			# Create Property Bag
			$bag = $api.CreatePropertyBag()
			$bag.AddValue("TotalMemory", $TotalMemory)
			$bag.AddValue("UsedMemory", $UsedMemory)
			$bag.AddValue("UsedPercentage", $UsedPercentage)
			$bag
		
		}
	} Catch {
		# Log error Message
		$message = "SNMPv2 Error : " + $Error + " : " + $_
		Log-Event $SCRIPT_ERROR $EVENT_LEVEL_ERROR $message $true
	}
}


# Get End Time For Script
$EndTime = (GET-DATE)
$TimeTaken = NEW-TIMESPAN -Start $StartTime -End $EndTime
$Seconds = [math]::Round($TimeTaken.TotalSeconds, 2)

# Log Finished Message
Log-Event $SCRIPT_ENDED $EVENT_LEVEL_INFO "Script Finished. Took $Seconds Seconds to Complete!"