#==================================================================================
# Script: 	Get-DiskPartitionInfo.ps1
# Date:			05/06/20
# Author: 	Andi Patrick
# Purpose:	Gets F5 Device Disk Partition Info via SNMP returns all as Property Bag
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
$SCRIPT_NAME			= 'Get-DiskPartitionInfo.ps1'
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
# Function:	Walk-SnmpV2
# Purpose:	Walks an SNMP MIB
#           Returns List of ObjectIdentifier (Id & Data)
#==================================================================================
function Walk-SnmpV2
{
    param(
        $reciever,
        [Lextm.SharpSnmpLib.ObjectIdentifier]$oid
    )
    Try {
        # Use SNMP v2
        $ver = [Lextm.SharpSnmpLib.VersionCode]::V2

        # Set Walk Mode to WithinSubtree
        $walkMode = [Lextm.SharpSnmpLib.Messaging.WalkMode]::WithinSubtree

        # Get Results from SNMP
	    $results = New-Object 'System.Collections.Generic.List[Lextm.SharpSnmpLib.Variable]'
    	[Lextm.SharpSnmpLib.Messaging.Messenger]::Walk($ver, $reciever, $CommunityString, $oid, $results, 3000, $walkMode)

        $results    

    } Catch {
		# Write Error to Event Log
        $message = "SNMP Error : " + $_
   		Log-Event $SCRIPT_ERROR $EVENT_LEVEL_ERROR $message $true
    }
}
#==================================================================================
# Function:	BulkGet-SnmpV3
# Purpose:	Gets a single SNMP Value
#			Returns List of ObjectIdentifier (Id & Data)
#==================================================================================
function BulkGet-SnmpV3
{
    param(
        $reciever,
        [int]$maxRepetitions,
        [Lextm.SharpSnmpLib.ObjectIdentifier]$tableOid
    )
    Try {
        # Use SNMP v3
        $ver = [Lextm.SharpSnmpLib.VersionCode]::V3

        # Create OID List
        $oidList = New-Object 'System.Collections.Generic.List[Lextm.SharpSnmpLib.Variable]'                        
        $oidList.Add($tableOid)

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
        $request = New-Object Lextm.SharpSnmpLib.Messaging.GetBulkRequestMessage($ver, $NextMessageId, $NextRequestId, $SNMPv3UserName, $SNMPv3ContextName, $maxRepetitions,  $oidList, $priv, $MaxMessageSize, $report)
        # Get Results
        $reply = [Lextm.SharpSnmpLib.Messaging.SnmpMessageExtension]::GetResponse($request, 3500, $reciever)

        # As Long as ther are no errors
        If ($reply.Scope.Pdu.ErrorStatus -eq 0) {
            $reply.Scope.Pdu.Variables
        }
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
Log-Event $SCRIPT_STARTED $EVENT_LEVEL_INFO "Collecting Disk Partition Info from F5 Device"

# Load SharpSNMPLib
[void][reflection.assembly]::LoadFrom( (Resolve-Path $SharpSnmpLocation) )
$walkMode = [Lextm.SharpSnmpLib.Messaging.WalkMode]::WithinSubtree

# Create endpoint for SNMP server
$connection = New-Object System.Net.IpEndPoint ([System.Net.IPAddress]::Parse($SNMPAddress), $PortNumber)

# bigipTrafficMgmt.bigipSystem.sysSystem.sysSystemName
$sysSystemName =  New-Object Lextm.SharpSnmpLib.ObjectIdentifier(".1.3.6.1.4.1.3375.2.1.6.1.0")
# bigipTrafficMgmt.bigipSystem.sysHostInfoStat.sysHostDisk.sysHostDiskNumber
$sysHostDiskNumber = New-Object Lextm.SharpSnmpLib.ObjectIdentifier(".1.3.6.1.4.1.3375.2.1.7.3.1.0")
# bigipTrafficMgmt.bigipSystem.sysHostInfoStat.sysHostDisk.sysHostDiskTable.sysHostDiskEntry.sysHostDiskPartition
$sysHostDiskPartition = New-Object Lextm.SharpSnmpLib.ObjectIdentifier(".1.3.6.1.4.1.3375.2.1.7.3.2.1.1")
# bigipTrafficMgmt.bigipSystem.sysHostInfoStat.sysHostDisk.sysHostDiskTable.sysHostDiskEntry.sysHostDiskTotalBlocks
$sysHostDiskTotalBlocks = New-Object Lextm.SharpSnmpLib.ObjectIdentifier(".1.3.6.1.4.1.3375.2.1.7.3.2.1.3")
# bigipTrafficMgmt.bigipSystem.sysHostInfoStat.sysHostDisk.sysHostDiskTable.sysHostDiskEntry.sysHostDiskFreeBlocks
$sysHostDiskFreeBlocks = New-Object Lextm.SharpSnmpLib.ObjectIdentifier(".1.3.6.1.4.1.3375.2.1.7.3.2.1.4")

# Get SNMP Data (Version Dependant)
$DiskPartitionCount = 0
If ($SNMPVersion -eq "3") {
	Try {
	    # Try To get System Name
        $sysName = (Get-SnmpV3 $connection $sysSystemName).Data
        # Did we Get a Reply
        If ($sysName -eq $null) 
		{
            # Write Warning to Event Log
            Log-Event $SCRIPT_ERROR $EVENT_LEVEL_WARNING "No SNMP Response" $true
		}
		else
		{		
			# Get Count of Disk Partitions
			[int]$DiskPartitionCount = (Get-SnmpV3 $connection $sysHostDiskNumber).Data.ToInt32()
			# Get Disk Partition Paths (SNMPv3 0 Based Array)
			$DiskPartitionPaths = BulkGet-SnmpV3 $connection $DiskPartitionCount $sysHostDiskPartition
			# Get Disk Partition TotalBlocks (SNMPv3 0 Based Array)
			$DiskPartitionTotalBlocks = BulkGet-SnmpV3 $connection $DiskPartitionCount $sysHostDiskTotalBlocks
			# Get Disk Partition TotalBlocks (SNMPv3 0 Based Array)
			$DiskPartitionFreeBlocks = BulkGet-SnmpV3 $connection $DiskPartitionCount $sysHostDiskFreeBlocks
			For ($i=0; $i -lt $DiskPartitionCount;$i++){
				If ($DiskPartitionFreeBlocks[$i].Data.TypeCode -eq "Gauge32") {
					# Calculate Disk Free space and used space
					[Double]$DiskFreePercentage = [Math]::Round(($DiskPartitionFreeBlocks[$i].Data.ToUInt32() / $DiskPartitionTotalBlocks[$i].Data.ToUInt32()) * 100, 1)
					[Double]$DiskUsedPercentage = 100 - $DiskFreePercentage
				} else {			
					# Calculate Disk Free space and used space
					[Double]$DiskFreePercentage = [Math]::Round(($DiskPartitionFreeBlocks[$i].Data.ToInt32() / $DiskPartitionTotalBlocks[$i].Data.ToInt32()) * 100, 1)
					[Double]$DiskUsedPercentage = [Math]::Round((100 - $DiskFreePercentage), 1)
				}
				# Write Debug message
				$message = "Created Disk Partition Info Property Bag for "+ $DiskPartitionPaths[$i].Data.ToString() + "`r`n"
				$message = $message + "Free Disk Space % : " + $DiskFreePercentage + "`r`n"
				$message = $message + "Used Disk Space % : " + $DiskUsedPercentage + "`r`n"
				Log-Event $SCRIPT_PROPERTYBAG_CREATED $EVENT_LEVEL_INFO $message
				# Create Property bag
				$bag = $api.CreatePropertyBag()
				$bag.AddValue("Path", $DiskPartitionPaths[$i].Data.ToString())
				$bag.AddValue("UsedSpacePercentage", $DiskUsedPercentage)
				$bag.AddValue("FreeSpacePercentage", $DiskFreePercentage)
				$bag
			}
		}
	} Catch {
		# Log Finished Message
		$message = "SNMPv3 Error : " + $_
		Log-Event $SCRIPT_ERROR $EVENT_LEVEL_ERROR $message
	}
} else {
	Try {
	    # Try To get System Name
        $sysName = (Get-SnmpV2 $connection $sysSystemName).Data
        # Did we Get a Reply
        If ($sysName -eq $null) 
		{
            # Write Warning to Event Log
            Log-Event $SCRIPT_ERROR $EVENT_LEVEL_WARNING "No SNMP Response" $true
		}
		else
		{		

			# Get Count of Disk Partitions
			[int]$DiskPartitionCount = (Get-SnmpV2 $connection $sysHostDiskNumber).Data.ToInt32()
			# Get Disk Partition Paths (SNMPv2 1 Based Array)
			$DiskPartitionPaths = Walk-SnmpV2 $connection $sysHostDiskPartition
			# Get Disk Partition TotalBlocks (SNMPv2 1 Based Array)
			$DiskPartitionTotalBlocks = Walk-SnmpV2 $connection $sysHostDiskTotalBlocks
			# Get Disk Partition TotalBlocks (SNMPv2 1 Based Array)
			$DiskPartitionFreeBlocks = Walk-SnmpV2 $connection $sysHostDiskFreeBlocks
		
			For ($i=1; $i -le $DiskPartitionCount;$i++){
				If ($DiskPartitionFreeBlocks[$i].Data.TypeCode -eq "Gauge32") {
					# Calculate Disk Free space and used space
					[Double]$DiskFreePercentage = [Math]::Round(($DiskPartitionFreeBlocks[$i].Data.ToUInt32() / $DiskPartitionTotalBlocks[$i].Data.ToUInt32()) * 100, 1)
					[Double]$DiskUsedPercentage = 100 - $DiskFreePercentage
				} else {			
					# Calculate Disk Free space and used space
					[Double]$DiskFreePercentage = [Math]::Round(($DiskPartitionFreeBlocks[$i].Data.ToInt32() / $DiskPartitionTotalBlocks[$i].Data.ToInt32()) * 100, 1)
					[Double]$DiskUsedPercentage = [Math]::Round((100 - $DiskFreePercentage), 1)
				}
				# Write Debug message
				$message = "Created Disk Partition Info Property Bag for "+ $DiskPartitionPaths[$i].Data.ToString() + "`r`n"
				$message = $message + "Free Disk Space % : " + $DiskFreePercentage + "`r`n"
				$message = $message + "Used Disk Space % : " + $DiskUsedPercentage + "`r`n"
				Log-Event $SCRIPT_PROPERTYBAG_CREATED $EVENT_LEVEL_INFO $message
				# Create Property bag
				$bag = $api.CreatePropertyBag()
				$bag.AddValue("Path", $DiskPartitionPaths[$i].Data.ToString())
				$bag.AddValue("UsedSpacePercentage", $DiskUsedPercentage)
				$bag.AddValue("FreeSpacePercentage", $DiskFreePercentage)
				$bag
			}
		}

	} Catch {
		# Log error Message
		$message = "SNMPv2 Error : " + $Error + " : " + $_
		Log-Event $SCRIPT_ERROR $EVENT_LEVEL_ERROR $message
	}
}


# Get End Time For Script
$EndTime = (GET-DATE)
$TimeTaken = NEW-TIMESPAN -Start $StartTime -End $EndTime
$Seconds = [math]::Round($TimeTaken.TotalSeconds, 2)

# Log Finished Message
Log-Event $SCRIPT_ENDED $EVENT_LEVEL_INFO "Script Finished. Took $Seconds Seconds to Complete!"