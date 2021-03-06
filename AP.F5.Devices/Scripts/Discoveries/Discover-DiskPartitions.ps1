﻿#==================================================================================
# Script: 	Discover-DiskPartitions.ps1
# Date:		03/06/20
# Author: 	Andi Patrick
# Purpose:	Gets F5 Device Disk Partitions via SNMP returns all as Property Bag
#==================================================================================

# Get the named parameters
Param(
	$Debug,
	$SharpSnmpLocation,
	$sourceId, 
	$managedEntityId, 
	$DeviceKey,
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
$SCRIPT_NAME			= 'Discover-DiskPartitions.ps1'
$EVENT_LEVEL_ERROR 		= 1
$EVENT_LEVEL_WARNING 	= 2
$EVENT_LEVEL_INFO 		= 4

$SCRIPT_STARTED             = 14601
$SCRIPT_PROPERTYBAG_CREATED	= 14602
$SCRIPT_EVENT               = 14603
$SCRIPT_ERROR               = 14604
$SCRIPT_ERROR_NOSNMP        = 14605
$SCRIPT_ERROR_SNMP2         = 14606
$SCRIPT_ERROR_SNMP3         = 14607
$SCRIPT_ENDED               = 14608

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
   		Log-Event $SCRIPT_ERROR_SNMP2 $EVENT_LEVEL_INFO $message $true
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
   		Log-Event $SCRIPT_ERROR_SNMP3 $EVENT_LEVEL_INFO $message $true
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
   		Log-Event $SCRIPT_ERROR_SNMP2 $EVENT_LEVEL_INFO $message $true
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
   		Log-Event $SCRIPT_ERROR_SNMP3 $EVENT_LEVEL_INFO $message $true
    }                   

}

##==================================================================================
# Sub:      LogEvent
# Purpose:	Logs an informational event to the Operations Manager event log
#           $writeevent by default is debug value
#==================================================================================
function Log-Event
{
	param(
    $eventNo,
    $eventLevel,
    $message,
    $writeEvent = $Debug
    )

	if ($writeEvent -eq $true)
	{
		$message = $SNMPAddress + "`r`n" + $message + $option
		$api.LogScriptEvent($SCRIPT_NAME,$eventNo,$eventLevel,$message)
	}
}

#Start by setting up API object.
$api = New-Object -comObject 'MOM.ScriptAPI'

# Log Startup Message
Log-Event $SCRIPT_STARTED $EVENT_LEVEL_INFO "Started F5 Disk Partition Discovery" $true

# Load SharpSNMPLib
[void][reflection.assembly]::LoadFrom( (Resolve-Path $SharpSnmpLocation) )
$walkMode = [Lextm.SharpSnmpLib.Messaging.WalkMode]::WithinSubtree

# Create endpoint for SNMP server
$connection = New-Object System.Net.IpEndPoint ([System.Net.IPAddress]::Parse($SNMPAddress), $PortNumber)

# bigipTrafficMgmt.bigipSystem.sysHostInfoStat.sysHostDisk.sysHostDiskTable.sysHostDiskEntry.sysHostDiskPartition
$sysHostDiskPartition = New-Object Lextm.SharpSnmpLib.ObjectIdentifier(".1.3.6.1.4.1.3375.2.1.7.3.2.1.1")
# bigipTrafficMgmt.bigipSystem.sysHostInfoStat.sysHostDisk.sysHostDiskNumber
$sysHostDiskNumber = New-Object Lextm.SharpSnmpLib.ObjectIdentifier(".1.3.6.1.4.1.3375.2.1.7.3.1.0")
# bigipTrafficMgmt.bigipSystem.sysHostInfoStat.sysHostDisk.sysHostDiskTable.sysHostDiskEntry.sysHostDiskBlockSize
$sysHostDiskBlockSize = New-Object Lextm.SharpSnmpLib.ObjectIdentifier(".1.3.6.1.4.1.3375.2.1.7.3.2.1.2")
# bigipTrafficMgmt.bigipSystem.sysHostInfoStat.sysHostDisk.sysHostDiskTable.sysHostDiskEntry.sysHostDiskTotalBlocks
$sysHostDiskTotalBlocks = New-Object Lextm.SharpSnmpLib.ObjectIdentifier(".1.3.6.1.4.1.3375.2.1.7.3.2.1.3")

# Get SNMP Data (Version Dependant)
If ($SNMPVersion -eq "3") {
	Try {

		# Create Discovery Data Object
		$DiscoveryData = $api.CreateDiscoveryData(0, $sourceId,  $managedEntityId)
	
		# Try Getting Disk Count from SNMP
		$DiskCount = (Get-SnmpV3 $connection $sysHostDiskNumber).Data
		If ($DiskCount -eq $null) {

			# Write Warning to Event Log
		    Log-Event $SCRIPT_ERROR_NOSNMP $EVENT_LEVEL_WARNING "No SNMP Response" $true

		}
		else
		{
			[int]$DiskCount = $DiskCount.ToInt32()
			$DiskPaths = BulkGet-SnmpV3 $connection $DiskCount $sysHostDiskPartition
			$DiskBlockSize = BulkGet-SnmpV3 $connection $DiskCount $sysHostDiskBlockSize		
			$DiskTotalBlocks = BulkGet-SnmpV3 $connection $DiskCount $sysHostDiskTotalBlocks
			For($i=0; $i -lt $DiskCount; $i++){
				$Path = $DiskPaths[$i].Data.ToString()
				$Suffix = $DiskPaths[$i].Id.ToString().Replace($sysHostDiskPartition.ToString(),"")
				If ($DiskBlockSize[$i].Data.TypeCode -eq "Gauge32") {
					$Size = $DiskBlockSize[$i].Data.ToUInt32() * $DiskTotalBlocks[$i].Data.ToUInt32()
					$Size = [Math]::Round((($Size / 1024) / 1024) / 1024, 1)
				} else {
					$Size = $DiskBlockSize[$i].Data.ToInt32() * $DiskTotalBlocks[$i].Data.ToInt32()
					$Size = [Math]::Round((($Size / 1024) / 1024) / 1024, 1)			
				}

				# Create a New F5 Device Disk Partition Instance
				$instance = $DiscoveryData.CreateClassInstance("$MPElement[Name='AP.F5.Device.DiskPartition']$")
				$instance.AddProperty("$MPElement[Name='AP.F5.Device']/SerialNumber$", $DeviceKey)
				$instance.AddProperty("$MPElement[Name='AP.F5.Device.DiskPartition']/Path$", $Path)
				$instance.AddProperty("$MPElement[Name='AP.F5.Device.DiskPartition']/Size$", $Size)
				$instance.AddProperty("$MPElement[Name='System!System.Entity']/DisplayName$", $Path)	

				# Add to Discovery Data
				$DiscoveryData.AddInstance($instance)		
		
			}
			$DiscoveryData
		}
	} Catch {
		# Log Finished Message
		$message = "SNMPv3 Error : " + $_
   		Log-Event $SCRIPT_ERROR_SNMP3 $EVENT_LEVEL_INFO $message $true
	}
} else {
	Try {
		# Create Discovery Data Object
		$DiscoveryData = $api.CreateDiscoveryData(0, $sourceId,  $managedEntityId)

		# Try Getting Disk Count from SNMP
		$DiskCount = (Get-SnmpV2 $connection $sysHostDiskNumber).Data
		If ($DiskCount -eq $null) {

			# Write Warning to Event Log
		    Log-Event $SCRIPT_ERROR_NOSNMP $EVENT_LEVEL_WARNING "No SNMP Response" $true

		}
		else
		{
			[int]$DiskCount = $DiskCount.ToInt32()
			$DiskPaths = Walk-SnmpV2 $connection $sysHostDiskPartition
			$DiskBlockSize = Walk-SnmpV2 $connection $sysHostDiskBlockSize		
			$DiskTotalBlocks = Walk-SnmpV2 $connection $sysHostDiskTotalBlocks
			For($i=1; $i -le $DiskCount; $i++){		
				$Path = $DiskPaths[$i].Data.ToString()
				$Suffix = $DiskPaths[$i].Id.ToString().Replace($sysHostDiskPartition.ToString(),"")
				If ($DiskBlockSize[$i].Data.TypeCode -eq "Gauge32") {
					$Size = $DiskBlockSize[$i].Data.ToUInt32() * $DiskTotalBlocks[$i].Data.ToUInt32()
					$Size = [Math]::Round((($Size / 1024) / 1024) / 1024, 1)
				} else {
					$Size = $DiskBlockSize[$i].Data.ToInt32() * $DiskTotalBlocks[$i].Data.ToInt32()
					$Size = [Math]::Round((($Size / 1024) / 1024) / 1024, 1)			
				}
				# Create a New F5 Device Disk Partition Instance
				$instance = $DiscoveryData.CreateClassInstance("$MPElement[Name='AP.F5.Device.DiskPartition']$")
				$instance.AddProperty("$MPElement[Name='AP.F5.Device']/SerialNumber$", $DeviceKey)
				$instance.AddProperty("$MPElement[Name='AP.F5.Device.DiskPartition']/Path$", $Path)
				$instance.AddProperty("$MPElement[Name='AP.F5.Device.DiskPartition']/Size$", $Size)
				$instance.AddProperty("$MPElement[Name='System!System.Entity']/DisplayName$", $Path)	

				# Add to Discovery Data
				$DiscoveryData.AddInstance($instance)
			}
			$DiscoveryData
		}
	} Catch {
		# Log error Message
		$message = "SNMPv2 Error : " + $Error + " : " + $_
   		Log-Event $SCRIPT_ERROR_SNMP2 $EVENT_LEVEL_INFO $message $true
	}
}

# Get End Time For Script
$EndTime = (GET-DATE)
$TimeTaken = NEW-TIMESPAN -Start $StartTime -End $EndTime
$Seconds = [math]::Round($TimeTaken.TotalSeconds, 2)

# Log Finished Message
$message = "Script Finished. Took $Seconds Seconds to Complete!"
Log-Event $SCRIPT_ENDED $EVENT_LEVEL_INFO $message
