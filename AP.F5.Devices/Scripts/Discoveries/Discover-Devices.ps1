#==================================================================================
# Script: 	Discover-Devices.ps1
# Date:		01/04/19
# Author: 	Andi Patrick
# Purpose:	Gets F5 Devices via SNMP returns all as Property Bag
#==================================================================================

# Get the named parameters
Param(
	$Debug,
	$SharpSnmpLocation,
	$sourceId, 
	$managedEntityId, 
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
$SCRIPT_NAME			= 'Discover-Devices.ps1'
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
   		$api.LogScriptEvent($SCRIPT_NAME,$SCRIPT_ERROR_SNMP2,$EVENT_LEVEL_INFO,$message)
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
   		$api.LogScriptEvent($SCRIPT_NAME,$SCRIPT_ERROR_SNMP3,$EVENT_LEVEL_INFO,$message)
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
   		$api.LogScriptEvent($SCRIPT_NAME,$SCRIPT_ERROR_SNMP2,$EVENT_LEVEL_INFO,$message)
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
   		$api.LogScriptEvent($SCRIPT_NAME,$SCRIPT_ERROR_SNMP3,$EVENT_LEVEL_INFO,$message)
    }                   

}
#==================================================================================
# Function:	Get-ResourcePoolName
# Purpose:	Gets the Resource Pool Associated with F5 Network Devices
#==================================================================================
function Get-ResourcePoolName
{
	# Get Network management Nodes
	$Class = Get-SCOMClass -name "System.NetworkManagement.Node"
	# Get F5 Instances
	$Instances = Get-SCOMClassInstance -class $Class | where {($_."[System.NetworkManagement.Node].SystemObjectID").Value -like ".1.3.6.1.4.1.3375*"}
	# Providing we have some instances (which we should as this workflow is targeted to one)
	If ($Instances.Count -gt 0) {
		# Get The Relationship Object
		$Relationship = Get-SCOMRelationship | where {$_.Name -eq "Microsoft.SystemCenter.ManagementActionPointShouldManageEntity"}
		# Get it's ID
		$RelationshipID = $Relationship.Id
		# Get Non Deleted Instances that have this Relationship
		$RelationshipInstances = Get-SCOMRelationshipInstance -TargetInstance:$Instances | Where {$_.RelationshipId -eq $RelationshipID -and $_.IsDeleted -eq $false}
		# Return the Item
		$RelationshipInstances[0].SourceObject.Name
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

	$message = $SNMPAddress + "`r`n" + $message + $option
	if ($writeEvent -eq $true)
	{
		$api.LogScriptEvent($SCRIPT_NAME,$eventNo,$eventLevel,$message)
	}
}

#Start by setting up API object.
$api = New-Object -comObject 'MOM.ScriptAPI'

# Log Startup Message
Log-Event $SCRIPT_STARTED $EVENT_LEVEL_INFO "Started F5 Device Discovery" $true

# Load SharpSNMPLib
[void][reflection.assembly]::LoadFrom( (Resolve-Path $SharpSnmpLocation) )
$walkMode = [Lextm.SharpSnmpLib.Messaging.WalkMode]::WithinSubtree

# Create endpoint for SNMP server
$connection = New-Object System.Net.IpEndPoint ([System.Net.IPAddress]::Parse($SNMPAddress), $PortNumber)

# bigipTrafficMgmt.bigipSystem.sysPlatform.sysGeneral.sysGeneralChassisSerialNum
$sysGeneralChassisSerialNum = New-Object Lextm.SharpSnmpLib.ObjectIdentifier(".1.3.6.1.4.1.3375.2.1.3.3.3.0")
# bigipTrafficMgmt.bigipSystem.sysSystem.sysSystemNodeName
$sysSystemNodeName = New-Object Lextm.SharpSnmpLib.ObjectIdentifier(".1.3.6.1.4.1.3375.2.1.6.2.0")
# bigipTrafficMgmt.bigipSystem.sysProduct.sysProductName
$sysProductName = New-Object Lextm.SharpSnmpLib.ObjectIdentifier(".1.3.6.1.4.1.3375.2.1.4.1.0")
# bigipTrafficMgmt.bigipSystem.sysProduct.sysProductVersion
$sysProductVersion = New-Object Lextm.SharpSnmpLib.ObjectIdentifier(".1.3.6.1.4.1.3375.2.1.4.2.0")
# bigipTrafficMgmt.bigipSystem.sysProduct.sysProductBuild
$sysProductBuild = New-Object Lextm.SharpSnmpLib.ObjectIdentifier(".1.3.6.1.4.1.3375.2.1.4.3.0")
# bigipTrafficMgmt.bigipSystem.sysProduct.sysProductEdition
$sysProductEdition = New-Object Lextm.SharpSnmpLib.ObjectIdentifier(".1.3.6.1.4.1.3375.2.1.4.4.0")
# bigipTrafficMgmt.bigipSystem.sysProduct.sysProductDate
$sysProductDate = New-Object Lextm.SharpSnmpLib.ObjectIdentifier(".1.3.6.1.4.1.3375.2.1.4.5.0")
# bigipTrafficMgmt.bigipSystem.sysPlatform.sysPlatformInfo.sysPlatformInfoMarketingName
$sysPlatformInfoMarketingName = New-Object Lextm.SharpSnmpLib.ObjectIdentifier(".1.3.6.1.4.1.3375.2.1.3.5.2.0")
# bigipTrafficMgmt.bigipSystem.sysPlatform.sysPlatformInfo.sysPlatformInfoName
$sysPlatformInfoName = New-Object Lextm.SharpSnmpLib.ObjectIdentifier(".1.3.6.1.4.1.3375.2.1.3.5.1.0")
# bigipTrafficMgmt.bigipSystem.sysCM.sysCmSyncStatus.sysCmSyncStatusId
$sysCmSyncStatusId = New-Object Lextm.SharpSnmpLib.ObjectIdentifier(".1.3.6.1.4.1.3375.2.1.14.1.1.0")



# Get SNMP Data (Version Dependant)
If ($SNMPVersion -eq "3") {
	Try {
		# Try To Get SerialNumber$
		$Serial = (Get-SnmpV3 $connection $sysGeneralChassisSerialNum)
		$SystemNodeName = (Get-SnmpV3 $connection $sysSystemNodeName)
		$ProductName = (Get-SnmpV3 $connection $sysProductName)
		$ProductVersion = (Get-SnmpV3 $connection $sysProductVersion)
		$ProductBuild = (Get-SnmpV3 $connection $sysProductBuild)
		$ProductEdition = (Get-SnmpV3 $connection $sysProductEdition)
		$ProductDate = (Get-SnmpV3 $connection $sysProductDate)
		$Model = (Get-SnmpV3 $connection $sysPlatformInfoMarketingName)
		# Is Virtual
		$ModelNum = (Get-SnmpV3 $connection $sysPlatformInfoName).Data.ToString()
		$IsVirtual = $false
		If ($ModelNum -eq "Z100") {$IsVirtual = $true}
		# Is Standalone
		$SyncStatus = (Get-SnmpV3 $connection $sysCmSyncStatusId).Data.ToInt32()
		$IsStandalone = $false
		If ($SyncStatus -eq 6) {$IsStandalone = $true}				
	} Catch {
		# Log Finished Message
		$message = "SNMPv3 Error : " + $_
		Log-Event $SCRIPT_ERROR_SNMP3 $EVENT_LEVEL_ERROR $message $true
	}
} else {
	Try {
		$Serial = (Get-SnmpV2 $connection $sysGeneralChassisSerialNum)
		$SystemNodeName = (Get-SnmpV2 $connection $sysSystemNodeName)
		$ProductName = (Get-SnmpV2 $connection $sysProductName)
		$ProductVersion = (Get-SnmpV2 $connection $sysProductVersion)
		$ProductBuild = (Get-SnmpV2 $connection $sysProductBuild)
		$ProductEdition = (Get-SnmpV2 $connection $sysProductEdition)
		$ProductDate = (Get-SnmpV2 $connection $sysProductDate)
		$Model = (Get-SnmpV2 $connection $sysPlatformInfoMarketingName)
		# Is Virtual
		$ModelNum = (Get-SnmpV2 $connection $sysPlatformInfoName).Data.ToString()
		$IsVirtual = $false
		If ($ModelNum -eq "Z100") {$IsVirtual = $true}
		# Is Standalone
		$SyncStatus = (Get-SnmpV2 $connection $sysCmSyncStatusId).Data.ToInt32()
		$IsStandalone = $false
		If ($SyncStatus -eq 6) {$IsStandalone = $true}		
	} Catch {
		# Log error Message
		$message = "SNMPv2 Error : " + $Error + " : " + $_
		Log-Event $SCRIPT_ERROR_SNMP2 $EVENT_LEVEL_ERROR $message $true		
	}
}

# Was There a Valid Return
If ($Serial -eq $null)
{
	# Write Warning to Event Log
    Log-Event $SCRIPT_ERROR_NOSNMP $EVENT_LEVEL_WARNING "No SNMP Response" $true
}
else
{
	Try {
		# Create a New F5 Device Instance
		$DiscoveryData = $api.CreateDiscoveryData(0, $sourceId,  $managedEntityId)
		$instance = $DiscoveryData.CreateClassInstance("$MPElement[Name='AP.F5.Device']$")
		$instance.AddProperty("$MPElement[Name='System!System.Entity']/DisplayName$", $SystemNodeName.Data.ToString())	
		$instance.AddProperty("$MPElement[Name='AP.F5.Device']/DeviceName$", $SystemNodeName.Data.ToString())
		$instance.AddProperty("$MPElement[Name='AP.F5.Device']/SerialNumber$", $Serial.Data.ToString())
		$instance.AddProperty("$MPElement[Name='AP.F5.Device']/SNMPAddress$", $SNMPAddress)
		$instance.AddProperty("$MPElement[Name='AP.F5.Device']/SNMPVersion$", $SNMPVersion)
		$instance.AddProperty("$MPElement[Name='AP.F5.Device']/SNMPPort$", $PortNumber)
		$instance.AddProperty("$MPElement[Name='AP.F5.Device']/ProductName$", $ProductName.Data.ToString())
		$instance.AddProperty("$MPElement[Name='AP.F5.Device']/ProductVersion$", $ProductVersion.Data.ToString())
		$instance.AddProperty("$MPElement[Name='AP.F5.Device']/ProductBuild$", $ProductBuild.Data.ToString())
		$instance.AddProperty("$MPElement[Name='AP.F5.Device']/ProductEdition$", $ProductEdition.Data.ToString())
		$instance.AddProperty("$MPElement[Name='AP.F5.Device']/ProductDate$", $ProductDate.Data.ToString())
		$instance.AddProperty("$MPElement[Name='AP.F5.Device']/Model$", $Model.Data.ToString())
		$instance.AddProperty("$MPElement[Name='AP.F5.Device']/IsVirtual$", $IsVirtual)
		$instance.AddProperty("$MPElement[Name='AP.F5.Device']/IsStandalone$", $IsStandalone)
		$DiscoveryData.AddInstance($instance)

		# Get Associated Resource Pool
		$ResourcePoolName = Get-ResourcePoolName
		# Create Management Action Point Should Manage Entity 
		# So This Object Will be managed by the same Management Servers That Manage the Network Discovery for the F5 Devices
		# If ResourcePoolName is NULL then it is the default All management Servers Pool so we don't need to change it
		if($ResourcePoolName -ne $null)
		{
			$message = "Resource Pool Name : " + $ResourcePoolName
			$api.LogScriptEvent($SCRIPT_NAME,$SCRIPT_EVENT,$EVENT_LEVEL_INFO,$message)
			$oRelSource = $DiscoveryData.CreateClassInstance("$MPElement[Name='SC!Microsoft.SystemCenter.ManagementServiceRuntimePool']$")
			$oRelSource.AddProperty("$MPElement[Name='SC!Microsoft.SystemCenter.ManagementServiceRuntimePool']/Name$", $ResourcePoolName)
			$oRel = $DiscoveryData.CreateRelationshipInstance("$MPElement[Name='SC!Microsoft.SystemCenter.ManagementActionPointShouldManageEntity']$")
			$oRel.Source = $oRelSource
			$oRel.Target = $instance
			$DiscoveryData.AddInstance($oRel)
		} else {
			Log-Event $SCRIPT_EVENT $EVENT_LEVEL_INFO "Resource Pool Name : All Management Servers Pool" $true
		}
		
		$DiscoveryData
	
	} Catch {
		# Log error Message
		$message = "SCOM Discovery Error : " + $_
		Log-Event $SCRIPT_ERROR $EVENT_LEVEL_ERROR $message $true				
	}
}


# Get End Time For Script
$EndTime = (GET-DATE)
$TimeTaken = NEW-TIMESPAN -Start $StartTime -End $EndTime
$Seconds = [math]::Round($TimeTaken.TotalSeconds, 2)

# Log Finished Message
$message = "Script Finished. Took $Seconds Seconds to Complete!"
Log-Event $SCRIPT_ENDED $EVENT_LEVEL_INFO $message $true
