Param(
	$SharpSnmpLocation,
	$iControlLocation,
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
$SCRIPT_NAME            = 'Get-DeviceGroups.ps1'
$EVENT_LEVEL_ERROR      = 1
$EVENT_LEVEL_WARNING    = 2
$EVENT_LEVEL_INFO       = 4

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
        $message = "SNMP2 Error : " + $_
   		Log-Event $SCRIPT_ERROR_SNMP2 $EVENT_LEVEL_ERROR $message $true
	}
}

#==================================================================================
# Function:	Get-SnmpV3
# Purpose:	Gets a single SNMP Value
#			      Returns Single ObjectIdentifier (Id & Data)
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
   		Log-Event $SCRIPT_ERROR_SNMP3 $EVENT_LEVEL_ERROR $message $true
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
   		Log-Event $SCRIPT_ERROR_SNMP2 $EVENT_LEVEL_ERROR $message $true
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
   		Log-Event $SCRIPT_ERROR_SNMP3 $EVENT_LEVEL_ERROR $message $true
    }                   
}

#==================================================================================
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
Log-Event $SCRIPT_STARTED $EVENT_LEVEL_INFO "Collecting Device Groups from F5 Devices" $true

# Load SharpSNMPLib
[void][reflection.assembly]::LoadFrom( (Resolve-Path $SharpSnmpLocation) )
[void][reflection.assembly]::LoadFrom( (Resolve-Path $iControlLocation) )

$walkMode = [Lextm.SharpSnmpLib.Messaging.WalkMode]::Default

# Get F5 Devices from SCOM
$scom_f5_devices = Get-SCOMClass -name "AP.F5.Device" | Get-SCOMClassInstance
$message = "Found " + $scom_f5_devices.Count + " F5 Devices"
Log-Event $SCRIPT_EVENT $EVENT_LEVEL_INFO $message $true

# bigipTrafficMgmt.bigipSystem.sysNetwork.sysDevice.sysSysDevice.sysSysDeviceNumber
$sysSysDeviceNumber =  New-Object Lextm.SharpSnmpLib.ObjectIdentifier(".1.3.6.1.4.1.3375.2.1.2.14.1.1.0")
# bigipTrafficMgmt.bigipSystem.sysNetwork.sysDevice.sysSysDevice.sysSysDeviceTable.sysSysDeviceEntry.sysSysDeviceHostname
$sysSysDeviceHostname =  New-Object Lextm.SharpSnmpLib.ObjectIdentifier(".1.3.6.1.4.1.3375.2.1.2.14.1.2.1.4")
# bigipTrafficMgmt.bigipSystem.sysNetwork.sysDevice.sysSysDevice.sysSysDeviceTable.sysSysDeviceEntry.sysSysDeviceChassisId
$sysSysDeviceChassisId =  New-Object Lextm.SharpSnmpLib.ObjectIdentifier(".1.3.6.1.4.1.3375.2.1.2.14.1.2.1.18")
# bigipTrafficMgmt.bigipSystem.sysCM.sysCmSyncStatusDetails.sysCmSyncStatusDetailsNumber
$sysCmSyncStatusDetailsNumber =  New-Object Lextm.SharpSnmpLib.ObjectIdentifier(".1.3.6.1.4.1.3375.2.1.14.2.1.0")
# bigipTrafficMgmt.bigipSystem.sysCM.sysCmSyncStatusDetails.sysCmSyncStatusDetailsTable.sysCmSyncStatusDetailsEntry.sysCmSyncStatusDetailsDetails
$sysCmSyncStatusDetailsDetails =  New-Object Lextm.SharpSnmpLib.ObjectIdentifier(".1.3.6.1.4.1.3375.2.1.14.2.2.1.2")


# Loop Through Devices
Foreach ($f5_device in $scom_f5_devices) {
	$ip = ($f5_device|Select-Object -ExpandProperty *.SNMPAddress).Value
	$port = ($f5_device|Select-Object -ExpandProperty *.SNMPPort).Value
	$version = ($f5_device|Select-Object -ExpandProperty *.SNMPVersion).Value
    $ip
	# Create endpoint for SNMP server
	$connection = New-Object System.Net.IpEndPoint ([System.Net.IPAddress]::Parse($ip), $port)

	If ($version -eq "3") 
	{
		# Try To get Count of Devices
        $deviceCount = (Get-SnmpV3 $connection $sysSysDeviceNumber).Data
        # Did we Get a Reply
        If ($deviceCount -eq $null) 
        {
            # Write Warning to Event Log
            Log-Event $SCRIPT_ERROR_NOSNMP $EVENT_LEVEL_WARNING "No SNMP Response" $true
		} else 
        {
            $deviceCount = $deviceCount.ToInt32()
            # Get Hostnames
            $deviceHostNames = BulkGet-SnmpV3 $connection $deviceCount $sysSysDeviceHostname
            # Get SerialNumbers
            $deviceSerialNumbers = BulkGet-SnmpV3 $connection $deviceCount $sysSysDeviceChassisId

            $deviceArray = @()
            # Create deviceObjects
            For ($i=0;$i -lt $deviceCount;$i++)
            {
                # Get DeviceInfo
                $deviceInfo = @{
                    HostName = $deviceHostNames[$i].Data.ToString();
                    SerialNumber = $deviceSerialNumbers[$i].Data.ToString()                    
				}
                # Create an Object
                $device = New-Object -TypeName PSObject -Property $deviceInfo
                $deviceArray += $device
            }

            # Get Device Groups
            $deviceGroupCount = (Get-SnmpV3 $connection $sysCmSyncStatusDetailsNumber).Data.ToInt32()
            $deviceGroupCount
            $deviceGroups = BulkGet-SnmpV3 $connection $deviceGroupCount $sysCmSyncStatusDetailsDetails
            For ($i=0;$i -lt $deviceGroupCount;$i++) {
                $addToArray = $true
                # Get Device Group Name
                $deviceGroupName =  $deviceGroups[$i].Data.ToString()
                $deviceGroupName = $deviceGroupName.Split(':')[0]
                $deviceGroupName =  $deviceGroupName.Split(' ')[0]
                # Don't Add "device_trust_group"
                If ($deviceGroupName -eq "device_trust_group") 
                {
                    $addToArray = $false
				}
                # Don't Add Device Only
                Foreach ($device in $deviceArray) {
                    If ($device.HostName -eq $deviceGroupName) 
                    {
                        $addToArray = $false                
					}
				}

                If ($addToArray) 
                {
                    $deviceGroup = @{
                        Name = $deviceGroupName;
                        Devices = $deviceArray
			        }               
				}
                
			}

		}
        $deviceGroup
    
	}
	else 
	{
		# Try To get System Name
        $deviceCount = (Get-SnmpV2 $connection $sysSysDeviceNumber).Data
        # Did we Get a Reply
        If ($deviceCount -eq $null) 
        {
            # Write Warning to Event Log
            Log-Event $SCRIPT_ERROR_NOSNMP $EVENT_LEVEL_WARNING "No SNMP Response" $true
		} else 
        {
            $deviceCount = $deviceCount.ToInt32()
            # Get Hostnames
            $deviceHostNames = Walk-SnmpV2 $connection $sysSysDeviceHostname
            # Get SerialNumbers
            $deviceSerialNumbers = Walk-SnmpV2 $connection $sysSysDeviceChassisId

            $deviceArray = @()
            # Create deviceObjects
            For ($i=1;$i -le $deviceCount;$i++)
            {
                # Get DeviceInfo
                $deviceInfo = @{
                    HostName = $deviceHostNames[$i].Data.ToString();
                    SerialNumber = $deviceSerialNumbers[$i].Data.ToString()                    
				}
                # Create an Object
                $device = New-Object -TypeName PSObject -Property $deviceInfo
                $deviceArray += $device
            }

            # Get Device Groups
            $deviceGroupCount = (Get-SnmpV2 $connection $sysCmSyncStatusDetailsNumber).Data.ToInt32()
            $deviceGroupCount
            $deviceGroups = Walk-SnmpV2 $connection $sysCmSyncStatusDetailsDetails
            For ($i=1;$i -le $deviceGroupCount;$i++) {
                $addToArray = $true
                # Get Device Group Name
                $deviceGroupName =  $deviceGroups[$i].Data.ToString()
                $deviceGroupName = $deviceGroupName.Split(':')[0]
                $deviceGroupName =  $deviceGroupName.Split(' ')[0]
                # Don't Add "device_trust_group"
                If ($deviceGroupName -eq "device_trust_group") 
                {
                    $addToArray = $false
				}
                # Don't Add Device Only
                Foreach ($device in $deviceArray) {
                    If ($device.HostName -eq $deviceGroupName) 
                    {
                        $addToArray = $false                
					}
				}

                If ($addToArray) 
                {
                    $deviceGroup = @{
                        Name = $deviceGroupName;
                        Devices = $deviceArray
			        }               
				}
                
			}

		}
        $deviceGroup
	}

}

# Get End Time For Script
$EndTime = (GET-DATE)
$TimeTaken = NEW-TIMESPAN -Start $StartTime -End $EndTime
$Seconds = [math]::Round($TimeTaken.TotalSeconds, 2)

# Log Finished Message
$message = "Script Finished. Took $Seconds Seconds to Complete!"
Log-Event $SCRIPT_ENDED $EVENT_LEVEL_INFO $message $true

