#==================================================================================
# Script: 	Get-DeviceInfo.ps1
# Date:		05/06/20
# Author: 	Andi Patrick
# Purpose:	Gets F5 Device Info via SNMP returns all as Property Bag
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
$SCRIPT_NAME            = 'Get-DeviceInfo.ps1'
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
   		Log-Event $SCRIPT_ERROR $EVENT_LEVEL_ERROR $message $true
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
Log-Event $SCRIPT_STARTED $EVENT_LEVEL_INFO "Collecting Device Info from F5 Device"

# Load SharpSNMPLib
[void][reflection.assembly]::LoadFrom( (Resolve-Path $SharpSnmpLocation) )
$walkMode = [Lextm.SharpSnmpLib.Messaging.WalkMode]::Default

# Create endpoint for SNMP server
$connection = New-Object System.Net.IpEndPoint ([System.Net.IPAddress]::Parse($SNMPAddress), $PortNumber)

# bigipTrafficMgmt.bigipSystem.sysSystem.sysSystemName
$sysSystemName =  New-Object Lextm.SharpSnmpLib.ObjectIdentifier(".1.3.6.1.4.1.3375.2.1.6.1.0")
# bigipTrafficMgmt.bigipSystem.sysCM.sysCmFailoverStatus.sysCmFailoverStatusId
$sysCmFailoverStatusId =  New-Object Lextm.SharpSnmpLib.ObjectIdentifier(".1.3.6.1.4.1.3375.2.1.14.3.1.0")
# bigipTrafficMgmt.bigipSystem.sysCM.sysCmFailoverStatus.sysCmFailoverStatusStatus
$sysCmFailoverStatusStatus =  New-Object Lextm.SharpSnmpLib.ObjectIdentifier(".1.3.6.1.4.1.3375.2.1.14.3.2.0")
# bigipTrafficMgmt.bigipSystem.sysGlobals.sysGlobalStats.sysGlobalStat.sysStatClientMaxConns5m
$sysStatClientMaxConns5m = New-Object Lextm.SharpSnmpLib.ObjectIdentifier(".1.3.6.1.4.1.3375.2.1.1.2.1.91.0")
# bigipTrafficMgmt.bigipSystem.sysGlobals.sysGlobalStats.sysGlobalStat.sysStatClientBytesIn5m
$sysStatClientBytesIn5m = New-Object Lextm.SharpSnmpLib.ObjectIdentifier(".1.3.6.1.4.1.3375.2.1.1.2.1.88.0")
# bigipTrafficMgmt.bigipSystem.sysGlobals.sysGlobalStats.sysGlobalStat.sysStatClientBytesOut5m
$sysStatClientBytesOut5m = New-Object Lextm.SharpSnmpLib.ObjectIdentifier(".1.3.6.1.4.1.3375.2.1.1.2.1.90.0")
# bigipTrafficMgmt.bigipSystem.sysGlobals.sysGlobalStats.sysGlobalStat.sysStatServerMaxConns5m
$sysStatServerMaxConns5m = New-Object Lextm.SharpSnmpLib.ObjectIdentifier(".1.3.6.1.4.1.3375.2.1.1.2.1.98.0")
# bigipTrafficMgmt.bigipSystem.sysGlobals.sysGlobalStats.sysGlobalStat.sysStatServerBytesIn5m
$sysStatServerBytesIn5m = New-Object Lextm.SharpSnmpLib.ObjectIdentifier(".1.3.6.1.4.1.3375.2.1.1.2.1.95.0")
# bigipTrafficMgmt.bigipSystem.sysGlobals.sysGlobalStats.sysGlobalStat.sysStatServerBytesOut5m
$sysStatServerBytesOut5m = New-Object Lextm.SharpSnmpLib.ObjectIdentifier(".1.3.6.1.4.1.3375.2.1.1.2.1.97.0")

# Pick SNMPv3 or SNMPv2
$FailoverState = 0
If ($SNMPVersion -eq "3") {
    Try{

        # Try To get System Name
        $sysName = (Get-SnmpV3 $connection $sysSystemName).Data
        # Did we Get a Reply
        If ($sysName -eq $null) {

            # Write Warning to Event Log
            Log-Event $SCRIPT_ERROR $EVENT_LEVEL_WARNING "No SNMP Response" $true

            # Create Property Bag
            $message = "Created Device Info Property Bag for "+ $SNMPAddress + "`r`n"
            $message = $message + "SNMP Status : Failed`r`n"
            Log-Event $SCRIPT_PROPERTYBAG_CREATED $EVENT_LEVEL_INFO $message

            # Create Property Bag
            $bag = $api.CreatePropertyBag()
			$bag.AddValue("SnmpState", "Failed")
			$bag
      
        } else {
           
            # Get FailoverState
  		    $FailoverState = (Get-SnmpV3 $connection $sysCmFailoverStatusId).Data
            If ($FailoverState.TypeCode -eq "Counter32") {
                $FailoverStateId = $FailoverState.ToUInt32()      
			} 
            else 
            {
                $FailoverStateId = $FailoverState.ToInt32()            
			}
            $FailoverStateText = (Get-SnmpV3 $connection $sysCmFailoverStatusStatus).Data.ToString()

            # Get Client Side Connection Counters
  		    [int]$ClientSideConnections = (Get-SnmpV3 $connection $sysStatClientMaxConns5m).Data.ToUInt32()

            # Get Client Side Kb In
  	        [int]$ClientSideBytesIn = (Get-SnmpV3 $connection $sysStatClientBytesIn5m).Data.ToUInt32()

            # Get Client Side Kb Out
  		    [int]$ClientSideBytesOut = (Get-SnmpV3 $connection $sysStatClientBytesOut5m).Data.ToUInt32()

            # Get Server Side Connection Counters
            [int]$ServerSideConnections = (Get-SnmpV3 $connection $sysStatServerMaxConns5m).Data.ToUInt32()

            # Get Server Side Kb In
            [int]$ServerSideBytesIn = (Get-SnmpV3 $connection $sysStatServerBytesIn5m).Data.ToUInt32()

            # Get Server Side Kb Out
            [int]$ServerSideBytesOut = (Get-SnmpV3 $connection $sysStatServerBytesOut5m).Data.ToUInt32()

            # Log Debug Message
            $message = "Created Device Info Property Bag for "+ $SNMPAddress + "`r`n"
            $message = $message + "SNMP Status : Okay`r`n"
            $message = $message + "Failover State Id : " + $FailoverStateId + "`r`n"
            $message = $message + "Failover State : " + $FailoverStateText + "`r`n"
            $message = $message + "Client Side Connections : " + $ClientSideConnections + "`r`n"
            $message = $message + "Client Side BytesIn : " + $ClientSideBytesIn + "`r`n"
            $message = $message + "Client Side BytesOut : " + $ClientSideBytesOut + "`r`n"
            $message = $message + "Server Side Connections : " + $ServerSideConnections + "`r`n"
            $message = $message + "Server Side BytesIn : " + $ServerSideBytesIn + "`r`n"
            $message = $message + "Server Side BytesOut : " + $ServerSideBytesOut + "`r`n"
            Log-Event $SCRIPT_PROPERTYBAG_CREATED $EVENT_LEVEL_INFO $message

            # Create Property Bag
            $bag = $api.CreatePropertyBag()
            $bag.AddValue("SnmpState", "Okay")
            $bag.AddValue("FailoverStateId", $FailoverStateId)
            $bag.AddValue("FailoverStateText", $FailoverStateText)
            $bag.AddValue("ClientSideConnections", $ClientSideConnections)
            $bag.AddValue("ClientSideBytesIn", $ClientSideBytesIn)
            $bag.AddValue("ClientSideBytesOut", $ClientSideBytesOut)
            $bag.AddValue("ServerSideConnections", $ServerSideConnections)
            $bag.AddValue("ServerSideBytesIn", $ServerSideBytesIn)
            $bag.AddValue("ServerSideBytesOut", $ServerSideBytesOut)
            $bag     
		}

	} Catch {
		# Log Finished Message
		$message = "SNMPv3 Error : " + $_
		Log-Event $SCRIPT_ERROR $EVENT_LEVEL_ERROR $message $true
	}

} 
else 
{
    Try
    {

        # Try To get System Name
        $sysName = (Get-SnmpV2 $connection $sysSystemName).Data
      
        # Did we Get a Reply
        If ($sysName -eq $null) {

            # Write Warning to Event Log
            Log-Event $SCRIPT_ERROR $EVENT_LEVEL_WARNING "No SNMP Response" $true

            # Create Property Bag
            $message = "Created Device Info Property Bag for "+ $SNMPAddress + "`r`n"
            $message = $message + "SNMP Status : Failed`r`n"
            Log-Event $SCRIPT_PROPERTYBAG_CREATED $EVENT_LEVEL_INFO $message

            # Create Property Bag
            $bag = $api.CreatePropertyBag()
            $bag.AddValue("SnmpState", "Failed")
            $bag
      
        } 
        else 
        {

            # Get FailoverState
            $FailoverState = (Get-SnmpV2 $connection $sysCmFailoverStatusId).Data
            If ($FailoverState.TypeCode -eq "Counter32") 
            {
                $FailoverStateId = $FailoverState.ToUInt32()      
	        }
            else
            {
                $FailoverStateId = $FailoverState.ToInt32()            
	        }
            $FailoverStateText = (Get-SnmpV2 $connection $sysCmFailoverStatusStatus).Data.ToString()

            # Get Client Side Connection Counters
            [int]$ClientSideConnections = (Get-SnmpV2 $connection $sysStatClientMaxConns5m).Data.ToUInt32()

            # Get Client Side Kb In
            [int]$ClientSideBytesIn = (Get-SnmpV2 $connection $sysStatClientBytesIn5m).Data.ToUInt32()

            # Get Client Side Kb Out
            [int]$ClientSideBytesOut = (Get-SnmpV2 $connection $sysStatClientBytesOut5m).Data.ToUInt32()

            # Get Server Side Connection Counters
            [int]$ServerSideConnections = (Get-SnmpV2 $connection $sysStatServerMaxConns5m).Data.ToUInt32()

            # Get Server Side Kb In
            [int]$ServerSideBytesIn = (Get-SnmpV2 $connection $sysStatServerBytesIn5m).Data.ToUInt32()

            # Get Server Side Kb Out
            [int]$ServerSideBytesOut = (Get-SnmpV2 $connection $sysStatServerBytesOut5m).Data.ToUInt32()

            # Log Debug Message
            $message = "Created Device Info Property Bag for "+ $SNMPAddress + "`r`n"
            $message = $message + "SNMP Status : Okay`r`n"
            $message = $message + "Failover State Id : " + $FailoverStateId + "`r`n"
            $message = $message + "Failover State : " + $FailoverStateText + "`r`n"
            $message = $message + "Client Side Connections : " + $ClientSideConnections + "`r`n"
            $message = $message + "Client Side BytesIn : " + $ClientSideBytesIn + "`r`n"
            $message = $message + "Client Side BytesOut : " + $ClientSideBytesOut + "`r`n"
            $message = $message + "Server Side Connections : " + $ServerSideConnections + "`r`n"
            $message = $message + "Server Side BytesIn : " + $ServerSideBytesIn + "`r`n"
            $message = $message + "Server Side BytesOut : " + $ServerSideBytesOut + "`r`n"
            Log-Event $SCRIPT_PROPERTYBAG_CREATED $EVENT_LEVEL_INFO $message

            # Create Property Bag
            $bag = $api.CreatePropertyBag()
            $bag.AddValue("SnmpState", "Okay")
            $bag.AddValue("FailoverStateId", $FailoverStateId)
            $bag.AddValue("FailoverStateText", $FailoverStateText)
            $bag.AddValue("ClientSideConnections", $ClientSideConnections)
            $bag.AddValue("ClientSideBytesIn", $ClientSideBytesIn)
            $bag.AddValue("ClientSideBytesOut", $ClientSideBytesOut)
            $bag.AddValue("ServerSideConnections", $ServerSideConnections)
            $bag.AddValue("ServerSideBytesIn", $ServerSideBytesIn)
            $bag.AddValue("ServerSideBytesOut", $ServerSideBytesOut)
            $bag     
		}

    } Catch {
        # Log Finished Message
        $message = "SNMPv2 Error : " + $_
        Log-Event $SCRIPT_ERROR $EVENT_LEVEL_ERROR $message $true
    }
}

# Get End Time For Script
$EndTime = (GET-DATE)
$TimeTaken = NEW-TIMESPAN -Start $StartTime -End $EndTime
$Seconds = [math]::Round($TimeTaken.TotalSeconds, 2)

# Log Finished Message
Log-Event $SCRIPT_ENDED $EVENT_LEVEL_INFO "Script Finished. Took $Seconds Seconds to Complete!"