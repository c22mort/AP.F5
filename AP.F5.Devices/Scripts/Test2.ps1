
param(
    $restusername,
    $restpassword
)

add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

$baseUri = "https://10.175.1.15"

$uri = $baseUri + "/mgmt/tm/cm/device-group"
$Credential = [System.Management.Automation.PSCredential]::new($restusername,(ConvertTo-SecureString $restpassword -AsPlainText -Force))
$deviceGroups = Invoke-RestMethod -Uri $uri -Credential $Credential

Foreach ($deviceGroup in $deviceGroups.Items)
{
    
    $uri = $deviceGroup.DevicesReference.link.Replace('localhost', '10.175.1.15')
    $devices = Invoke-RestMethod -Uri $uri -Credential $Credential

    # Create Device Group
    $deviceGroupObject = @{
        Name = $deviceGroup.name
        Type = $deviceGroup.type
        Devices = $devices.items | Sort-Object -Property name
    }
    $deviceGroupObject | fl
}