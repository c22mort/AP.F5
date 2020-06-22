
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

$baseUri = "https://10.175.1.213"

$uri = $baseUri + "/mgmt/tm/sys/hardware"
Try
{
    $Credential = [System.Management.Automation.PSCredential]::new($restusername,(ConvertTo-SecureString $restpassword -AsPlainText -Force))
    $hardwareList = Invoke-RestMethod -Uri $uri -Credential $Credential

    $fans = $hardwareList.entries.'https://localhost/mgmt/tm/sys/hardware/chassis-fan-status-index'.nestedStats.entries
    $fanUriList = ($fans | Get-Member -Type NoteProperty).Name
    Foreach($fanUri in $fanUriList)
    {
        $fanInfo = $fans.$fanUri.nestedStats.entries
        $fanInfo.index.Value
        $fanInfo.status.description
        #$fanInfo
    }

    $psus = $hardwareList.entries.'https://localhost/mgmt/tm/sys/hardware/chassis-power-supply-status-index'.nestedStats.entries
    $psuUriList = ($psus | Get-Member -Type NoteProperty).Name
    $psuUriList
    Foreach($psuUri in $psuUriList)
    {
        $psuInfo = $psus.$psuUri.nestedStats.entries
        $psuInfo
    }
}
Catch
{
    $_
}

