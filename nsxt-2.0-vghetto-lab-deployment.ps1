# Author: William Lam
# Website: www.virtuallyghetto.com
# Description: PowerCLI script to deploy a fully functional NSX-T 2.0 lab consisting of
#               vSphere 6.5 Update 1 which includes Nested ESXi hosts enable w/vSAN + VCSA 6.5u1.
#               Expects a vCenter Server endpoint in which all VMs will be deployed to the system
# Reference: http://www.virtuallyghetto.com/2017/10/vghetto-automated-nsx-t-2-0-lab-deployment.html

# vCenter Server used to deploy Lab
$VIServer = "vcenter.primp-industries.com"
$VIUsername = "primp"
$VIPassword = "MY-SUPER-DUPER-SECURE-PASSWORD-IS-VMWARE-123"

# Full Path to both the Nested ESXi 6.5u1 VA, Extracted VCSA 6.5u1 ISO & NSX-T OVAs
$NestedESXiApplianceOVA = "C:\Users\primp\Desktop\Nested_ESXi6.5_Appliance_Template_v1.ova"
$VCSAInstallerPath = "C:\Users\primp\Desktop\VMware-VCSA-all-6.5.0-5973321"
$NSXTManagerOVA = "C:\Users\primp\Desktop\nsx-unified-appliance-2.0.0.0.0.6522097.ova"
$NSXTControllerOVA = "C:\Users\primp\Desktop\nsx-controller-2.0.0.0.0.6522091.ova"
$NSXTEdgeOVA = "C:\Users\primp\Desktop\nsx-edge-2.0.0.0.0.6522113.ova"

# Nested ESXi VMs to deploy
$NestedESXiHostnameToIPs = @{
"vesxi65-1" = "172.30.0.171"
"vesxi65-2" = "172.30.0.172"
"vesxi65-3" = "172.30.0.173"
}

# Nested ESXi VM Resources
$NestedESXivCPU = "2"
$NestedESXivMEM = "12" #GB
$NestedESXiCachingvDisk = "4" #GB
$NestedESXiCapacityvDisk = "12" #GB

# VCSA Deployment Configuration
$VCSADeploymentSize = "tiny"
$VCSADisplayName = "vcenter65-1"
$VCSAIPAddress = "172.30.0.170"
$VCSAHostname = "vcenter65-1.primp-industries.com" #Change to IP if you don't have valid DNS
$VCSAPrefix = "24"
$VCSASSODomainName = "vsphere.local"
$VCSASSOSiteName = "virtuallyGhetto"
$VCSASSOPassword = "VMware1!"
$VCSARootPassword = "VMware1!"
$VCSASSHEnable = "true"

# General Deployment Configuration for Nested ESXi, VCSA & NSX VMs
$VMCluster = "Primp-Cluster"
$VirtualSwitchType = "VDS" # VSS or VDS
$VMNetwork = "dv-access333-dev"
$VMDatastore = "himalaya-local-SATA-dc3500-1"
$VMNetmask = "255.255.255.0"
$VMGateway = "172.30.0.1"
$VMDNS = "172.30.0.100"
$VMNTP = "pool.ntp.org"
$VMPassword = "VMware1!"
$VMDomain = "primp-industries.com"
$VMSyslog = "172.30.0.170"
# Applicable to Nested ESXi only
$VMSSH = "true"
$VMVMFS = "false"

# Name of new vSphere Datacenter/Cluster when VCSA is deployed
$NewVCDatacenterName = "Datacenter"
$NewVCVSANClusterName = "VSAN-Cluster"

# NSX-T Configuration
$DeployNSX = 1
$NSXRootPassword = "VMware1!"
$NSXAdminUsername = "admin"
$NSXAdminPassword = "VMware1!"
$NSXAuditUsername = "audit"
$NSXAuditPassword = "VMware1!"
$NSXSSHEnable = "true"
$NSXEnableRootLogin = "true" # this is required to be true for now until we have NSX-T APIs for initial setup
$NSXPrivatePortgroup = "dv-private-network"

$TunnelEndpointName = "TEP-IP-Pool"
$TunnelEndpointDescription = "Tunnel Endpoint for Transport Nodes"
$TunnelEndpointIPRangeStart = "192.168.1.10"
$TunnelEndpointIPRangeEnd = "192.168.1.20"
$TunnelEndpointCIDR = "192.168.1.0/24"
$TunnelEndpointGateway = "192.168.1.1"

$OverlayTransportZoneName = "Overlay-TZ"
$VlanTransportZoneName = "VLAN-TZ"

$LogicalSwitchName = "Edge-Uplink"
$LogicalSwitchVlan = "0"

$ESXiUplinkProfileName = "ESXi-Uplink-Profile"
$ESXiUplinkProfilePolicy = "FAILOVER_ORDER" # Leave alone unless you know what you're doing
$ESXiUplinkProfileActivepNIC = "vmnic2" # vminic2 or vminic 3, Leave alone unless you know what you're doing
$ESXiUplinkProfileTransportVLAN = "0"
$ESXiUplinkProfileMTU = "1600"

# NSX-T Manager Configurations
$NSXTMgrDeploymentSize = "small"
$NSXTMgrvCPU = "2"
$NSXTMgrvMEM = "8"
$NSXTMgrDisplayName = "nsxt-mgr"
$NSXTMgrHostname = "nsxt-mgr.primp-industries.com"
$NSXTMgrIPAddress = "172.30.0.201"

# NSX-T Controller Configurations
$NSXTCtrvCPU = "2"
$NSXTCtrvMEM = "6"
$NSXControllerSharedSecret = "s3cR3ctz"
$NSXTControllerHostnameToIPs = @{
"nsxt-ctr1" = "172.30.0.203"
"nsxt-ctr2" = "172.30.0.204"
"nsxt-ctr3" = "172.30.0.205"
}

# NSX-T Edge Configuration
$NSXTEdgevCPU = "2"
$NSXTEdgevMEM = "4"
$NSXTEdgeHostnameToIPs = @{
"nsxt-edge" = "172.30.0.202"
}

# Advanced Configurations
# Set to 1 only if you have DNS (forward/reverse) for ESXi hostnames
$addHostByDnsName = 0

#### DO NOT EDIT BEYOND HERE ####

$debug = $true
$verboseLogFile = "nsxt20-vghetto-lab-deployment.log"
$vSphereVersion = "6.5"
$random_string = -join ((65..90) + (97..122) | Get-Random -Count 8 | % {[char]$_})
$VAppName = "vGhetto-Nested-NSX-T-Lab-$vSphereVersion-$random_string"

$vcsaSize2MemoryStorageMap = @{
"tiny"=@{"cpu"="2";"mem"="10";"disk"="250"};
"small"=@{"cpu"="4";"mem"="16";"disk"="290"};
"medium"=@{"cpu"="8";"mem"="24";"disk"="425"};
"large"=@{"cpu"="16";"mem"="32";"disk"="640"};
"xlarge"=@{"cpu"="24";"mem"="48";"disk"="980"}
}

$nsxStorageMap = @{
"manager"="160";
"controller"="120";
"edge"="120"
}

$esxiTotalCPU = 0
$vcsaTotalCPU = 0
$nsxTotalCPU = 0
$esxiTotalMemory = 0
$vcsaTotalMemory = 0
$nsxTotalMemory = 0
$esxiTotStorage = 0
$vcsaTotalStorage = 0
$nsxTotalStorage = 0

$preCheck = 1
$confirmDeployment = 1
$deployNestedESXiVMs = 1
$deployVCSA = 1
$setupNewVC = 1
$addESXiHostsToVC = 1
$configureVSANDiskGroups = 1
$clearVSANHealthCheckAlarm = 1
$initialNSXConfig = 1
$postDeployNSXConfig = 1
$moveVMsIntovApp = 1

$StartTime = Get-Date

Function Get-SSLThumbprint256 {
    param(
    [Parameter(
        Position=0,
        Mandatory=$true,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)
    ]
    [Alias('FullName')]
    [String]$URL
    )

add-type @"
        using System.Net;
        using System.Security.Cryptography.X509Certificates;
            public class IDontCarePolicy : ICertificatePolicy {
            public IDontCarePolicy() {}
            public bool CheckValidationResult(
                ServicePoint sPoint, X509Certificate cert,
                WebRequest wRequest, int certProb) {
                return true;
            }
        }
"@
    [System.Net.ServicePointManager]::CertificatePolicy = new-object IDontCarePolicy

    # Need to connect using simple GET operation for this to work
    Invoke-RestMethod -Uri $URL -Method Get | Out-Null

    $ENDPOINT_REQUEST = [System.Net.Webrequest]::Create("$URL")
    $CERT = $ENDPOINT_REQUEST.ServicePoint.Certificate
    # https://stackoverflow.com/a/22251597
    $BYTES = $cert.Export([Security.Cryptography.X509Certificates.X509ContentType]::Cert)
    Set-content -value $BYTES -encoding byte -path $ENV:TMP\cert-temp
    $SSL_THUMBPRINT = (Get-FileHash -Path $ENV:TMP\cert-temp -Algorithm SHA256).Hash
    return $SSL_THUMBPRINT -replace '(..(?!$))','$1:'
}

Function Set-VMKeystrokes {
    <#
        Please see http://www.virtuallyghetto.com/2017/09/automating-vm-keystrokes-using-the-vsphere-api-powercli.html for more details
    #>
        param(
            [Parameter(Mandatory=$true)][String]$VMName,
            [Parameter(Mandatory=$true)][String]$StringInput,
            [Parameter(Mandatory=$false)][Boolean]$ReturnCarriage,
            [Parameter(Mandatory=$false)][Boolean]$DebugOn
        )

        # Map subset of USB HID keyboard scancodes
        # https://gist.github.com/MightyPork/6da26e382a7ad91b5496ee55fdc73db2
        $hidCharacterMap = @{
            "a"="0x04";
            "b"="0x05";
            "c"="0x06";
            "d"="0x07";
            "e"="0x08";
            "f"="0x09";
            "g"="0x0a";
            "h"="0x0b";
            "i"="0x0c";
            "j"="0x0d";
            "k"="0x0e";
            "l"="0x0f";
            "m"="0x10";
            "n"="0x11";
            "o"="0x12";
            "p"="0x13";
            "q"="0x14";
            "r"="0x15";
            "s"="0x16";
            "t"="0x17";
            "u"="0x18";
            "v"="0x19";
            "w"="0x1a";
            "x"="0x1b";
            "y"="0x1c";
            "z"="0x1d";
            "1"="0x1e";
            "2"="0x1f";
            "3"="0x20";
            "4"="0x21";
            "5"="0x22";
            "6"="0x23";
            "7"="0x24";
            "8"="0x25";
            "9"="0x26";
            "0"="0x27";
            "!"="0x1e";
            "@"="0x1f";
            "#"="0x20";
            "$"="0x21";
            "%"="0x22";
            "^"="0x23";
            "&"="0x24";
            "*"="0x25";
            "("="0x26";
            ")"="0x27";
            "_"="0x2d";
            "+"="0x2e";
            "{"="0x2f";
            "}"="0x30";
            "|"="0x31";
            ":"="0x33";
            "`""="0x34";
            "~"="0x35";
            "<"="0x36";
            ">"="0x37";
            "?"="0x38";
            "-"="0x2d";
            "="="0x2e";
            "["="0x2f";
            "]"="0x30";
            "\"="0x31";
            "`;"="0x33";
            "`'"="0x34";
            ","="0x36";
            "."="0x37";
            "/"="0x38";
            " "="0x2c";
        }

        $vm = Get-View -ViewType VirtualMachine -Filter @{"Name"=$VMName}

        # Verify we have a VM or fail
        if(!$vm) {
            Write-host "Unable to find VM $VMName"
            return
        }

        $hidCodesEvents = @()
        foreach($character in $StringInput.ToCharArray()) {
            # Check to see if we've mapped the character to HID code
            if($hidCharacterMap.ContainsKey([string]$character)) {
                $hidCode = $hidCharacterMap[[string]$character]

                $tmp = New-Object VMware.Vim.UsbScanCodeSpecKeyEvent

                # Add leftShift modifer for capital letters and/or special characters
                if( ($character -cmatch "[A-Z]") -or ($character -match "[!|@|#|$|%|^|&|(|)|_|+|{|}|||:|~|<|>|?]") ) {
                    $modifer = New-Object Vmware.Vim.UsbScanCodeSpecModifierType
                    $modifer.LeftShift = $true
                    $tmp.Modifiers = $modifer
                }

                # Convert to expected HID code format
                $hidCodeHexToInt = [Convert]::ToInt64($hidCode,"16")
                $hidCodeValue = ($hidCodeHexToInt -shl 16) -bor 0007

                $tmp.UsbHidCode = $hidCodeValue
                $hidCodesEvents+=$tmp
            } else {
                My-Logger Write-Host "The following character `"$character`" has not been mapped, you will need to manually process this character"
                break
            }
        }

        # Add return carriage to the end of the string input (useful for logins or executing commands)
        if($ReturnCarriage) {
            # Convert return carriage to HID code format
            $hidCodeHexToInt = [Convert]::ToInt64("0x28","16")
            $hidCodeValue = ($hidCodeHexToInt -shl 16) + 7

            $tmp = New-Object VMware.Vim.UsbScanCodeSpecKeyEvent
            $tmp.UsbHidCode = $hidCodeValue
            $hidCodesEvents+=$tmp
        }

        # Call API to send keystrokes to VM
        $spec = New-Object Vmware.Vim.UsbScanCodeSpec
        $spec.KeyEvents = $hidCodesEvents
        $results = $vm.PutUsbScanCodes($spec)
    }

Function My-Logger {
    param(
    [Parameter(Mandatory=$true)]
    [String]$message
    )

    $timeStamp = Get-Date -Format "MM-dd-yyyy_hh:mm:ss"

    Write-Host -NoNewline -ForegroundColor White "[$timestamp]"
    Write-Host -ForegroundColor Green " $message"
    $logMessage = "[$timeStamp] $message"
    $logMessage | Out-File -Append -LiteralPath $verboseLogFile
}

Function URL-Check([string] $url) {
    $isWorking = $true

    try {
        $request = [System.Net.WebRequest]::Create($url)
        $request.Method = "HEAD"
        $request.UseDefaultCredentials = $true

        $response = $request.GetResponse()
        $httpStatus = $response.StatusCode

        $isWorking = ($httpStatus -eq "OK")
    }
    catch {
        $isWorking = $false
    }
    return $isWorking
}

if($preCheck -eq 1) {
    if(!(Test-Path $NestedESXiApplianceOVA)) {
        Write-Host -ForegroundColor Red "`nUnable to find $NestedESXiApplianceOVA ...`nexiting"
        exit
    }

    if(!(Test-Path $VCSAInstallerPath)) {
        Write-Host -ForegroundColor Red "`nUnable to find $VCSAInstallerPath ...`nexiting"
        exit
    }

    if(!(Test-Path $NSXTManagerOVA)) {
        Write-Host -ForegroundColor Red "`nUnable to find $NSXTManagerOVA ...`nexiting"
        exit
    }

    if(!(Test-Path $NSXTControllerOVA)) {
        Write-Host -ForegroundColor Red "`nUnable to find $NSXTControllerOVA ...`nexiting"
        exit
    }

    if(!(Test-Path $NSXTEdgeOVA)) {
        Write-Host -ForegroundColor Red "`nUnable to find $NSXTEdgeOVA ...`nexiting"
        exit
    }
}

if($confirmDeployment -eq 1) {
    Write-Host -ForegroundColor Magenta "`nPlease confirm the following configuration will be deployed:`n"

    Write-Host -ForegroundColor Yellow "---- vGhetto NSX-T Automated Lab Deployment Configuration ---- "
    Write-Host -NoNewline -ForegroundColor Green "Nested ESXi Image Path: "
    Write-Host -ForegroundColor White $NestedESXiApplianceOVA
    Write-Host -NoNewline -ForegroundColor Green "VCSA Image Path: "
    Write-Host -ForegroundColor White $VCSAInstallerPath

    if($DeployNSX -eq 1) {
        Write-Host -NoNewline -ForegroundColor Green "NSX-T Manager Image Path: "
        Write-Host -ForegroundColor White $NSXTManagerOVA
        Write-Host -NoNewline -ForegroundColor Green "NSX-T Controller Image Path: "
        Write-Host -ForegroundColor White $NSXTControllerOVA
        Write-Host -NoNewline -ForegroundColor Green "NSX-T Edge Image Path: "
        Write-Host -ForegroundColor White $NSXTEdgeOVA
    }

    Write-Host -ForegroundColor Yellow "`n---- vCenter Server Deployment Target Configuration ----"
    Write-Host -NoNewline -ForegroundColor Green "vCenter Server Address: "
    Write-Host -ForegroundColor White $VIServer
    Write-Host -NoNewline -ForegroundColor Green "VM Network: "
    Write-Host -ForegroundColor White $VMNetwork

    if($DeployNSX -eq 1) {
        Write-Host -NoNewline -ForegroundColor Green "NSX-T Private VM Network: "
        Write-Host -ForegroundColor White $NSXPrivatePortgroup
    }

    Write-Host -NoNewline -ForegroundColor Green "VM Storage: "
    Write-Host -ForegroundColor White $VMDatastore
    Write-Host -NoNewline -ForegroundColor Green "VM Cluster: "
    Write-Host -ForegroundColor White $VMCluster
    Write-Host -NoNewline -ForegroundColor Green "VM vApp: "
    Write-Host -ForegroundColor White $VAppName

    Write-Host -ForegroundColor Yellow "`n---- vESXi Configuration ----"
    Write-Host -NoNewline -ForegroundColor Green "# of Nested ESXi VMs: "
    Write-Host -ForegroundColor White $NestedESXiHostnameToIPs.count
    Write-Host -NoNewline -ForegroundColor Green "vCPU: "
    Write-Host -ForegroundColor White $NestedESXivCPU
    Write-Host -NoNewline -ForegroundColor Green "vMEM: "
    Write-Host -ForegroundColor White "$NestedESXivMEM GB"
    Write-Host -NoNewline -ForegroundColor Green "Caching VMDK: "
    Write-Host -ForegroundColor White "$NestedESXiCachingvDisk GB"
    Write-Host -NoNewline -ForegroundColor Green "Capacity VMDK: "
    Write-Host -ForegroundColor White "$NestedESXiCapacityvDisk GB"
    Write-Host -NoNewline -ForegroundColor Green "IP Address(s): "
    Write-Host -ForegroundColor White $NestedESXiHostnameToIPs.Values
    Write-Host -NoNewline -ForegroundColor Green "Netmask "
    Write-Host -ForegroundColor White $VMNetmask
    Write-Host -NoNewline -ForegroundColor Green "Gateway: "
    Write-Host -ForegroundColor White $VMGateway
    Write-Host -NoNewline -ForegroundColor Green "DNS: "
    Write-Host -ForegroundColor White $VMDNS
    Write-Host -NoNewline -ForegroundColor Green "NTP: "
    Write-Host -ForegroundColor White $VMNTP
    Write-Host -NoNewline -ForegroundColor Green "Syslog: "
    Write-Host -ForegroundColor White $VMSyslog
    Write-Host -NoNewline -ForegroundColor Green "Enable SSH: "
    Write-Host -ForegroundColor White $VMSSH
    Write-Host -NoNewline -ForegroundColor Green "Create VMFS Volume: "
    Write-Host -ForegroundColor White $VMVMFS
    Write-Host -NoNewline -ForegroundColor Green "Root Password: "
    Write-Host -ForegroundColor White $VMPassword

    Write-Host -ForegroundColor Yellow "`n---- VCSA Configuration ----"
    Write-Host -NoNewline -ForegroundColor Green "Deployment Size: "
    Write-Host -ForegroundColor White $VCSADeploymentSize
    Write-Host -NoNewline -ForegroundColor Green "SSO Domain: "
    Write-Host -ForegroundColor White $VCSASSODomainName
    Write-Host -NoNewline -ForegroundColor Green "SSO Site: "
    Write-Host -ForegroundColor White $VCSASSOSiteName
    Write-Host -NoNewline -ForegroundColor Green "SSO Password: "
    Write-Host -ForegroundColor White $VCSASSOPassword
    Write-Host -NoNewline -ForegroundColor Green "Root Password: "
    Write-Host -ForegroundColor White $VCSARootPassword
    Write-Host -NoNewline -ForegroundColor Green "Enable SSH: "
    Write-Host -ForegroundColor White $VCSASSHEnable
    Write-Host -NoNewline -ForegroundColor Green "Hostname: "
    Write-Host -ForegroundColor White $VCSAHostname
    Write-Host -NoNewline -ForegroundColor Green "IP Address: "
    Write-Host -ForegroundColor White $VCSAIPAddress
    Write-Host -NoNewline -ForegroundColor Green "Netmask "
    Write-Host -ForegroundColor White $VMNetmask
    Write-Host -NoNewline -ForegroundColor Green "Gateway: "
    Write-Host -ForegroundColor White $VMGateway

    if($DeployNSX -eq 1) {
        Write-Host -ForegroundColor Yellow "`n---- NSX-T Configuration ----"
        Write-Host -NoNewline -ForegroundColor Green "NSX Manager Hostname: "
        Write-Host -ForegroundColor White $NSXTMgrHostname
        Write-Host -NoNewline -ForegroundColor Green "NSX Manager IP Address: "
        Write-Host -ForegroundColor White $NSXTMgrIPAddress
        Write-Host -NoNewline -ForegroundColor Green "# of NSX Controller VMs: "
        Write-Host -ForegroundColor White $NSXTControllerHostnameToIPs.count
        Write-Host -NoNewline -ForegroundColor Green "IP Address(s): "
        Write-Host -ForegroundColor White $NSXTControllerHostnameToIPs.Values
        Write-Host -NoNewline -ForegroundColor Green "# of NSX Edge VMs: "
        Write-Host -ForegroundColor White $NSXTEdgeHostnameToIPs.count
        Write-Host -NoNewline -ForegroundColor Green "IP Address(s): "
        Write-Host -ForegroundColor White $NSXTEdgeHostnameToIPs.Values
        Write-Host -NoNewline -ForegroundColor Green "Netmask: "
        Write-Host -ForegroundColor White $VMNetmask
        Write-Host -NoNewline -ForegroundColor Green "Gateway: "
        Write-Host -ForegroundColor White $VMGateway
        Write-Host -NoNewline -ForegroundColor Green "Enable SSH: "
        Write-Host -ForegroundColor White $NSXSSHEnable
        Write-Host -NoNewline -ForegroundColor Green "Enable Root Login: "
        Write-Host -ForegroundColor White $NSXEnableRootLogin
    }

    $esxiTotalCPU = $NestedESXiHostnameToIPs.count * [int]$NestedESXivCPU
    $esxiTotalMemory = $NestedESXiHostnameToIPs.count * [int]$NestedESXivMEM
    $esxiTotalStorage = ($NestedESXiHostnameToIPs.count * [int]$NestedESXiCachingvDisk) + ($NestedESXiHostnameToIPs.count * [int]$NestedESXiCapacityvDisk)
    $vcsaTotalCPU = $vcsaSize2MemoryStorageMap.$VCSADeploymentSize.cpu
    $vcsaTotalMemory = $vcsaSize2MemoryStorageMap.$VCSADeploymentSize.mem
    $vcsaTotalStorage = $vcsaSize2MemoryStorageMap.$VCSADeploymentSize.disk

    Write-Host -ForegroundColor Yellow "`n---- Resource Requirements ----"
    Write-Host -NoNewline -ForegroundColor Green "ESXi VM CPU: "
    Write-Host -NoNewline -ForegroundColor White $esxiTotalCPU
    Write-Host -NoNewline -ForegroundColor Green " ESXi VM Memory: "
    Write-Host -NoNewline -ForegroundColor White $esxiTotalMemory "GB "
    Write-Host -NoNewline -ForegroundColor Green "ESXi VM Storage: "
    Write-Host -ForegroundColor White $esxiTotalStorage "GB"
    Write-Host -NoNewline -ForegroundColor Green "VCSA VM CPU: "
    Write-Host -NoNewline -ForegroundColor White $vcsaTotalCPU
    Write-Host -NoNewline -ForegroundColor Green " VCSA VM Memory: "
    Write-Host -NoNewline -ForegroundColor White $vcsaTotalMemory "GB "
    Write-Host -NoNewline -ForegroundColor Green "VCSA VM Storage: "
    Write-Host -ForegroundColor White $vcsaTotalStorage "GB"

    if($DeployNSX -eq 1) {
        $nsxTotalCPU += $NSXTControllerHostnameToIPs.count * [int]$NSXTCtrvCPU
        $nsxTotalMemory += $NSXTControllerHostnameToIPs.count * [int]$NSXTCtrvMEM
        $nsxTotalStorage += $NSXTControllerHostnameToIPs.count * [int]$nsxStorageMap["controller"]

        $nsxTotalCPU += [int]$NSXTMgrvCPU
        $nsxTotalMemory += [int]$NSXTMgrvMEM
        $nsxTotalStorage += [int]$nsxStorageMap["manager"]

        $nsxTotalCPU += $NSXTEdgeHostnameToIPs.count * [int]$NSXTEdgevCPU
        $nsxTotalMemory += $NSXTEdgeHostnameToIPs.count * [int]$NSXTEdgevMEM
        $nsxTotalStorage += $NSXTEdgeHostnameToIPs.count * [int]$nsxStorageMap["edge"]

        Write-Host -NoNewline -ForegroundColor Green "NSX VM CPU: "
        Write-Host -NoNewline -ForegroundColor White $nsxTotalCPU
        Write-Host -NoNewline -ForegroundColor Green " NSX VM Memory: "
        Write-Host -NoNewline -ForegroundColor White $nsxTotalMemory "GB "
        Write-Host -NoNewline -ForegroundColor Green " NSX VM Storage: "
        Write-Host -ForegroundColor White $nsxTotalStorage "GB"
    }

    Write-Host -ForegroundColor White "---------------------------------------------"
    Write-Host -NoNewline -ForegroundColor Green "Total CPU: "
    Write-Host -ForegroundColor White ($esxiTotalCPU + $vcsaTotalCPU + $nsxTotalCPU)
    Write-Host -NoNewline -ForegroundColor Green "Total Memory: "
    Write-Host -ForegroundColor White ($esxiTotalMemory + $vcsaTotalMemory + $nsxTotalMemory) "GB"
    Write-Host -NoNewline -ForegroundColor Green "Total Storage: "
    Write-Host -ForegroundColor White ($esxiTotalStorage + $vcsaTotalStorage + $nsxTotalStorage) "GB"

    Write-Host -ForegroundColor Magenta "`nWould you like to proceed with this deployment?`n"
    $answer = Read-Host -Prompt "Do you accept (Y or N)"
    if($answer -ne "Y" -or $answer -ne "y") {
        exit
    }
    Clear-Host
}

My-Logger "Connecting to Management vCenter Server $VIServer ..."
$viConnection = Connect-VIServer $VIServer -User $VIUsername -Password $VIPassword -WarningAction SilentlyContinue

$datastore = Get-Datastore -Server $viConnection -Name $VMDatastore | Select -First 1
if($VirtualSwitchType -eq "VSS") {
    $network = Get-VirtualPortGroup -Server $viConnection -Name $VMNetwork | Select -First 1
    if($DeployNSX -eq 1) {
        $privateNetwork = Get-VirtualPortGroup -Server $viConnection -Name $NSXPrivatePortgroup | Select -First 1
    }
} else {
    $network = Get-VDPortgroup -Server $viConnection -Name $VMNetwork | Select -First 1
    if($DeployNSX -eq 1) {
        $privateNetwork = Get-VDPortgroup -Server $viConnection -Name $NSXPrivatePortgroup | Select -First 1
    }
}
$cluster = Get-Cluster -Server $viConnection -Name $VMCluster
$datacenter = $cluster | Get-Datacenter
$vmhost = $cluster | Get-VMHost | Select -First 1

if($datastore.Type -eq "vsan") {
    My-Logger "VSAN Datastore detected, enabling Fake SCSI Reservations ..."
    Get-AdvancedSetting -Entity $vmhost -Name "VSAN.FakeSCSIReservations" | Set-AdvancedSetting -Value 1 -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile
}

if($deployNestedESXiVMs -eq 1) {
    $NestedESXiHostnameToIPs.GetEnumerator() | Sort-Object -Property Value | Foreach-Object {
        $VMName = $_.Key
        $VMIPAddress = $_.Value

        $ovfconfig = Get-OvfConfiguration $NestedESXiApplianceOVA
        $ovfconfig.NetworkMapping.VM_Network.value = $VMNetwork

        $ovfconfig.common.guestinfo.hostname.value = $VMName
        $ovfconfig.common.guestinfo.ipaddress.value = $VMIPAddress
        $ovfconfig.common.guestinfo.netmask.value = $VMNetmask
        $ovfconfig.common.guestinfo.gateway.value = $VMGateway
        $ovfconfig.common.guestinfo.dns.value = $VMDNS
        $ovfconfig.common.guestinfo.domain.value = $VMDomain
        $ovfconfig.common.guestinfo.ntp.value = $VMNTP
        $ovfconfig.common.guestinfo.syslog.value = $VMSyslog
        $ovfconfig.common.guestinfo.password.value = $VMPassword
        if($VMSSH -eq "true") {
            $VMSSHVar = $true
        } else {
            $VMSSHVar = $false
        }
        $ovfconfig.common.guestinfo.ssh.value = $VMSSHVar

        My-Logger "Deploying Nested ESXi VM $VMName ..."
        $vm = Import-VApp -Source $NestedESXiApplianceOVA -OvfConfiguration $ovfconfig -Name $VMName -Location $cluster -VMHost $vmhost -Datastore $datastore -DiskStorageFormat thin

        My-Logger "Adding vmnic2/vmnic3 to $NSXPrivatePortgroup ..."
        New-NetworkAdapter -VM $vm -Type Vmxnet3 -Portgroup $NSXPrivatePortgroup -StartConnected -confirm:$false | Out-File -Append -LiteralPath $verboseLogFile
        New-NetworkAdapter -VM $vm -Type Vmxnet3 -Portgroup $NSXPrivatePortgroup -StartConnected -confirm:$false | Out-File -Append -LiteralPath $verboseLogFile

        My-Logger "Updating vCPU Count to $NestedESXivCPU & vMEM to $NestedESXivMEM GB ..."
        Set-VM -Server $viConnection -VM $vm -NumCpu $NestedESXivCPU -MemoryGB $NestedESXivMEM -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile

        My-Logger "Updating vSAN Caching VMDK size to $NestedESXiCachingvDisk GB ..."
        Get-HardDisk -Server $viConnection -VM $vm -Name "Hard disk 2" | Set-HardDisk -CapacityGB $NestedESXiCachingvDisk -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile

        My-Logger "Updating vSAN Capacity VMDK size to $NestedESXiCapacityvDisk GB ..."
        Get-HardDisk -Server $viConnection -VM $vm -Name "Hard disk 3" | Set-HardDisk -CapacityGB $NestedESXiCapacityvDisk -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile

        My-Logger "Powering On $vmname ..."
        $vm | Start-Vm -RunAsync | Out-Null
    }
}

if($DeployNSX -eq 1) {
    # Deploy NSX Manager
    $nsxMgrOvfConfig = Get-OvfConfiguration $NSXTManagerOVA
    $nsxMgrOvfConfig.DeploymentOption.Value = $NSXTMgrDeploymentSize
    $nsxMgrOvfConfig.NetworkMapping.Network_1.value = $VMNetwork

    $nsxMgrOvfConfig.Common.nsx_role.Value = "nsx-manager"
    $nsxMgrOvfConfig.Common.nsx_hostname.Value = $NSXTMgrHostname
    $nsxMgrOvfConfig.Common.nsx_ip_0.Value = $NSXTMgrIPAddress
    $nsxMgrOvfConfig.Common.nsx_netmask_0.Value = $VMNetmask
    $nsxMgrOvfConfig.Common.nsx_gateway_0.Value = $VMGateway
    $nsxMgrOvfConfig.Common.nsx_dns1_0.Value = $VMDNS
    $nsxMgrOvfConfig.Common.nsx_domain_0.Value = $VMDomain
    $nsxMgrOvfConfig.Common.nsx_ntp_0.Value = $VMNTP

    if($NSXSSHEnable -eq "true") {
        $NSXSSHEnableVar = $true
    } else {
        $NSXSSHEnableVar = $false
    }
    $nsxMgrOvfConfig.Common.nsx_isSSHEnabled.Value = $NSXSSHEnableVar
    if($NSXEnableRootLogin -eq "true") {
        $NSXRootPasswordVar = $true
    } else {
        $NSXRootPasswordVar = $false
    }
    $nsxMgrOvfConfig.Common.nsx_allowSSHRootLogin.Value = $NSXRootPasswordVar

    $nsxMgrOvfConfig.Common.nsx_passwd_0.Value = $NSXRootPassword
    $nsxMgrOvfConfig.Common.nsx_cli_username.Value = $NSXAdminUsername
    $nsxMgrOvfConfig.Common.nsx_cli_passwd_0.Value = $NSXAdminPassword
    $nsxMgrOvfConfig.Common.nsx_cli_audit_username.Value = $NSXAuditUsername
    $nsxMgrOvfConfig.Common.nsx_cli_audit_passwd_0.Value = $NSXAuditPassword

    My-Logger "Deploying NSX Manager VM $NSXTMgrDisplayName ..."
    $nsxmgr_vm = Import-VApp -Source $NSXTManagerOVA -OvfConfiguration $nsxMgrOvfConfig -Name $NSXTMgrDisplayName -Location $cluster -VMHost $vmhost -Datastore $datastore -DiskStorageFormat thin

    #My-Logger "Updating vCPU Count to $NSXvCPU & vMEM to $NSXvMEM GB ..."
    #Set-VM -Server $viConnection -VM $nsxmgr_vm -NumCpu $NSXvCPU -MemoryGB $NSXvMEM -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile

    My-Logger "Powering On $NSXTMgrDisplayName ..."
    $nsxmgr_vm | Start-Vm -RunAsync | Out-Null

    # Deploy Controllers
    $nsxCtrOvfConfig = Get-OvfConfiguration $NSXTControllerOVA
    $NSXTControllerHostnameToIPs.GetEnumerator() | Sort-Object -Property Value | Foreach-Object {
        $VMName = $_.Key
        $VMIPAddress = $_.Value
        $VMHostname = "$VMName" + "@" + $VMDomain

        $nsxCtrOvfConfig.NetworkMapping.Network_1.value = $VMNetwork
        $nsxCtrOvfConfig.Common.nsx_hostname.Value = $VMHostname
        $nsxCtrOvfConfig.Common.nsx_ip_0.Value = $VMIPAddress
        $nsxCtrOvfConfig.Common.nsx_netmask_0.Value = $VMNetmask
        $nsxCtrOvfConfig.Common.nsx_gateway_0.Value = $VMGateway
        $nsxCtrOvfConfig.Common.nsx_dns1_0.Value = $VMDNS
        $nsxCtrOvfConfig.Common.nsx_domain_0.Value = $VMDomain
        $nsxCtrOvfConfig.Common.nsx_ntp_0.Value = $VMNTP

        if($NSXSSHEnable -eq "true") {
            $NSXSSHEnableVar = $true
        } else {
            $NSXSSHEnableVar = $false
        }
        $nsxCtrOvfConfig.Common.nsx_isSSHEnabled.Value = $NSXSSHEnableVar
        if($NSXEnableRootLogin -eq "true") {
            $NSXRootPasswordVar = $true
        } else {
            $NSXRootPasswordVar = $false
        }
        $nsxCtrOvfConfig.Common.nsx_allowSSHRootLogin.Value = $NSXRootPasswordVar

        $nsxCtrOvfConfig.Common.nsx_passwd_0.Value = $NSXRootPassword
        $nsxCtrOvfConfig.Common.nsx_cli_username.Value = $NSXAdminUsername
        $nsxCtrOvfConfig.Common.nsx_cli_passwd_0.Value = $NSXAdminPassword
        $nsxCtrOvfConfig.Common.nsx_cli_audit_username.Value = $NSXAuditUsername
        $nsxCtrOvfConfig.Common.nsx_cli_audit_passwd_0.Value = $NSXAuditPassword

        My-Logger "Deploying NSX Controller VM $VMName ..."
        $nsxctr_vm = Import-VApp -Source $NSXTControllerOVA -OvfConfiguration $nsxCtrOvfConfig -Name $VMName -Location $cluster -VMHost $vmhost -Datastore $datastore -DiskStorageFormat thin

        #My-Logger "Updating vCPU Count to $NSXvCPU & vMEM to $NSXvMEM GB ..."
        #Set-VM -Server $viConnection -VM $nsxctr_vm -NumCpu $NSXvCPU -MemoryGB $NSXvMEM -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile

        My-Logger "Powering On $VMName ..."
        $nsxctr_vm | Start-Vm -RunAsync | Out-Null
    }

    # Deploy Edges
    $nsxEdgeOvfConfig = Get-OvfConfiguration $NSXTEdgeOVA
    $NSXTEdgeHostnameToIPs.GetEnumerator() | Sort-Object -Property Value | Foreach-Object {
        $VMName = $_.Key
        $VMIPAddress = $_.Value
        $VMHostname = "$VMName" + "@" + $VMDomain

        $nsxEdgeOvfConfig.DeploymentOption.Value = $NSXTMgrDeploymentSize
        $nsxEdgeOvfConfig.NetworkMapping.Network_1.value = $VMNetwork

        $nsxEdgeOvfConfig.Common.nsx_hostname.Value = $VMHostname
        $nsxEdgeOvfConfig.Common.nsx_ip_0.Value = $VMIPAddress
        $nsxEdgeOvfConfig.Common.nsx_netmask_0.Value = $VMNetmask
        $nsxEdgeOvfConfig.Common.nsx_gateway_0.Value = $VMGateway
        $nsxEdgeOvfConfig.Common.nsx_dns1_0.Value = $VMDNS
        $nsxEdgeOvfConfig.Common.nsx_domain_0.Value = $VMDomain
        $nsxEdgeOvfConfig.Common.nsx_ntp_0.Value = $VMNTP

        if($NSXSSHEnable -eq "true") {
            $NSXSSHEnableVar = $true
        } else {
            $NSXSSHEnableVar = $false
        }
        $nsxEdgeOvfConfig.Common.nsx_isSSHEnabled.Value = $NSXSSHEnableVar
        if($NSXEnableRootLogin -eq "true") {
            $NSXRootPasswordVar = $true
        } else {
            $NSXRootPasswordVar = $false
        }
        $nsxEdgeOvfConfig.Common.nsx_allowSSHRootLogin.Value = $NSXRootPasswordVar

        $nsxEdgeOvfConfig.Common.nsx_passwd_0.Value = $NSXRootPassword
        $nsxEdgeOvfConfig.Common.nsx_cli_username.Value = $NSXAdminUsername
        $nsxEdgeOvfConfig.Common.nsx_cli_passwd_0.Value = $NSXAdminPassword
        $nsxEdgeOvfConfig.Common.nsx_cli_audit_username.Value = $NSXAuditUsername
        $nsxEdgeOvfConfig.Common.nsx_cli_audit_passwd_0.Value = $NSXAuditPassword

        My-Logger "Deploying NSX Edge VM $NSXTEdgeDisplayName ..."
        $nsxedge_vm = Import-VApp -Source $NSXTEdgeOVA -OvfConfiguration $nsxEdgeOvfConfig -Name $VMName -Location $cluster -VMHost $vmhost -Datastore $datastore -DiskStorageFormat thin

        #My-Logger "Updating vCPU Count to $NSXvCPU & vMEM to $NSXvMEM GB ..."
        #Set-VM -Server $viConnection -VM $nsxedge_vm -NumCpu $NSXvCPU -MemoryGB $NSXvMEM -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile

        My-Logger "Powering On $NSXTEdgeDisplayName ..."
        $nsxedge_vm | Start-Vm -RunAsync | Out-Null
    }
}

if($deployVCSA -eq 1) {
        $config = (Get-Content -Raw "$($VCSAInstallerPath)\vcsa-cli-installer\templates\install\embedded_vCSA_on_VC.json") | convertfrom-json
        $config.'new.vcsa'.vc.hostname = $VIServer
        $config.'new.vcsa'.vc.username = $VIUsername
        $config.'new.vcsa'.vc.password = $VIPassword
        $config.'new.vcsa'.vc.'deployment.network' = $VMNetwork
        $config.'new.vcsa'.vc.datastore = $datastore
        $config.'new.vcsa'.vc.datacenter = $datacenter.name
        $config.'new.vcsa'.vc.target = $VMCluster
        $config.'new.vcsa'.appliance.'thin.disk.mode' = $true
        $config.'new.vcsa'.appliance.'deployment.option' = $VCSADeploymentSize
        $config.'new.vcsa'.appliance.name = $VCSADisplayName
        $config.'new.vcsa'.network.'ip.family' = "ipv4"
        $config.'new.vcsa'.network.mode = "static"
        $config.'new.vcsa'.network.ip = $VCSAIPAddress
        $config.'new.vcsa'.network.'dns.servers'[0] = $VMDNS
        $config.'new.vcsa'.network.prefix = $VCSAPrefix
        $config.'new.vcsa'.network.gateway = $VMGateway
        $config.'new.vcsa'.network.'system.name' = $VCSAHostname
        $config.'new.vcsa'.os.password = $VCSARootPassword
        if($VCSASSHEnable -eq "true") {
            $VCSASSHEnableVar = $true
        } else {
            $VCSASSHEnableVar = $false
        }
        $config.'new.vcsa'.os.'ssh.enable' = $VCSASSHEnableVar
        $config.'new.vcsa'.sso.password = $VCSASSOPassword
        $config.'new.vcsa'.sso.'domain-name' = $VCSASSODomainName
        $config.'new.vcsa'.sso.'site-name' = $VCSASSOSiteName

        My-Logger "Creating VCSA JSON Configuration file for deployment ..."
        $config | ConvertTo-Json | Set-Content -Path "$($ENV:Temp)\jsontemplate.json"

        My-Logger "Deploying the VCSA ..."
        Invoke-Expression "$($VCSAInstallerPath)\vcsa-cli-installer\win32\vcsa-deploy.exe install --no-esx-ssl-verify --accept-eula --acknowledge-ceip $($ENV:Temp)\jsontemplate.json"| Out-File -Append -LiteralPath $verboseLogFile
}

if($moveVMsIntovApp -eq 1) {
    My-Logger "Creating vApp $VAppName ..."
    $VApp = New-VApp -Name $VAppName -Server $viConnection -Location $cluster

    if($deployNestedESXiVMs -eq 1) {
        My-Logger "Moving Nested ESXi VMs into $VAppName vApp ..."
        $NestedESXiHostnameToIPs.GetEnumerator() | Sort-Object -Property Value | Foreach-Object {
            $vm = Get-VM -Name $_.Key -Server $viConnection
            Move-VM -VM $vm -Server $viConnection -Destination $VApp -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile
        }
    }

    if($deployVCSA -eq 1) {
        $vcsaVM = Get-VM -Name $VCSADisplayName -Server $viConnection
        My-Logger "Moving $VCSADisplayName into $VAppName vApp ..."
        Move-VM -VM $vcsaVM -Server $viConnection -Destination $VApp -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile
    }

    if($DeployNSX -eq 1) {
        $nsxMgrVM = Get-VM -Name $NSXTMgrDisplayName -Server $viConnection
        My-Logger "Moving $NSXTMgrDisplayName into $VAppName vApp ..."
        Move-VM -VM $nsxMgrVM -Server $viConnection -Destination $VApp -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile

        My-Logger "Moving NSX Controller VMs into $VAppName vApp ..."
        $NSXTControllerHostnameToIPs.GetEnumerator() | Sort-Object -Property Value | Foreach-Object {
            $nsxCtrVM = Get-VM -Name $_.Key -Server $viConnection
            Move-VM -VM $nsxCtrVM -Server $viConnection -Destination $VApp -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile
        }

        My-Logger "Moving NSX Edge VMs into $VAppName vApp ..."
        $NSXTEdgeHostnameToIPs.GetEnumerator() | Sort-Object -Property Value | Foreach-Object {
            $nsxEdgeVM = Get-VM -Name $_.Key -Server $viConnection
            Move-VM -VM $nsxEdgeVM -Server $viConnection -Destination $VApp -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile
        }
    }
}

My-Logger "Disconnecting from $VIServer ..."
Disconnect-VIServer -Server $viConnection -Confirm:$false

if($setupNewVC -eq 1) {
    My-Logger "Connecting to the new VCSA ..."
    $vc = Connect-VIServer $VCSAIPAddress -User "administrator@$VCSASSODomainName" -Password $VCSASSOPassword -WarningAction SilentlyContinue

    My-Logger "Creating Datacenter $NewVCDatacenterName ..."
    New-Datacenter -Server $vc -Name $NewVCDatacenterName -Location (Get-Folder -Type Datacenter -Server $vc) | Out-File -Append -LiteralPath $verboseLogFile

    My-Logger "Creating VSAN Cluster $NewVCVSANClusterName ..."
    New-Cluster -Server $vc -Name $NewVCVSANClusterName -Location (Get-Datacenter -Name $NewVCDatacenterName -Server $vc) -DrsEnabled -VsanEnabled -VsanDiskClaimMode 'Manual' | Out-File -Append -LiteralPath $verboseLogFile

    if($addESXiHostsToVC -eq 1) {
        $NestedESXiHostnameToIPs.GetEnumerator() | sort -Property Value | Foreach-Object {
            $VMName = $_.Key
            $VMIPAddress = $_.Value

            $targetVMHost = $VMIPAddress
            if($addHostByDnsName -eq 1) {
                $targetVMHost = $VMName
            }
            My-Logger "Adding ESXi host $targetVMHost to Cluster ..."
            Add-VMHost -Server $vc -Location (Get-Cluster -Name $NewVCVSANClusterName) -User "root" -Password $VMPassword -Name $targetVMHost -Force | Out-File -Append -LiteralPath $verboseLogFile
        }
    }

    if($configureVSANDiskGroups -eq 1) {
        My-Logger "Enabling VSAN & disabling VSAN Health Check ..."
        Get-VsanClusterConfiguration -Server $vc -Cluster $NewVCVSANClusterName | Set-VsanClusterConfiguration -HealthCheckIntervalMinutes 0 | Out-File -Append -LiteralPath $verboseLogFile


        foreach ($vmhost in Get-Cluster -Server $vc | Get-VMHost) {
            $luns = $vmhost | Get-ScsiLun | select CanonicalName, CapacityGB

            My-Logger "Querying ESXi host disks to create VSAN Diskgroups ..."
            foreach ($lun in $luns) {
                if(([int]($lun.CapacityGB)).toString() -eq "$NestedESXiCachingvDisk") {
                    $vsanCacheDisk = $lun.CanonicalName
                }
                if(([int]($lun.CapacityGB)).toString() -eq "$NestedESXiCapacityvDisk") {
                    $vsanCapacityDisk = $lun.CanonicalName
                }
            }
            My-Logger "Creating VSAN DiskGroup for $vmhost ..."
            New-VsanDiskGroup -Server $vc -VMHost $vmhost -SsdCanonicalName $vsanCacheDisk -DataDiskCanonicalName $vsanCapacityDisk | Out-File -Append -LiteralPath $verboseLogFile
          }
    }

    if($clearVSANHealthCheckAlarm -eq 1) {
        My-Logger "Clearing default VSAN Health Check Alarms, not applicable in Nested ESXi env ..."
        $alarmMgr = Get-View AlarmManager -Server $vc
        Get-Cluster -Server $vc | where {$_.ExtensionData.TriggeredAlarmState} | %{
            $cluster = $_
            $Cluster.ExtensionData.TriggeredAlarmState | %{
                $alarmMgr.AcknowledgeAlarm($_.Alarm,$cluster.ExtensionData.MoRef)
            }
        }
    }

    # Exit maintanence mode in case patching was done earlier
    foreach ($vmhost in Get-Cluster -Server $vc | Get-VMHost) {
        if($vmhost.ConnectionState -eq "Maintenance") {
            Set-VMHost -VMhost $vmhost -State Connected -RunAsync -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile
        }
    }

    My-Logger "Disconnecting from new VCSA ..."
    Disconnect-VIServer $vc -Confirm:$false
}

if($initialNSXConfig -eq 1 -and $DeployNSX -eq 1) {
    if(!(Connect-NsxtServer -Server $NSXTMgrHostname -Username $NSXAdminUsername -Password $NSXAdminPassword -WarningAction SilentlyContinue)) {
        Write-Host -ForegroundColor Red "Unable to connect to NSX Manager, please check the deployment"
        exit
    } else {
        My-Logger "Successfully logged into NSX Manager $NSXTMgrHostname  ..."
    }

    My-Logger "Connecting back to Management vCenter Server $VIServer ..."
    Connect-VIServer $VIServer -User $VIUsername -Password $VIPassword -WarningAction SilentlyContinue | Out-Null

    # Retrieve NSX Manager Thumbprint which will be needed later
    My-Logger "Retrieving NSX Manager Thumbprint ..."
    $nsxMgrID = (Get-NsxtService -Name "com.vmware.nsx.cluster.nodes").list().results.id
    $nsxMgrCertThumbprint = (Get-NsxtService -Name "com.vmware.nsx.cluster.nodes").get($nsxMgrID).manager_role.api_listen_addr.certificate_sha256_thumbprint

    ### Setup NSX Controllers
    $ctrCount=0
    $firstNSXController = ""
    $nsxControllerCertThumbprint  = ""
    $NSXTControllerHostnameToIPs.GetEnumerator() | Sort-Object -Property Value | Foreach-Object {
        $nsxCtrName = $_.name
        $nsxCtrIp = $_.value

        if($ctrCount -eq 0) {
            My-Logger "Configuring NSX Controller $nsxCtrName as control-cluster master ..."
            # Store the first NSX Controller for later use
            $firstNSXController = $nsxCtrName

            # Login by passing in admin username <enter>
            if($debug) { My-Logger "Sending admin username ..." }
            Set-VMKeystrokes -VMName $nsxCtrName -StringInput $NSXAdminUsername -ReturnCarriage $true
            Start-Sleep 2

            # Login by passing in admin password <enter>
            if($debug) { My-Logger "Sending admin password ..." }
            Set-VMKeystrokes -VMName $nsxCtrName -StringInput $NSXAdminPassword -ReturnCarriage $true
            Start-Sleep 5

            # Join Controller to NSX Manager
            if($debug) { My-Logger "Sending join management plane command ..." }
            $joinMgmtCmd1 = "join management-plane $NSXTMgrIPAddress username $NSXAdminUsername thumbprint $nsxMgrCertThumbprint"
            $joinMgmtCmd2 = "$NSXAdminPassword"
            Set-VMKeystrokes -VMName $nsxCtrName -StringInput $joinMgmtCmd1 -ReturnCarriage $true
            Start-Sleep 5
            Set-VMKeystrokes -VMName $nsxCtrName -StringInput $joinMgmtCmd2 -ReturnCarriage $true
            Start-Sleep 25

            # Setup shared secret
            if($debug) { My-Logger "Sending shared secret command ..." }
            $sharedSecretCmd = "set control-cluster security-model shared-secret secret $NSXControllerSharedSecret"
            Set-VMKeystrokes -VMName $nsxCtrName -StringInput $sharedSecretCmd -ReturnCarriage $true
            Start-Sleep  5

            # Initialize NSX Controller Cluster
            if($debug) { My-Logger "Sending control cluster init command ..." }
            $initCmd = "initialize control-cluster"
            Set-VMKeystrokes -VMName $nsxCtrName -StringInput $initCmd -ReturnCarriage $true
            Start-Sleep 25
        } else {
            My-Logger "Configuring additional NSX Controller $nsxCtrName ..."

            # Login by passing in admin username <enter>
            if($debug) { My-Logger "Sending admin username ..." }
            Set-VMKeystrokes -VMName $nsxCtrName -StringInput $NSXAdminUsername -ReturnCarriage $true
            Start-Sleep 2

            # Login by passing in admin password <enter>
            if($debug) { My-Logger "Sending admin password ..." }
            Set-VMKeystrokes -VMName $nsxCtrName -StringInput $NSXAdminPassword -ReturnCarriage $true
            Start-Sleep 5

            # Join Controller to NSX Manager
            if($debug) { My-Logger "Sending join management plane command ..." }
            $joinMgmtCmd1 = "join management-plane $NSXTMgrIPAddress username $NSXAdminUsername thumbprint $nsxMgrCertThumbprint"
            $joinMgmtCmd2 = "$NSXAdminPassword"
            Set-VMKeystrokes -VMName $nsxCtrName -StringInput $joinMgmtCmd1 -ReturnCarriage $true
            Start-Sleep 5
            Set-VMKeystrokes -VMName $nsxCtrName -StringInput $joinMgmtCmd2 -ReturnCarriage $true
            Start-Sleep 25

            # Setup shared secret
            if($debug) { My-Logger "Sending shared secret command ..." }
            $sharedSecretCmd = "set control-cluster security-model shared-secret secret $NSXControllerSharedSecret"
            Set-VMKeystrokes -VMName $nsxCtrName -StringInput $sharedSecretCmd -ReturnCarriage $true
            Start-Sleep 5

            ### --- (stupid hack because we don't have an API) --- ###
                # Exit from nsxcli
                if($debug) { My-Logger "Sending exit command ..." }
                Set-VMKeystrokes -VMName $nsxCtrName -StringInput "exit" -ReturnCarriage $true
                Start-Sleep 10

                # Login using root
                if($debug) { My-Logger "Sending root username ..." }
                Set-VMKeystrokes -VMName $nsxCtrName -StringInput "root" -ReturnCarriage $true
                Start-Sleep 2

                # Login by passing in root password <enter>
                if($debug) { My-Logger "Sending root password ..." }
                Set-VMKeystrokes -VMName $nsxCtrName -StringInput $NSXRootPassword -ReturnCarriage $true
                Start-Sleep 10

                # Retrieve Control Cluster Thumbprint by running nsxcli in the shell and
                # storing the thumbprint to a file which we will download later
                if($debug) { My-Logger "Sending get control cluster cert ..." }
                $ctrClusterThumbprintCmd = "nsxcli -c `"get control-cluster certificate thumbprint`" > /tmp/controller-thumbprint"
                Set-VMKeystrokes -VMName $nsxCtrName -StringInput $ctrClusterThumbprintCmd -ReturnCarriage $true
                Start-Sleep 25

                if($debug) { My-Logger "Processing certificate thumbprint ..." }
                Copy-VMGuestFile -vm (Get-VM -Name $nsxCtrName) -GuestToLocal -GuestUser "root" -GuestPassword $NSXRootPassword -Source /tmp/controller-thumbprint -Destination $ENV:TMP\controller-thumbprint | Out-Null
                $nsxControllerCertThumbprint = Get-Content -Path $ENV:TMP\controller-thumbprint | ? {$_.trim() -ne "" }

                # Exit from shell
                if($debug) { My-Logger "Sending exit command ..." }
                Set-VMKeystrokes -VMName $nsxCtrName -StringInput "exit" -ReturnCarriage $true
                Start-Sleep 10
            ### --- (stupid hack because we don't have an API) --- ###

            # Login by passing in admin username <enter>
            if($debug) { My-Logger "Sending admin username ..." }
            Set-VMKeystrokes -VMName $nsxCtrName -StringInput $NSXAdminUsername -ReturnCarriage $true
            Start-Sleep 2

            # Login by passing in admin password <enter>
            if($debug) { My-Logger "Sending admin password ..." }
            Set-VMKeystrokes -VMName $nsxCtrName -StringInput $NSXAdminPassword -ReturnCarriage $true
            Start-Sleep 5

            # Join NSX Controller to NSX Controller Cluster
            if($debug) { My-Logger "Sending join control cluster command ..." }
            $joinCtrCmd = "join control-cluster $nsxCtrIp thumbprint $nsxControllerCertThumbprint"
            Set-VMKeystrokes -VMName $firstNSXController -StringInput $joinCtrCmd -ReturnCarriage $true
            Start-Sleep 30

            # Activate NSX Controller
            if($debug) { My-Logger "Sending control cluster activate command ..." }
            $initCmd = "activate control-cluster"
            Set-VMKeystrokes -VMName $nsxCtrName -StringInput $initCmd -ReturnCarriage $true
            Start-Sleep 30

            # Exit Console
            if($debug) { My-Logger "Sending final exit ..." }
            Set-VMKeystrokes -VMName $nsxCtrName -StringInput "exit" -ReturnCarriage $true
        }
        $ctrCount++
    }

    ### Setup NSX Edges
    $NSXTEdgeHostnameToIPs.GetEnumerator() | Sort-Object -Property Value | Foreach-Object {
        $nsxEdgeName = $_.name
        $nsxEdgeIp = $_.value

        My-Logger "Configuring NSX Edge $nsxEdgeName ..."

        # Login by passing in admin username <enter>
        if($debug) { My-Logger "Sending admin username ..." }
        Set-VMKeystrokes -VMName $nsxEdgeName -StringInput $NSXAdminUsername -ReturnCarriage $true
        Start-Sleep 2

        # Login by passing in admin password <enter>
        if($debug) { My-Logger "Sending admin password ..." }
        Set-VMKeystrokes -VMName $nsxEdgeName -StringInput $NSXAdminPassword -ReturnCarriage $true
        Start-Sleep 5

        # Join Controller to NSX Manager
        if($debug) { My-Logger "Sending join management plane command ..." }
        $joinMgmtCmd1 = "join management-plane $NSXTMgrIPAddress username $NSXAdminUsername thumbprint $nsxMgrCertThumbprint"
        $joinMgmtCmd2 = "$NSXAdminPassword"
        Set-VMKeystrokes -VMName $nsxEdgeName -StringInput $joinMgmtCmd1 -ReturnCarriage $true
        Start-Sleep 5
        Set-VMKeystrokes -VMName $nsxEdgeName -StringInput $joinMgmtCmd2 -ReturnCarriage $true
        Start-Sleep 20

        # Exit Console
        if($debug) { My-Logger "Sending final exit ..." }
        Set-VMKeystrokes -VMName $nsxEdgeName -StringInput "exit" -ReturnCarriage $true
    }

    # Exit Console for first NSX Controller
    if($debug) { My-Logger "Sending final exit to initial Controller ..." }
    Set-VMKeystrokes -VMName $firstNSXController -StringInput "exit" -ReturnCarriage $true

    My-Logger "Disconnecting from NSX Manager ..."
    Disconnect-NsxtServer -Confirm:$false

    My-Logger "Disconnecting from Management vCenter ..."
    Disconnect-VIServer * -Confirm:$false
}

if($postDeployNSXConfig -eq 1 -and $DeployNSX -eq 1) {
    if(!(Connect-NsxtServer -Server $NSXTMgrHostname -Username $NSXAdminUsername -Password $NSXAdminPassword -WarningAction SilentlyContinue)) {
        Write-Host -ForegroundColor Red "Unable to connect to NSX Manager, please check the deployment"
        exit
    } else {
        My-Logger "Successfully logged into NSX Manager $NSXTMgrHostname  ..."
    }

    $runHealth=$true
    $runEULA=$true
    $runIPPool=$true
    $runTransportZone=$true
    $runAddVC=$true
    $runLogicalSwitch=$true
    $runHostPrep=$true
    $runUplinkProfile=$true
    $runAddTransportNode=$true

    ### Verify Health for all Nodes
    if($runHealth) {
        My-Logger "Verifying health of all NSX Manager/Controller Nodes ..."
        $clusterNodeService = Get-NsxtService -Name "com.vmware.nsx.cluster.nodes"
        $clusterNodeStatusService = Get-NsxtService -Name "com.vmware.nsx.cluster.nodes.status"
        $nodes = $clusterNodeService.list().results
        $mgmtNodes = $nodes | where { $_.controller_role -eq $null }
        $controllerNodes = $nodes | where { $_.manager_role -eq $null }

        foreach ($mgmtNode in $mgmtNodes) {
            $mgmtNodeId = $mgmtNode.id
            $mgmtNodeName = $mgmtNode.appliance_mgmt_listen_addr

            if($debug) { My-Logger "Check health status of Mgmt Node $mgmtNodeName ..." }
            while ( $clusterNodeStatusService.get($mgmtNodeId).mgmt_cluster_status.mgmt_cluster_status -ne "CONNECTED") {
                if($debug) { My-Logger "$mgmtNodeName is not ready, sleeping 20 seconds ..." }
                Start-Sleep 20
            }
        }

        foreach ($controllerNode in $controllerNodes) {
            $controllerNodeId = $controllerNode.id
            $controllerNodeName = $controllerNode.controller_role.control_plane_listen_addr.ip_address

            if($debug) { My-Logger "Checking health of Ctrl Node $controllerNodeName ..." }
            while ( $clusterNodeStatusService.get($controllerNodeId).control_cluster_status.control_cluster_status -ne "CONNECTED") {
                if($debug) { My-Logger "$controllerNodeName is not ready, sleeping 20 seconds ..." }
                Start-Sleep 20
            }
        }
    }

    ### Accept EULA
    if($runEULA) {
        My-Logger "Accepting NSX Manager EULA ..."
        $eulaService = Get-NsxtService -Name "com.vmware.nsx.eula.accept"
        $eulaService.create()
    }

    if($runIPPool) {
        My-Logger "Creating Tunnel Endpoint IP Pool ..."
        $ipPoolService = Get-NsxtService -Name "com.vmware.nsx.pools.ip_pools"
        $ipPoolSpec = $ipPoolService.help.create.ip_pool.Create()
        $subNetSpec = $ipPoolService.help.create.ip_pool.subnets.Element.Create()
        $allocationRangeSpec = $ipPoolService.help.create.ip_pool.subnets.Element.allocation_ranges.Element.Create()

        $allocationRangeSpec.start = $TunnelEndpointIPRangeStart
        $allocationRangeSpec.end = $TunnelEndpointIPRangeEnd
        $addResult = $subNetSpec.allocation_ranges.Add($allocationRangeSpec)
        $subNetSpec.cidr = $TunnelEndpointCIDR
        $subNetSpec.gateway_ip = $TunnelEndpointGateway
        $ipPoolSpec.display_name = $TunnelEndpointName
        $ipPoolSpec.description = $TunnelEndpointDescription
        $addResult = $ipPoolSpec.subnets.Add($subNetSpec)
        $ipPool = $ipPoolService.create($ipPoolSpec)
    }

    if($runTransportZone) {
        My-Logger "Creating Overlay & VLAN Transport Zones ..."
        $transportZoneService = Get-NsxtService -Name "com.vmware.nsx.transport_zones"
        $overlayTZSpec = $transportZoneService.help.create.transport_zone.Create()
        $overlayTZSpec.display_name = $OverlayTransportZoneName
        $overlayTZSpec.host_switch_name = $OverlayTransportZoneHostSwitchName
        $overlayTZSpec.transport_type = "OVERLAY"
        $overlayTZ = $transportZoneService.create($overlayTZSpec)

        $vlanTZSpec = $transportZoneService.help.create.transport_zone.Create()
        $vlanTZSpec.display_name = $VLANTransportZoneName
        $vlanTZSpec.host_switch_name = $VLANTransportZoneHostSwitchName
        $vlanTZSpec.transport_type = "VLAN"
        $vlanTZ = $transportZoneService.create($vlanTZSpec)
    }

    if($runAddVC) {
        My-Logger "Adding vCenter Server Compute Manager ..."
        $computeManagerSerivce = Get-NsxtService -Name "com.vmware.nsx.fabric.compute_managers"
        $computeManagerStatusService = Get-NsxtService -Name "com.vmware.nsx.fabric.compute_managers.status"

        $computeManagerSpec = $computeManagerSerivce.help.create.compute_manager.Create()
        $credentialSpec = $computeManagerSerivce.help.create.compute_manager.credential.username_password_login_credential.Create()
        $VCUsername = "administrator@$VCSASSODomainName"
        $VCURL = "https://" + $VCSAHostname + ":443"
        $VCThumbprint = Get-SSLThumbprint256 -URL $VCURL
        $credentialSpec.username = $VCUsername
        $credentialSpec.password = $VCSASSOPassword
        $credentialSpec.thumbprint = $VCThumbprint
        $computeManagerSpec.server = $VCSAHostname
        $computeManagerSpec.origin_type = "vCenter"
        $computeManagerSpec.display_name = $VCSAHostname
        $computeManagerSpec.credential = $credentialSpec
        $computeManagerResult = $computeManagerSerivce.create($computeManagerSpec)

        if($debug) { My-Logger "Waiting for VC registration to complete ..." }
            while ( $computeManagerStatusService.get($computeManagerResult.id).registration_status -ne "REGISTERED") {
                if($debug) { My-Logger "$VCSAHostname is not ready, sleeping 30 seconds ..." }
                Start-Sleep 30
        }
    }

    if($runLogicalSwitch) {
        My-Logger "Adding Logical Switch for Edge Uplink ..."
        $logicalSwitchService = Get-NsxtService -Name "com.vmware.nsx.logical_switches"
        $logicalSwitchSpec = $logicalSwitchService.help.create.logical_switch.Create()
        $logicalSwitchSpec.display_name = $LogicalSwitchName
        $logicalSwitchSpec.admin_state = "UP"
        $logicalSwitchSpec.vlan = $LogicalSwitchVlan
        $logicalSwitchSpec.transport_zone_id = $vlanTZ.id
        $uplinkLogicalSwitch = $logicalSwitchService.create($logicalSwitchSpec)
    }

    if($runHostPrep) {
        My-Logger "Preparing ESXi hosts & Installing NSX VIBs ..."
        $computeCollectionService = Get-NsxtService -Name "com.vmware.nsx.fabric.compute_collections"
        $computeId = $computeCollectionService.list().results[0].external_id

        $computeCollectionFabricTemplateService = Get-NsxtService -Name "com.vmware.nsx.fabric.compute_collection_fabric_templates"
        $computeFabricTemplateSpec = $computeCollectionFabricTemplateService.help.create.compute_collection_fabric_template.Create()
        $computeFabricTemplateSpec.auto_install_nsx = $true
        $computeFabricTemplateSpec.compute_collection_id = $computeId
        $computeCollectionFabric = $computeCollectionFabricTemplateService.create($computeFabricTemplateSpec)

        My-Logger "Waiting for ESXi hosts to finish host prep ..."
        $fabricNodes = (Get-NsxtService -Name "com.vmware.nsx.fabric.nodes").list().results | where { $_.resource_type -eq "HostNode" }
        foreach ($fabricNode in $fabricNodes) {
            $fabricNodeName = $fabricNode.display_name
            while ((Get-NsxtService -Name "com.vmware.nsx.fabric.nodes.status").get($fabricNode.external_id).host_node_deployment_status -ne "INSTALL_SUCCESSFUL") {
                if($debug) { My-Logger "ESXi hosts are still being prepped, sleeping for 30 seconds ..." }
                Start-Sleep 30
            }
        }
    }

    if($runUplinkProfile) {
        My-Logger "Creating ESXi Uplink Profile ..."
        $hostSwitchProfileService = Get-NsxtService -Name "com.vmware.nsx.host_switch_profiles"
        $ESXiUplinkProfileSpec = $hostSwitchProfileService.help.create.base_host_switch_profile.uplink_host_switch_profile.Create()
        $activeUplinkSpec = $hostSwitchProfileService.help.create.base_host_switch_profile.uplink_host_switch_profile.teaming.active_list.Element.Create()
        $activeUplinkSpec.uplink_name = $ESXiUplinkProfileActivepNIC
        $activeUplinkSpec.uplink_type = "PNIC"
        $ESXiUplinkProfileSpec.display_name = $ESXiUplinkProfileName
        $ESXiUplinkProfileSpec.mtu = $ESXiUplinkProfileMTU
        $ESXiUplinkProfileSpec.transport_vlan = $ESXiUplinkProfileTransportVLAN
        $addActiveUplink = $ESXiUplinkProfileSpec.teaming.active_list.Add($activeUplinkSpec)
        $ESXiUplinkProfileSpec.teaming.policy = $ESXiUplinkProfilePolicy
        $ESXiUplinkProfile = $hostSwitchProfileService.create($ESXiUplinkProfileSpec)
    }

    if($runAddTransportNode) {
        $transportNodeService = Get-NsxtService -Name "com.vmware.nsx.transport_nodes"
        $transportNodeStateService = Get-NsxtService -Name "com.vmware.nsx.transport_nodes.state"

        # preferred spec, but unable to get it working due to complex nested structure and poor error messaging :(
        <#
        $hostSwitchSpec = $transportNodeService.help.create.transport_node.host_switch_spec.standard_host_switch_spec.Create()
        $hostSwitchesSpec = $transportNodeService.help.create.transport_node.host_switch_spec.standard_host_switch_spec.host_switches.Element.Create()
        $hostSwitchProfileSpec = $transportNodeService.help.create.transport_node.host_switch_spec.standard_host_switch_spec.host_switches.Element.host_switch_profile_ids.Element.Create()
        $ipAssignmentSpec = $transportNodeService.help.create.transport_node.host_switch_spec.standard_host_switch_spec.host_switches.Element.ip_assignment_spec.static_ip_pool_spec.Create()
        $pnicSpec = $transportNodeService.help.create.transport_node.host_switch_spec.standard_host_switch_spec.host_switches.Element.pnics.Element.Create()
        $transportZoneEPSpec = $transportNodeService.help.create.transport_node.transport_zone_endpoints.Element.Create()
        #>

        # Retrieve all ESXi Host Nodes
        $hostNodes = (Get-NsxtService -Name "com.vmware.nsx.fabric.nodes").list().results | where { $_.resource_type -eq "HostNode" }
        $ESXiUplinkProfile = (Get-NsxtService -Name "com.vmware.nsx.host_switch_profiles").list().results[0]
        $ipPool = (Get-NsxtService -Name "com.vmware.nsx.pools.ip_pools").list().results[0]
        $vlanTZ = (Get-NsxtService -Name "com.vmware.nsx.transport_zones").list().results | where { $_.transport_type -eq "VLAN" }

        foreach ($hostNode in $hostNodes) {
            $hostNodeName = $hostNode.display_name
            My-Logger "Adding $hostNodeName Transport Node ..."

            # Create all required empty specs
            $transportNodeSpec = $transportNodeService.help.create.transport_node.Create()
            $hostSwitchSpec = $transportNodeService.help.create.transport_node.host_switches.Element.Create()
            $hostSwitchProfileSpec = $transportNodeService.help.create.transport_node.host_switches.Element.host_switch_profile_ids.Element.Create()
            $pnicSpec = $transportNodeService.help.create.transport_node.host_switches.Element.pnics.Element.Create()
            $transportZoneEPSpec = $transportNodeService.help.create.transport_node.transport_zone_endpoints.Element.Create()

            <# Other Spec based on non-depercated API but can't get it working as mentioned above due to poor error message
            $transportNodeSpec.resource_type = "TransportNode"
            $transportNodeSpec.display_name = $hostNodeName

            $hostSwitchesSpec.host_switch_name = "nsxDefaultHostSwitch"

            $pnicSpec.device_name = "vmnic2"
            $pnicSpec.uplink_name = "vmnic2"
            $hostSwitchesSpec.pnics.Add($pnicSpec)

            $ipAssignmentSpec.resource_type = "StaticIpPoolSpec"
            $ipAssignmentSpec.ip_pool_id = $ipPool.id
            $hostSwitchesSpec.ip_assignment_spec = $ipAssignmentSpec

            $hostSwitchProfileSpec.key = "UplinkHostSwitchProfile"
            $hostSwitchProfileSpec.value = $ESXiUplinkProfile.id
            $hostSwitchesSpec.host_switch_profile_ids.Add($hostSwitchProfileSpec)

            $hostSwitchSpec.resource_type = "StandardHostSwitchSpec"
            $hostSwitchSpec.host_switches.Add($hostSwitchesSpec)
            $transportNodeSpec.host_switch_spec = $hostSwitchSpec

            $transportZoneEPSpec.transport_zone_id = $vlanTZ.id
            $transportNodeSpec.transport_zone_endpoints.Add($transportZoneEPSpec)

            $transportNodeSpec.node_id = $hostNode.id
            #>

            $transportNodeSpec.display_name = $hostNodeName
            $hostSwitchSpec.host_switch_name = "nsxDefaultHostSwitch"
            $hostSwitchProfileSpec.key = "UplinkHostSwitchProfile"
            $hostSwitchProfileSpec.value = $ESXiUplinkProfile.id
            $pnicSpec.device_name = $ESXiUplinkProfileActivepNIC
            $pnicSpec.uplink_name = $ESXiUplinkProfileActivepNIC
            $hostSwitchSpec.static_ip_pool_id = $ipPool.id
            $pnicAddResult = $hostSwitchSpec.pnics.Add($pnicSpec)
            $switchProfileAddResult = $hostSwitchSpec.host_switch_profile_ids.Add($hostSwitchProfileSpec)
            $switchAddResult = $transportNodeSpec.host_switches.Add($hostSwitchSpec)
            $transportZoneEPSpec.transport_zone_id = $vlanTZ.id
            $transportZoneAddResult = $transportNodeSpec.transport_zone_endpoints.Add($transportZoneEPSpec)
            $transportNodeSpec.node_id = $hostNode.id
            $transportNode = $transportNodeService.create($transportNodeSpec)

            My-Logger "Waiting for transport node configurations to complete ..."
            while ($transportNodeStateService.get($transportNode.id).state -ne "success") {
                if($debug) { My-Logger "ESXi transport node still being configured, sleeping for 30 seconds ..." }
                Start-Sleep 30
            }
        }
    }
    My-Logger "Disconnecting from NSX Manager ..."
    Disconnect-NsxtServer * -Confirm:$false
}

$EndTime = Get-Date
$duration = [math]::Round((New-TimeSpan -Start $StartTime -End $EndTime).TotalMinutes,2)

My-Logger "NSX-T 2.0 Lab Deployment Complete!"
My-Logger "StartTime: $StartTime"
My-Logger "  EndTime: $EndTime"
My-Logger " Duration: $duration minutes"