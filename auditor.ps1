#Check if you need to elevate your permissions and do so
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { 
Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit
}

#Dump output to file
$CurrentDir = $PSScriptRoot
$ServerName = $env:computername
$DumpFilePath = "$CurrentDir\"+$ServerName+"-CONFIG_DUMP_$(get-date -Format yyyymmdd_hhmmtt).txt"

Start-Transcript -Path $DumpFilePath -NoClobber

#Check execution policy. Set to Unrestricted for testing.
Write-Host
Write-Host 'Checking if your PowerShell Script Execution Policy is set to Unrestricted' -ForegroundColor Yellow -BackgroundColor Black
Start-Sleep -s 5
Write-Host
$ExecutionPolicy = Get-ExecutionPolicy
$ScriptExecution = "Unrestricted"
    If ($ExecutionPolicy -eq $ScriptExecution) 
        {
            Write-Host 'Your PowerShell Script Execution Policy is already set to ' $ExecutionPolicy -ForegroundColor Yellow -BackgroundColor Black
        }
    Else
        {
            Write-Host Your PowerShell Script Execution Policy is set to $ExecutionPolicy -ForegroundColor Yellow -BackgroundColor Black
            Write-Host
            Write-Host 'This policy should be set to Unrestricted for the script to execute properly.' -ForegroundColor Magenta -BackgroundColor Black
            Write-Host
            Write-Host 'This change will be reverted back to its original state after script execution is complete.' -ForegroundColor Magenta -BackgroundColor Black
            Write-Host
            Write-Host 'Setting PowerShell Script Execution Policy to Unrestricted automatically. Please Wait...'
            Start-Sleep -s 5
            
            Set-ExecutionPolicy Unrestricted -force
        
            Write-Host
            Write-Host 'PowerShell Script Execution Policy is now set to Unrestricted.' -ForegroundColor Yellow -BackgroundColor Black
            Start-Sleep -s 5
        }
"`n"

"======================="
"POWERSHELL AUDIT SCRIPT"
"=======================`n"

#Script information

"================================================================="
"PowerShell Script for Windows Server Security Configuration Audit"
"=================================================================`n"
Write-Host
<# 
===============
CURRENT VERSION
===============

Version Details: V1.0.0
#>

"`n==============================="
"1.0. AUTHOR COMPANY INFORMATION"
"===============================`n"
Write-Host
$Author = @"
Eric Ambrosy - https://github.com/ambrosy-eric
"@
Write-Output $Author

"`n========================"
"2.0. GENERAL INFORMATION" 
"========================`n"
#Audit script
Write-Host


"`n================"
"TIME INFORMATION"
"================`n"
 #Display time and check time's accuracy
    Get-Date
    w32tm /query /computer:$ServerName /status | Out-Host


"`n=========================================================="
"OPERATING SYSTEM / SERVICE PACK / ARCHITECTURE INFORMATION"
"==========================================================`n"
#Display OS information such as OS version, OS Architecture (i.e. 64-bit) and Service Pack installed
$sServer = "."
$sOS =Get-WmiObject -class Win32_OperatingSystem -computername $sServer
$sOS | Select-Object Description, Caption, OSArchitecture, ServicePackMajorVersion | Format-List | Out-Host

"`n=================="
"SERVER INFORMATION"
"==================`n"
    Get-WmiObject Win32_OperatingSystem | FL * | Out-Host

"`n========================"
"GROUP POLICY INFORMATION"
"========================`n"
#Prints group policies in place on machine
    gpresult /V | Out-Host

"`n===================================="
"2.1. AUDITING / LOGGING / MONITORING"
"====================================`n"


"`n====================="
"2.1.1. AUDITING CHECK"
"=====================`n"
#Check if auditing for user accounts is enabled.
#No accounts displayed means no user account logging is in place.
    AuditPol /List /user /v | Out-Host

"`n========================"
"LISTING AUDIT CATEGORIES"
"========================`n"
#List categories where aduiting is enabled
    AuditPol /list /category | Out-Host

"`n============================"
"LISTING AUDIT SUB-CATEGORIES"
"============================`n"
#List subcategories of what is being logged from above
    AuditPol /list /subcategory:* | Out-Host

"`n==============================================="
"USER-LEVEL AUDIT SETTINGS FOR ALL USER ACCOUNTS"
"===============================================`n"
#List adit setting for users (Error 0x00000534 will occur if there are no specific user audit settings)
    AuditPol /get /user:* /category:* | Out-Host

"`n==========================================================="
"USER-LEVEL AUDIT SETTINGS FOR DEFAULT ADMINISTRATOR ACCOUNT"
"===========================================================`n"
    Auditpol /get /user:Administrator /category:* | Out-Host

"`n==================================================="
"USER-LEVEL AUDIT SETTINGS FOR DEFAULT GUEST ACCOUNT"
"===================================================`n"
    Auditpol /get /user:Guest /category:* | Out-Host

"`n===================================="
"SYSTEM-LEVEL AUDIT CATEGORY SETTINGS"
"====================================`n"
    AuditPol /get /category:* | Out-Host

"`n========================="
"CrashOnAuditFail SETTINGS"
"=========================`n"
    auditpol /get /option:CrashOnAuditFail | Out-Host

"`n==============================="
"FULL PrivilegeAuditing SETTINGS"
"===============================`n"
    auditpol /get /option:FullPrivilegeAuditing | Out-Host


"`n==========================="
"AUDIT BASE OBJECTS SETTINGS"
"===========================`n"
#Check auditing to access system kernel
    auditpol /get /option:AuditBaseObjects | Out-Host

"`n================================"
"2.1.2. PERMISSIONS ON EVENT LOGS"
"================================`n"

"`n================================="
"APPLICATION EVENT LOG PERMISSIONS"
"=================================`n"
#Check Event log premissions Restrict Guest Access value in registry should be set to 1.
    Write-Host "Restrict Guest Access Value in Registry is set to " -NoNewline
    (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Application').RestrictGuestAccess

"`n============================"
"SYSTEM EVENT LOG PERMISSIONS"
"============================`n"
    Write-Host "Restrict Guest Access Value in Registry is set to " -NoNewline
    (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\System').RestrictGuestAccess

"`n=============================="
"SECURITY EVENT LOG PERMISSIONS"
"==============================`n"
    Write-Host "Restrict Guest Access Value in Registry is set to " -NoNewline
    (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security').RestrictGuestAccess

"`n================================================================================"
"DISPLAYING DISCRETIONARY ACCESS CONTROL LISTS ('DACLS') ON APPLICATION EVENT LOG"
"================================================================================`n"
    icacls "C:\WINDOWS\system32\winevt\Logs\Application.evtx" | Out-Host

"`n==========================================================================="
"DISPLAYING DISCRETIONARY ACCESS CONTROL LISTS ('DACLS') ON SYSTEM EVENT LOG"
"===========================================================================`n"
    icacls "C:\WINDOWS\system32\winevt\Logs\System.evtx" | Out-Host

"`n============================================================================="
"DISPLAYING DISCRETIONARY ACCESS CONTROL LISTS ('DACLS') ON SECURITY EVENT LOG"
"=============================================================================`n"
    icacls "C:\WINDOWS\system32\winevt\Logs\Security.evtx" | Out-Host

"`n==================================================================================================="
"2.1.3. AUDITING OF SENSITIVE SYSTEM, APPLICATION FILES AND DIRECTORIES SHOULD BE ENABLED ON SERVERS"
"===================================================================================================`n"

"`n===================="
"ACLS FOR SYSTEM ROOT"
"====================`n"
    Get-Acl "$env:SystemRoot" |Format-List | Out-Host

"`n========================"
"ACLS FOR SYSTEM32 FOLDER"
"========================`n"
    Get-Acl "$env:SystemRoot\system32" |Format-List | Out-Host

"`n======================="
"ACLS FOR DRIVERS FOLDER"
"=======================`n"
    Get-Acl "$env:SystemRoot\system32\drivers" |Format-List | Out-Host

"`n======================"
"ACLS FOR CONFIG FOLDER"
"======================`n"
    Get-Acl "$env:SystemRoot\System32\config" |Format-List | Out-Host

"`n====================="
"ACLS FOR SPOOL FOLDER"
"=====================`n"
    Get-Acl "$env:SystemRoot\System32\spool" |Format-List | Out-Host

"`n=========================================="
"2.1.4. AUDITING OF SENSITIVE REGISTRY KEYS"
"==========================================`n"

"`n==============================="
"ACLS FOR SYSTEM KEY IN REGISTRY"
"===============================`n"
    Get-Acl "HKLM:\SYSTEM" | Select-Object Path, Owner, AccessToString

"`n================================"
"ACLS FOR PERFLIB KEY IN REGISTRY"
"================================`n"
    Get-Acl "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Perflib" | Select-Object Path, Owner, AccessToString

"`n================================="
"ACLS FOR WINLOGON KEY IN REGISTRY"
"=================================`n"
    Get-Acl "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" | Select-Object Path, Owner, AccessToString

"`n============================" 
"ACLS FOR LSA KEY IN REGISTRY"
"============================`n"
    Get-Acl "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" | Select-Object Path, Owner, AccessToString 

"`n============================================"
"ACLS FOR SECURE PIPE SERVERS KEY IN REGISTRY"
"============================================`n"
    Get-Acl "HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers" | Select-Object Path, Owner, AccessToString

"`n=================================="
"ACLS FOR KNOWNDLLS KEY IN REGISTRY"
"==================================`n"
    Get-Acl "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs" | Select-Object Path, Owner, AccessToString

"`n====================================="
"ACLS FOR ALLOWEDPATHS KEY IN REGISTRY"
"=====================================`n"
    Get-Acl "HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths" | Select-Object Path, Owner, AccessToString

"`n==============================="
"ACLS FOR SHARES KEY IN REGISTRY"
"===============================`n"
    Get-Acl "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Shares" | Select-Object Path, Owner, AccessToString

"`n=============================="
"ACLS FOR SNMP KEYS IN REGISTRY"
"==============================`n"
#This may error if there are no defined SNMP Keys. Should return blank output
    Get-Acl "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities" | Select-Object Path, Owner, AccessToString
    Get-Acl "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers"| Select-Object Path, Owner, AccessToString
    Get-Acl "HKLM:\SOFTWARE\Policies\SNMP\Parameters\ValidCommunities" | Select-Object Path, Owner, AccessToString
    Get-Acl "HKLM:\SOFTWARE\Policies\SNMP\Parameters\PermittedManagers" | Select-Object Path, Owner, AccessToString

"`n========================================="
"ACLS FOR CURRENT VERSION KEYS IN REGISTRY"
"=========================================`n"
    Get-Acl "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" | Select-Object Path, Owner, AccessToString
    Get-Acl "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" | Select-Object Path, Owner, AccessToString
    Get-Acl "HKLM:\SOFTWARE\MICROSOFT\Windows NT\CurrentVersion" | Select-Object Path, Owner, AccessToString
    Get-Acl "HKLM:\SOFTWARE\MICROSOFT\Windows NT\CurrentVersion\AeDebug" | Select-Object Path, Owner, AccessToString
    Get-Acl "HKLM:\SOFTWARE\MICROSOFT\Windows NT\CurrentVersion\Fonts" | Select-Object Path, Owner, AccessToString
    Get-Acl "HKLM:\SOFTWARE\MICROSOFT\Windows NT\CurrentVersion\FontSubstitutes"| Select-Object Path, Owner, AccessToString
    Get-Acl "HKLM:\SOFTWARE\MICROSOFT\Windows NT\CurrentVersion\Font Drivers" | Select-Object Path, Owner, AccessToString
    Get-Acl "HKLM:\SOFTWARE\MICROSOFT\Windows NT\CurrentVersion\FontMapper" | Select-Object Path, Owner, AccessToString
    Get-Acl "HKLM:\SOFTWARE\MICROSOFT\Windows NT\CurrentVersion\GRE_Initialize" | Select-Object Path, Owner, AccessToString
    Get-Acl "HKLM:\SOFTWARE\MICROSOFT\Windows NT\CurrentVersion\MCI Extensions" | Select-Object Path, Owner, AccessToString
    Get-Acl "HKLM:\SOFTWARE\MICROSOFT\Windows NT\CurrentVersion\Ports" | Select-Object Path, Owner, AccessToString
    Get-Acl "HKLM:\SOFTWARE\MICROSOFT\Windows NT\CurrentVersion\ProfileList" | Select-Object Path, Owner, AccessToString
    Get-Acl "HKLM:\SOFTWARE\MICROSOFT\Windows NT\CurrentVersion\Compatibility32" | Select-Object Path, Owner, AccessToString
    Get-Acl "HKLM:\SOFTWARE\MICROSOFT\Windows NT\CurrentVersion\Drivers32" | Select-Object Path, Owner, AccessToString
    Get-Acl "HKLM:\SOFTWARE\MICROSOFT\Windows NT\CurrentVersion\MCI32" | Select-Object Path, Owner, AccessToString
#Note should not be on newer versions of Windows
#Need to test on Server 2008 & 2008 R2. If not present, will remove
    Get-Acl "HKLM:\SOFTWARE\MICROSOFT\Windows NT\CurrentVersion\Compatibility" | Select-Object Path, Owner, AccessToString
    Get-Acl "HKLM:\SOFTWARE\MICROSOFT\Windows NT\CurrentVersion\Drivers" | Select-Object Path, Owner, AccessToString
    Get-Acl "HKLM:\SOFTWARE\MICROSOFT\Windows NT\CurrentVersion\MCI" | Select-Object Path, Owner, AccessToString
    Get-Acl "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx" | Select-Object Path, Owner, AccessToString
    Get-Acl "HKLM:\SOFTWARE\MICROSOFT\Windows NT\CurrentVersion\Embedding" | Select-Object Path, Owner, AccessToString
    Get-Acl "HKLM:\SOFTWARE\MICROSOFT\Windows NT\CurrentVersion\Type 1 Installer" | Select-Object Path, Owner, AccessToString
    Get-Acl "HKLM:\SOFTWARE\MICROSOFT\Windows NT\CurrentVersion\WOW" | Select-Object Path, Owner, AccessToString
    Get-Acl "HKCR:\" | Select-Object Path, Owner, AccessToString

"`n============================="
"ACLS FOR RPC KEYS IN REGISTRY"
"=============================`n"
    Get-Acl "HKLM:\SOFTWARE\MICROSOFT\RPC"| Select-Object Path, Owner, AccessToString

"`n============================"
"2.1.5. OBECT ACCESS AUDITING"
"============================`n"
    AuditPol /get /category:"Object Access" | Out-Host

"`n==================================================="
"2.1.6. AUDITING FOR LOGON EVENT SUCCESS AND FAILURE"
"===================================================`n"
    AuditPol /get /category:"Logon/Logoff,Account Logon" | Out-Host

"`n=========================================================="
"2.1.7. AUDITING FOR ACCOUNT MANAGEMENT SUCCESS AND FAILURE"
"==========================================================`n"
    AuditPol /get /category:"Account Management" | Out-Host

"`n================================="
"2.1.8. AUDITING FOR PRIVILEGE USE"
"=================================`n"
    AuditPol /get /category:"Privilege Use" | Out-Host

"`n=================================="
"2.1.9. AUDITING FOR POLICY CHANGE"
"==================================`n"
    AuditPol /get /category:"Policy Change" | Out-Host

"`n=================================="
"2.1.10. AUDITING FOR SYSTEM EVENTS"
"==================================`n"
    AuditPol /get /category:"System" | Out-Host

"`n======================================"
"2.2. FILE SYSTEM ACCESS AND MANAGEMENT" 
"======================================`n" 

"`n============================================="
"2.2.1. SHARES THAT ARE ACCESSIBLE ANONYMOUSLY"
"=============================================`n"
#Value of following registry key should be set to 1."
Write-Host "Restrict Null Session Access Value in Registry is set to " -NoNewline
    (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters').restrictnullsessaccess

"`n==============================="
"2.2.2. SYSTEM FOLDER PERMISSION" 
"===============================`n"
    Get-Acl "$env:SystemRoot\system32" | Select-Object Path, Owner, AccessToString 

"`n================================"
"2.2.3. SENSITIVE WINDOWS SYSTEMS"
"================================`n"
    Get-Acl "$env:SystemRoot" | Select-Object Path, Owner, AccessToString
    Get-Acl "$env:SystemDrive" | Select-Object Path, Owner, AccessToString
    Get-Acl "$env:SystemRoot\system32" | Select-Object Path, Owner, AccessToString
    Get-Acl "$env:SystemRoot\system32\drivers" | Select-Object Path, Owner, AccessToString
    Get-Acl "$env:SystemRoot\System32\config" | Select-Object Path, Owner, AccessToString
    Get-Acl "$env:SystemRoot\System32\spool" | Select-Object Path, Owner, AccessToString
    Get-Acl "$env:SystemRoot\security" | Select-Object Path, Owner, AccessToString
#The below folders will be present in AD server only
    Get-Acl "$env:SystemRoot\sysvol" | Select-Object Path, Owner, AccessToString
    Get-Acl "$env:SystemRoot\ntds" | Select-Object Path, Owner, AccessToString
    Get-Acl "$env:SystemRoot\ntfrs" | Select-Object Path, Owner, AccessToString

"`n================================================="
"2.2.4. PREVENT MODIFICATION OF KEYS UPON START UP"
"=================================================`n"
    Get-Acl "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" | Select-Object Path, Owner, AccessToString
    Get-Acl "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" | Select-Object Path, Owner, AccessToString

"`n================================================================"
"2.2.5. ACCESS TO REGISTRY REMOTELY ACCESSIBLE PATHS AND SUBPATHS"
"================================================================`n"
#Below are the default paths that are remotely accessible. There may be others
    Get-Acl "HKLM:\System\CurrentControlSet\Control\ProductOptions" | Select-Object Path, Owner, AccessToString
    Get-Acl "HKLM:\System\CurrentControlSet\Control\Server Applications" | Select-Object Path, Owner, AccessToString
    Get-Acl "HKLM:\Software\Microsoft\Windows NT\CurrentVersion" | Select-Object Path, Owner, AccessToString

"`n====================="
"2.3. GROUP MANAGEMENT" 
"=====================`n" 

"`n==========================="
"2.3.1. VIEW LIST OF DOMAINS"
"===========================`n"
    net View /Domain | Out-Host

"`n====================="
"2.3.2. ACCOUNT GROUPS"
"=====================`n"
#Below is the list of all local groups and its members present on $server.
#Should produce no output on non-DC
    $server = "$env:COMPUTERNAME"
    $computer = [ADSI]"WinNT://$server,computer"

    $computer.psbase.children | where { $_.psbase.schemaClassName -eq 'group' } | foreach {
        write-host $_.name
        write-host "------"
        $group =[ADSI]$_.psbase.Path
        $group.psbase.Invoke("Members") | foreach {$_."GetType".Invoke().InvokeMember("Name", 'GetProperty', $null, $_, $null) | Format-list}
        # $group.psbase.Invoke(“Members”) | foreach {$.GetType().InvokeMember(“Name”, ‘GetProperty’, $null, $, $null) | Format-list}
        write-host 
    }
#List all Domain Groups
#Can be on any Host
Write-Host "Below is the list of all groups on" (Get-WmiObject Win32_ComputerSystem).Domain -NoNewline
Write-Host " Domain."
    net group /domain | Format-list | Out-Host

"`n======================================"
"2.3.3. NULL CREDENTIAL LOGON PERMITTED"
"======================================`n"
#This should be set to '0'. 
Write-Host "everyoneincludesanonymous value in Registry is set to " -NoNewline
    (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Lsa').everyoneincludesanonymous

"`n================================="
"2.3.4. IS RESTRICTED GROUP IN USE"
"=================================`n"

$RestrictedGroup = Get-WMIObject Win32_Group -filter "domain='$env:computername'" | Select-String -AllMatches Restricted | Out-Host

#!$variablename is to check that if $variablename has $null as value.
#if (!$variablename) { Write-Host "variable is null" }
#$variablename is to check if $variablename has any value except $null.
#if ($variablename) { Write-Host "variable is NOT null" }
Write-Host
If (!$RestrictedGroup) {
    Write-Host Restricted group is not present.
    }
    else {
    Write-Host Restricted group is present.
    }

"`n=============================="
"2.4 REMOTE CONNECTION SETTINGS"
"==============================`n"

"`n==============================="
"2.4.1. TERMINAL SERVER SETTINGS"
"===============================`n"

"------------------------"
"Terminal Server Settings"
"------------------------"
    Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' | Out-Host

"-------------------------------"
"Terminal Server Client Settings"
"-------------------------------"
    Get-ItemProperty 'HKCU:\Software\Microsoft\Terminal Server Client\'| Out-Host

"`n====================================="
"2.4.2. RDP TERMINAL SERVICES SETTINGS" 
"=====================================`n"
Write-Host 'The minimum encryption level value in registry is set to ' -NoNewline
    (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\').MinEncryptionLevel
#Defines encryption levels
Write-Output '
1 = low (56-bit encryption)
2 = client compatible (variable encryption level)
3 = high (128-bit encryption)
4 = fips (256-bit encryption)'
"`n" 
#'0' is the preferred value
#Potential False Positive. Can still initiate session via TLS and have registry of 1 (Hybrid protocol)
Write-Host 'The minimum security layer value in registry is set to ' -NoNewline
    (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\').SecurityLayer
    Write-Output '
0 = SSL/TLS
1 = x.224 is used (Default)'

"`n============================================="
"2.4.3. SECURE CHANNEL DATA ENCRPTION SETTINGS"
"=============================================`n" 
#SealSecureChannel determines whether outgoing secure channel traffic is encrypted. 
#'1' is default and shows that outgoing traffic must be encrypted.
Write-Host 'The SealSecureChannel key value in the registry is set to '
    (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters').SealSecureChannel
# RequireStrongKey, with the SealSecureChannel determines secure channel encryption
# '1' is default and shows that system requires trusted DC to compute a strong key
Write-Host 'The RequireStrongKey key value in the registry is set to '
    (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters').RequireStrongKey

"`n========================"
"2.5. PASSWORD MANAGEMENT" 
"========================`n"

"`n======================"
"2.5.1. PASSWORD POLICY" 
"======================`n"

"`n====================="
"Local Password Policy"
"=====================`n"
 Write-Host
    net accounts | Out-Host

"`n======================"
"Domain Password Policy"
"======================`n"
Write-Host    
    net accounts /domain | Out-Host

"`n========================="
"2.5.2. INSTALLED SOFTWARE"
"=========================`n"
#List of installed programs
    Get-ItemProperty 'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate

"`n=============================="
"2.5.3. IS AUTO ADMIN LOGON SET"
"==============================`n"
#Check for AutoAdminLogon. '0' means is not set
Write-Host
    (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\')
Write-Host

"`n==================================="
"2.5.4. LIST OF LOCAL ADMIN ACCOUNTS"
"===================================`n"  
Write-Host
    net localgroup administrators | Out-Host

"`n========================="
"2.6. SYSTEM CONFIGURATION"  
"=========================`n"

"`n=============================="
"2.6.1. LATEST SECURITY PATCHES"
"==============================`n"
#Only last 30 to determine if pattern of installing is being followed.
Get-HotFix -Description "Security*" | sort installedon -desc | select -first 30 | Out-Host

"`n======================="
"2.6.2. SECURITY OPTIONS"
"=======================`n"
    Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' | select NullSessionPipes, autodisconnect, enableforcedlogoff, 
enablesecuritysignature, requiresecuritysignature, restrictnullsessaccess, AdjustedNullSessionPipes, EnableAuthenticateUserSharing | Out-Host

"`n========================="
"2.6.3. ANTIVIRUS SOFTWARE"   
"=========================`n" 
#Blank output means no AV.    
function Get-AntiVirusProduct {
[CmdletBinding()]
param (
[parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
[Alias('name')]
$computername=$env:computername


)

#$AntivirusProduct = Get-WmiObject -Namespace "root\SecurityCenter2" -Query $wmiQuery  @psboundparameters # -ErrorVariable myError -ErrorAction 'SilentlyContinue' # did not work            
 $AntiVirusProduct = Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct  -ComputerName $computername

#Switch to determine the status of antivirus definitions and real-time protection.
#The values in this switch-statement are retrieved from the following website: http://community.kaseya.com/resources/m/knowexch/1020.aspx
switch ($AntiVirusProduct.productState) {
"262144" {$defstatus = "Up to date" ;$rtstatus = "Disabled"}
    "262160" {$defstatus = "Out of date" ;$rtstatus = "Disabled"}
    "266240" {$defstatus = "Up to date" ;$rtstatus = "Enabled"}
    "266256" {$defstatus = "Out of date" ;$rtstatus = "Enabled"}
    "393216" {$defstatus = "Up to date" ;$rtstatus = "Disabled"}
    "393232" {$defstatus = "Out of date" ;$rtstatus = "Disabled"}
    "393488" {$defstatus = "Out of date" ;$rtstatus = "Disabled"}
    "397312" {$defstatus = "Up to date" ;$rtstatus = "Enabled"}
    "397328" {$defstatus = "Out of date" ;$rtstatus = "Enabled"}
    "397584" {$defstatus = "Out of date" ;$rtstatus = "Enabled"}
default {$defstatus = "Unknown" ;$rtstatus = "Unknown"}
    }

#Create hash-table for each computer
$ht = @{}
$ht.Computername = $computername
$ht.Name = $AntiVirusProduct.displayName
$ht.'Product GUID' = $AntiVirusProduct.instanceGuid
$ht.'Product Executable' = $AntiVirusProduct.pathToSignedProductExe
$ht.'Reporting Exe' = $AntiVirusProduct.pathToSignedReportingExe
$ht.'Definition Status' = $defstatus
$ht.'Real-time Protection Status' = $rtstatus


#Create a new object for each computer
New-Object -TypeName PSObject -Property $ht 

} 
Get-AntiVirusProduct | Out-Host

"`n======================="
"2.6.4. SERVICES RUNNING"   
"=======================`n"
#Review output to see if any non-essential services are running. 
    net start | Out-Host

"`n=================================="
"2.6.5. SERVICES RUNNING AT STARTUP"
"==================================`n"
#Check what software, system process, etc. are initiated at startup
    Get-WmiObject win32_startupCommand -ComputerName $ServerName | Select Name,Location,Command,User,caption | Out-Host
        Write-Output "Logged on user(s) for" $ServerName "`n";

"`n======================"
"2.6.6. FIREWALL STATUS"
"======================`n"
#Check OS firewall. Will show if rules are local or set by GPO
    #netsh advfirewall show domainprofile | Out-Host
    #netsh advfirewall show privateprofile | Out-Host
    #netsh advfirewall show publicprofile | Out-Host

    netsh advfirewall show currentprofile | Out-Host

"`n==================="
"2.6.7. TELNET CHECK"
"===================`n"
#Blank outputs/errors are because the keys don't exist.
"`n=================================="
"TlntSvr registry key entry details"
"==================================`n"
    Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\TlntSvr\' 

"======================================="
"TelnetServer registry key entry details"
"======================================="
    Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\TelnetServer\' 

"`n================================"
"2.7.  USER ACCOUNT CONFIGURATION"
"================================`n"

"`n================================"
"2.7.1 LOCAL ACCOUNTS INFORMATION"
"================================`n"
#List local accounts, their status, password information, etc. 
    Get-WmiObject -Class Win32_UserAccount -Filter  "LocalAccount='True'" | 
    Select-Object PSComputerName, Status, Caption, PasswordExpires, AccountType, Description, Disabled, Domain, FullName, InstallDate, LocalAccount, Lockout, Name, 
PasswordChangeable, PasswordRequired, SID, SIDType | Out-Host


"`n========================="
"2.7.2.LOCAL ADMINITRATORS"
"=========================`n"
#Below are all users in the local administrators group. 
Write-Host   
    net localgroup administrators | Out-Host

"`n=========================="  
"2.7.3.GUEST ACCOUNT STATUS"
"==========================`n"
    net user Guest | Out-Host

"`n======================="
"2.7.4 INACTIVE ACCOUNTS" 
"=======================`n"
#Check for user accounts that have not logged in for the past 90 days
Write-Host
    $([ADSI]"WinNT://$env:COMPUTERNAME").Children | where {$_.SchemaClassName -eq 'user'} | Select-Object name, lastlogin | Out-Host

"`n==============================="
"2.7.5. USER SESSION INACTIVITY"     
"===============================`n" 
Write-Host
    Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' | Format-List MaxDisconnectionTime, MaxIdleTime | Out-Host
Write-Host

"`n====================="
"2.7.6 USERS LOGGED IN"
"=====================`n"
    Get-WmiObject Win32_LoggedOnUser -ComputerName $ServerName | Select Antecedent,PSComputerName -Unique | Format-List | Out-Host
        Write-Output "End of request for" $ServerName | Out-Host

Write-Host
Write-Host Script execution complete. Please Wait... -ForegroundColor Yellow -BackgroundColor Black
Write-Host
Start-Sleep -s 5
Write-Host Reverting the PowerShell script execution policy to $ExecutionPolicy -ForegroundColor Yellow -BackgroundColor Black
    
    Start-Sleep -s 5
    Set-ExecutionPolicy $ExecutionPolicy -force

Write-Host
Write-Host The PowerShell Script Execution Policy setting has been reverted back to $ExecutionPolicy -ForegroundColor Yellow -BackgroundColor Black
Write-Host 
Write-Host Audit Complete
Write-Host

#STOP RECORDING TRANSCRIPT
Stop-Transcript
