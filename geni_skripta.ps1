#povezava na racunalnik + priprava registra za namestitev
Enter-PSSession GENISINB01503
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorUser" -Value 1 –Force
 
#listanje kompov z lastnostmi
Get-ADComputer -Filter 'Description -like "nina*"' -Properties Description,IPv4Address | FT Description,Name,IPv4Address -A
 
#iskanje po username
Get-ADUser -Filter "SamAccountName -like '*nina*'" -Properties Name,Surname,EmployeeID,EmailAddress,MobilePhone,LastLogonDate,PasswordLastSet -SearchBase "OU=Active Users,OU=Users,OU=GEN-I,DC=corp,DC=iges,DC=si"| Select-Object SamAccountName, Name, Surname, EmployeeID, EmailAddress, MobilePhone, LastLogonDate, PasswordLastSet | Format-Table -AutoSize
 
#pravice userja
Get-ADUser "anagj" -Prop MemberOf | select -Exp MemberOf | ? {$_ -notmatch 'Člani GEN-I Športno društvo|U_Users_VIP_Users|ReportingGroup'} | %{($_ -split ',')[0] -replace '^CN=', ''} | sort
 
#pravice računalnika
Get-ADPrincipalGroupMembership (Get-ADComputer GENISINB388) | select-object name -ExpandProperty name | Sort-Object
 
#ID
$userName = Read-Host -Prompt "Vnesi ime uporabnika"; Get-ADUser -Filter "SamAccountName -like '*$userName*'" -Properties Name,Surname,EmployeeID,EmailAddress,MobilePhone,LastLogonDate,PasswordLastSet -SearchBase "OU=Active Users,OU=Users,OU=GEN-I,DC=corp,DC=iges,DC=si"| Select-Object SamAccountName, Name, Surname, EmployeeID, EmailAddress, MobilePhone, LastLogonDate, PasswordLastSet | Format-Table -AutoSize
 
#Up time
$uptime = (Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
Write-Output "Computer: GENISIDT732 - CPU Uptime: $uptime"
 
 
#bitlocker check
Manage-Bde -status -computername genisidt069 D:
 
query user /server:GENISINB01503 #Preveri userje
 
#uporabi za posodobitve
"%programfiles%\Windows Defender\mpcmdrun.exe" -signatureupdate PS: Update-MpSignature -UpdateSource MicrosoftUpdateServer
 
#last lastLogonTime
Get-ADComputer -Identity GENISINB899 -Properties lastLogonTimestamp |
Select-Object Name, @{Name="LastLogonDate";Expression={[DateTime]::FromFileTime($_.lastLogonTimestamp)}}
 
#windows security
Set-ItemProperty "HKCU:\Software\Microsoft\Office\16.0\Outlook\AutoDiscover" -Name ExcludeExplicitO365Endpoint -Value '1' -Type DWord
 
#aplikacije
Invoke-Command -ComputerName GENISINB01580 -ScriptBlock {
    Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
    Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
    Format-Table -AutoSize
}
 
#preverba verzije za OfficeC2RClient.exe
Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration' ` | Select-Object -ExpandProperty VersionToReport
 
cd "C:\Program Files\Common Files\Microsoft Shared\ClickToRun"
 
cd "D:\SW_DVD9_Win_Pro_11_23H2.5_64BIT_English_Pro_Ent_EDU_N_MLF_X23-73316"
 
OfficeC2RClient.exe /update user #komanda za cmd
 
#v powershell iz cmd
Start-Process OfficeC2RClient.exe -ArgumentList "/update user"
 
 
#filtriranje procesa
Get-Process | Where-Object { $_.ProcessName -eq "OfficeClickToRun" }
 
#tiskalniki
Invoke-Command -ComputerName <computer_name> -ScriptBlock {
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC' -Force | Out-Null
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC' -Name 'RpcUseNamedPipeProtocol' -Value 1 -Type DWord
}
 
#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
 
#vpiši uporabniško ime
$username = Read-Host "vpiši uporabniško ime"
 
#poišči računalnik v polju Description ali ManagedBy
$computers = Get-ADComputer -Filter * -Properties Name, Description, ManagedBy, IPv4Address |
    Where-Object { ($_.Description -like "$username*") -or ($_.ManagedBy -like "$username*") }
 
#rezultati računalnikov
$computerResults = $computers | Select-Object Name, Description, ManagedBy, IPv4Address | Format-Table -AutoSize
 
#izpiši rezultate računalnikov
if ($computerResults) {
    $computerResults
} else {
    Write-Host "ni informacij o računalnikih za uporabnika: $username"
}
 
#če je računalnik na seznamu, izpiši informacije o uporabniku
if ($computers) {
    #poišči uporabnika
    $user = Get-ADUser -Filter "SamAccountName -like '$username*'" -Properties Name, Surname, EmployeeID, EmailAddress, MobilePhone, LastLogonDate, PasswordLastSet -SearchBase "OU=Active Users,OU=Users,OU=GEN-I,DC=corp,DC=iges,DC=si"
   
    #izpiši informacije o uporabniku
    $user | Select-Object SamAccountName, Name, Surname, EmployeeID, EmailAddress, MobilePhone, LastLogonDate, PasswordLastSet | Format-Table -AutoSize
} else {
    Write-Host "ni informacij o uporabniku: $username"
}
 
#-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
 
#preverba memorije na računalniku
$ComputerName = "GENISINB01770"
Get-CimInstance Win32_LogicalDisk -ComputerName $ComputerName | Where-Object {$_.DeviceID -match "C:|D:"} |
Select-Object DeviceID, VolumeName, @{Name="TotalSizeGB"; Expression={[math]::Round($_.Size/1GB,2)}}, @{Name="FreeSpaceGB"; Expression={[math]::Round($_.FreeSpace/1GB,2)}}
 
#funkcija za computername
 
Import-Module "\\corp.iges.si\DFS\IT_SW\skripte\HelpdeskCommander\prod\2.0\HelpdeskCommander.psm1"
 
Set-ExecutionPolicy RemoteSigned -Scope Process #pokretanje mrežnih skripti
 
Test-Path "\\corp.iges.si\DFS\IT_SW\skripte\HelpdeskCommander\prod\2.0\HelpdeskCommander.psm1"
 
Get-ComputerName -FullName "ambrož janc"
 
Get-ADUser kristijanam | select -ExpandProperty name
 
Get-Acl "\\corp.iges.si\IGES\GENI\GENI_Sales\PSSO – Short Term Optimisation" | Format-List
 
 
 
Import-Module ActiveDirectory
 
# aktivnost zadnjih 90 dni
$threshold = (Get-Date).AddDays(-90)
 
# definiraj OU-ove katere želiš da preveriš
$ouPaths = @(
    "OU=Desktops - KK,OU=Desktops,OU=GEN-I,DC=corp,DC=iges,DC=si",
    "OU=Desktops - LJ,OU=Desktops,OU=GEN-I,DC=corp,DC=iges,DC=si",
    "OU=Desktops - NG,OU=Desktops,OU=GEN-I,DC=corp,DC=iges,DC=si",
    "OU=Desktops - ZG,OU=Desktops,OU=GEN-I,DC=corp,DC=iges,DC=si",
    "OU=Notebooks - KK,OU=Notebooks,OU=GEN-I,DC=corp,DC=iges,DC=si",
    "OU=Notebooks - LJ,OU=Notebooks,OU=GEN-I,DC=corp,DC=iges,DC=si",
    "OU=Notebooks - NG,OU=Notebooks,OU=GEN-I,DC=corp,DC=iges,DC=si",
    "OU=Notebooks - ZG,OU=Notebooks,OU=GEN-I,DC=corp,DC=iges,DC=si"
)
 
# kreiraj prazno listo
$allComputers = @()
 
# zanka za OU-ove in kup aktivnih kateri nimaju Win11
foreach ($ou in $ouPaths) {
    $computers = Get-ADComputer -SearchBase $ou -Filter * -Properties Name, OperatingSystem, Description, LastLogonDate, Enabled |
        Where-Object {
            $_.Enabled -eq $true -and
            $_.LastLogonDate -gt $threshold -and
            $_.OperatingSystem -notlike "*Windows 11*"
        }
    $allComputers += $computers
}
 
# prikaz rezultata
$allComputers |
    Select-Object Name, OperatingSystem, Description, LastLogonDate |
    Sort-Object Name |
    Format-Table -AutoSize
 
# število računalnikov
Write-Host "`skupno število AKTIVNIH računalnikov (brez Windows 11):" $allComputers.Count -ForegroundColor Cyan
 
 
 
 
 
 
# Check if Credential guard is enabled - https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/configure?tabs=reg
# The command generates the following output:
# 0: Credential Guard is disabled (not running)
# 1: Credential Guard is enabled (running)
$comp = "GENISINB213"
Invoke-Command -ScriptBlock {(Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard).SecurityServicesRunning}
 
# Disable CREDENTIAL GUARD
Invoke-Command -ScriptBlock {Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LsaCfgFlags" -Value 0 -Type DWord}
 
# Uporabnik naj restarta računalnik, potem preveriš, če je credential guard DISABLED.
 
 
 
 
function Get-ComputerName {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [string]$FullName
    )
 
    <#
    .SYNOPSIS
    Retrieves the computer names associated with a user's full name from Active Directory.
 
    .DESCRIPTION
    This function retrieves the computer names associated with a user's full name from Active Directory by searching for computer descriptions that contain the full name.
 
    .PARAMETER FullName
    Specifies the full name of the user.
 
    .EXAMPLE
    Get-ComputerName -FullName "Janez Novak"
    Retrieves the computer names associated with the user's full name "Janez Novak" from Active Directory.
    #>
 
    if (!$FullName) {
        Get-Help Get-ComputerName
        return
    }
 
    $FullName = "*" + $FullName + "*"
    $computers = Get-ADComputer -Filter "Description -like '$FullName'" -Properties Name, Enabled |
                 Select-Object Name, Enabled |
                 Sort-Object Name
 
    if ($computers) {
        $enabledComputers = $computers | Where-Object { $_.Enabled }
        $disabledComputers = $computers | Where-Object { -not $_.Enabled }
 
        if ($enabledComputers) {
            Write-Host "Enabled:"
            $enabledComputers | ForEach-Object {
                Write-Host $_.Name
            }
        }
 
        if ($disabledComputers) {
            Write-Host "`nDisabled:"
            $disabledComputers | ForEach-Object {
                Write-Host $_.Name
            }
        }
    }
    else {
        Write-Host "No computers associated with user '$FullName' found in Active Directory."
    }
}
 
 
#-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#izpis računalnikov iz AD grupe
$GroupName = "C_SCCM_Required_Upgrade_Win10_To_Win11_23H2"
Get-ADGroupMember -Identity $GroupName | Where-Object { $_.objectClass -eq "computer" } | Select-Object Name
 
#user cert je za vpn
#computer cert je za Failed 802.1x authentication
 
#BITLOCKER
 
# Omogoči obnovitveno geslo za disk D
Enable-BitLocker -MountPoint "D:" -EncryptionMethod XTSAES128 –UsedSpaceOnly -RecoveryPasswordProtector
 
# Omogoči samodejno odklepanje za disk D
Enable-BitLockerAutoUnlock -MountPoint "D:"
 
 
#enkripcija diska, npr C:
 
manage-bde -on C:
 
#dodajanje gesla
 
manage-bde -on C: -pw
 
#spreminjanje ključa
 
manage-bde -protectors -add C: -RecoveryKey D:\RecoveryKey.bek
 
#preverba statusa
 
manage-bde -status C:
 
#dekripcija
 
manage-bde -off C:
 
#------------------------------------------------------------------------------------------------------------------------------------------------------------
 
#registry pol file location
C:\Windows\System32\GroupPolicy\Machine
 
#iz win10 21h2 na win11 22h2
C_SCCM_Required_Upgrade_To_Win11_23H2
 
#iz win10 na win11
C_SCCM_Required_Upgrade_Win10_To_Win11_23H2
 
 
#osnovne pravice
GEN-I
U_Users_HomeFolder_FileServer_LJ
U_Users_HighSecuritySettings
P_LJ_GEN-I COLOR Printer
P_LJ_GEN-I BW Printer
U_Users_ADSync_R
U_Users_GEN-I_AlwaysON_VPN
U_Users_Azure_Gecko_Access
U_License_O365_E3
U_Users_MicrosoftAuthenticator_AuthenticationMode_Any
U_Users_FineGrainedPasswordPolicy_4StandardUsers
U_Users_Authenticator_PasswordLess
 
 
 
#pravice za LAPTOP
C_AdobeReaderHighSecurity_Computers
C_Applocker_ManagedComputers
C_AttackSurfaceReduction_Computers_BlockedAll
C_BitlockerEnabledComputers
C_CertficateManagedDeployment
C_HighSecurityComputers
C_LocalSecurityAuthority_ProtectionEnabled_Computers
C_NAC_8021X_EnabledComputers_MachineAuth_WIFI
C_NAC_8021X_EnabledComputers_MachineAuth_WIRED_ALL
C_Network_LLMNR_Disabled_Computers
C_Network_NBT-NS_Disabled_Computers
C_Windows10Computers
C_Windows10Computers_ALL
C_WindowsControlledFolderAccess
C_WindowsDefenderATP_NetworkProtection_Computers
C_WindowsDefenderATPComputers
Domain Computers
 
 
#pravice za PC
C_AdobeReaderHighSecurity_Computers;
C_Applocker_ManagedComputers;
C_CertficateManagedDeployment;
C_HighSecurityComputers;
C_NAC_8021X_EnabledComputers_MachineAuth_WIRED_ALL;
C_Windows10Computers;
C_Windows10Computers_ALL
C_WindowsDefenderATP_NetworkProtection_Computers;
C_WindowsDefenderATPComputers;
C_AttackSurfaceReduction_Computers_BlockedAll;
C_LocalSecurityAuthority_ProtectionEnabled_Computers;
C_WindowsControlledFolderAccess;
C_Network_LLMNR_Disabled_Computers
C_Network_NBT-NS_Disabled_Computers
 
 
#za klicni center:
 
1. mora bit računalnik v obeh grupah
    C_CiscoIPCommunicator;
    C_CiscoAgentDesktop;
 
2. namestiti v software centri cisco supervisor in ip communicator
 
3. namestiš jabra direct
 
4. skopiraš klicne maske
 
    iz lokacije \\geniljmgmt04\HDShare\Skripta za klicno masko\new2 skopiraj datoteke:  
 
        ielaunch.vbs  
        ielaunchee.vbs  
        ielaunchhr.vbs  
 
uporabniku na računalnik na spodnjo lokacijo: C:\Program Files (x86)\Cisco\Desktop\bin
 
 
#-------------------------------------------------------------------------------------------------------------------------------------------------------------
 
#primerjanje pravic dva userja
 
# Define the usernames
$user1 = "kristijanam"
$user2 = "sergejj"
 
# Get the groups for each user
$groups1 = Get-ADUser -Identity $user1 -Properties MemberOf | Select-Object -ExpandProperty MemberOf | ForEach-Object { (Get-ADGroup $_).Name }
$groups2 = Get-ADUser -Identity $user2 -Properties MemberOf | Select-Object -ExpandProperty MemberOf | ForEach-Object { (Get-ADGroup $_).Name }
 
# Sort the groups alphabetically
$groups1 = $groups1 | Sort-Object
$groups2 = $groups2 | Sort-Object
 
# Compare the groups
$commonGroups = $groups1 | Where-Object { $groups2 -contains $_ } | Sort-Object
$uniqueGroupsUser1 = $groups1 | Where-Object { $groups2 -notcontains $_ } | Sort-Object
$uniqueGroupsUser2 = $groups2 | Where-Object { $groups1 -notcontains $_ } | Sort-Object
 
# Display the results
Write-Host "Common Groups:"
$commonGroups
Write-Host
 
Write-Host "Groups unique to ${user1}:"
$uniqueGroupsUser1
Write-Host
 
Write-Host "Groups unique to ${user2}:"
$uniqueGroupsUser2
Write-Host
 
#------------------------------------------------------------------------------------------------------------------------------------------------------------
 
#helpdesk_funkcije
 
function Get-ComputerInformation {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [string]$ComputerName = $env:COMPUTERNAME
    )
   
    <#
    .SYNOPSIS
    Retrieves information about the computer.
 
    .DESCRIPTION
    This function retrieves basic information about the specified computer or the local computer.
 
    .PARAMETER ComputerName
    Specifies the name of the computer. Default is the local computer.
 
    .EXAMPLE
    Get-ComputerInformation -ComputerName "Server01"
    Retrieves information about the computer named Server01.
    #>
 
    #Prepare data
    $computerInfo = Get-ADComputer $ComputerName -Properties *
    $description = $computerInfo.description -split "-" | ForEach-Object { $_.Trim() }
    $ping = Test-NetConnection -ComputerName $ComputerName -InformationLevel Quiet
    $ipv4 = "NA"
    $pathcheck = "NA"
    if($ping) {
        $ipv4 = $computerInfo.IPv4Address
    }
 
    #Prepare output
    $output = [ordered]@{
        Name    = $ComputerName;
        User    = $description[0];
        Model   = $description[1];
        OS      = $description[2] -replace '[^0-9]', '';
        Online  = $ping;
        IPv4    = $ipv4
        Enabled = $ComputerInfo.Enabled
    }
 
    $output | Format-Table -AutoSize -HideTableHeaders
}
 
function Get-Username {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [string]$FullName
    )
   
    <#
    .SYNOPSIS
    Retrieves the username of a user based on their full name from Active Directory.
 
    .DESCRIPTION
    This function retrieves the username of a user based on their full name from Active Directory.
 
    .PARAMETER FullName
    Specifies the full name of the user. If not provided, defaults to the current user's full name.
    If empty it provides current user.
 
    .EXAMPLE
    Get-Username -FullName "Janez Novak"
    Retrieves the username of the user with the full name "Janez Novak" from Active Directory.
    #>
 
    if (!$FullName) {
        return $env:USERNAME
    }
 
    # Retrieve username based on full name
    $username = (Get-ADUser -Filter { DisplayName -eq $FullName }).SamAccountName
 
    if ($username) {
        $username
    }
    else {
        Write-Host "User '$FullName' not found in Active Directory."
    }
}
 
function Get-Fullname {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [string]$Username = $env:USERNAME
    )
   
    <#
    .SYNOPSIS
    Retrieves the full name of a user based on their username from Active Directory.
 
    .DESCRIPTION
    This function retrieves the full name of a user based on their username from Active Directory.
 
    .PARAMETER Username
    Specifies the username of the user. If not provided, defaults to the current user's username.
    If empty it will use current user.
 
    .EXAMPLE
    Get-Fullname -Username "janezn"
    Retrieves the full name of the user with the username "janezn" from Active Directory.
    #>
 
    $user = Get-ADUser -Filter { SamAccountName -eq $Username } -Properties DisplayName
 
    if ($user) {
        $user.DisplayName
    }
    else {
        Write-Host "User '$Username' not found in Active Directory."
    }
}
 
function Get-UserGroup {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [string]$Username = $env:USERNAME
    )
   
    <#
    .SYNOPSIS
    Retrieves the groups that a user belongs to in Active Directory, excluding blacklisted groups.
 
    .DESCRIPTION
    This function retrieves the groups that a user belongs to in Active Directory based on their username, excluding blacklisted groups.
 
    .PARAMETER Username
    Specifies the username of the user.
 
    .EXAMPLE
    Get-UserGroup -Username "janezn"
    Retrieves the non-blacklisted groups that the user with the username "janezn" belongs to in Active Directory.
    #>
 
    $user = Get-ADUser -Filter { SamAccountName -eq $Username } -Properties DisplayName
   
    if ($user) {
        $groups = Get-ADPrincipalGroupMembership -Identity $user
 
        $blacklist = Get-Content -Path (Join-Path $PSScriptRoot "GroupBlacklist.txt")
 
        $groupNames = $groups | Where-Object { $_.Name -notin $blacklist } | Select-Object -ExpandProperty Name | Sort-Object
 
        if ($groupNames) {
            Write-Host
            $fullname = $user.DisplayName
            Write-Host "Fullname:`n$fullname"
            Write-Host "`nGroups:"
            $groupNames | ForEach-Object { Write-Host $_ }
            Write-Host "`nIgnored:"
            $ignoredGroups = $groups | Where-Object { $_.Name -in $blacklist } | Select-Object -ExpandProperty Name | Sort-Object
            $ignoredGroups | ForEach-Object { Write-Host $_ }
            Write-Host
        }
        else {
            Write-Host "User '$Username' is not a member of any non-blacklisted groups."
        }
    }
    else {
        Write-Host "User '$Username' not found in Active Directory."
    }
}
 
function Get-ComputerName {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [string]$FullName
    )
 
    <#
    .SYNOPSIS
    Retrieves the computer names associated with a user's full name from Active Directory.
 
    .DESCRIPTION
    This function retrieves the computer names associated with a user's full name from Active Directory by searching for computer descriptions that contain the full name.
 
    .PARAMETER FullName
    Specifies the full name of the user.
 
    .EXAMPLE
    Get-ComputerName -FullName "Janez Novak"
    Retrieves the computer names associated with the user's full name "Janez Novak" from Active Directory.
    #>
 
    if (!$FullName) {
        Get-Help Get-ComputerName
        return
    }
 
    $FullName = "*" + $FullName + "*"
    $computers = Get-ADComputer -Filter "Description -like '$FullName'" -Properties Name, Enabled |
                 Select-Object Name, Enabled |
                 Sort-Object Name
 
    if ($computers) {
        $enabledComputers = $computers | Where-Object { $_.Enabled }
        $disabledComputers = $computers | Where-Object { -not $_.Enabled }
 
        if ($enabledComputers) {
            Write-Host "Enabled:"
            $enabledComputers | ForEach-Object {
                Write-Host $_.Name
            }
        }
 
        if ($disabledComputers) {
            Write-Host "`nDisabled:"
            $disabledComputers | ForEach-Object {
                Write-Host $_.Name
            }
        }
    }
    else {
        Write-Host "No computers associated with user '$FullName' found in Active Directory."
    }
}
 
function Get-UserInfo {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [string]$Username = $env:USERNAME
    )
 
    <#
    .SYNOPSIS
    Retrieves detailed information about a user from Active Directory.
 
    .DESCRIPTION
    This function retrieves detailed information about a user from Active Directory based on their username.
 
    .PARAMETER Username
    Specifies the username of the user. If not provided, defaults to the current user's username.
 
    .EXAMPLE
    Get-UserInfo -Username "janezn"
    Retrieves detailed information about the user with the username "janezn" from Active Directory.
    #>
 
    $data = net user $Username /domain
    $filter = 2,3,7,10,11,12,13,14,20,16,22,8
   
    foreach ($row in $filter) {
        Write-Host $data[$row]
    }
}
 
function Initialize-Computer {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [string]$ComputerName
    )
 
    <#
    .SYNOPSIS
    Initializes a computer by performing various setup tasks.
 
    .DESCRIPTION
    This function initializes a computer by performing various setup tasks. It checks if the script is run with administrator privileges,
    verifies if the computer exists in Active Directory, and then performs additional tasks based on connectivity and configurations.
 
    .PARAMETER ComputerName
    Specifies the name of the computer to be initialized. If not provided, the local computer will be used.
 
    .EXAMPLE
    Initialize-Computer -ComputerName "Computer123"
    Initializes the computer named "Computer123" by performing setup tasks.
    #>
 
    if (!$ComputerName) {
        Get-Help Initialize-Computer
        return
    }
 
    # Check if script is run with administrator privileges
    $CurrentWindowsIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $CurrentWindowsPrincipal = New-Object System.Security.Principal.WindowsPrincipal($CurrentWindowsIdentity)
 
    if ($CurrentWindowsPrincipal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "Access granted!" -ForegroundColor Green
    }
    else {
        Write-Host "Access denied!" -ForegroundColor Red
        return
    }
 
    try {
        if (Get-ADComputer $ComputerName) {
            Write-Host $ComputerName
        }
    }
    catch {
        Write-Host "This computer does not exist!" -ForegroundColor Red
        return
    }
 
    if (Test-NetConnection $ComputerName -InformationLevel Quiet) {
 
        #Driver transfer
        if(!(Test-Path "\\$ComputerName\D$\Programme")){
            $status = Copy-Item "\\corp.iges.si\dfs\IT_SW\Drivers\Programme" -Destination "\\$ComputerName\D$\" -Recurse -ErrorVariable capturedErrors -ErrorAction SilentlyContinue -PassThru
            if($status)
            {
                Write-Host "Driver transfer succesful!" -ForegroundColor Green
            }
            else
            {
                Write-Host "Error: Driver transfer failed!" -ForegroundColor Red
            }
        }
        else{
            Write-Host "Error: Driver destination not empty!" -ForegroundColor Yellow
        }
 
        #VPN transfer
        if(!(Test-Path "\\$ComputerName\C$\ProgramData\Microsoft\Network\Connections\Pbk\rasphone_new.pbk")){
        $status =  Copy-Item "\\corp.iges.si\dfs\IT_SW\AlwaysOn VPN\Pbk" -Destination "\\$ComputerName\C$\ProgramData\Microsoft\Network\Connections\" -Recurse -ErrorVariable capturedErrors -ErrorAction SilentlyContinue -PassThru
        if($status)
        {
            Write-Host "VPN transfer succesful!" -ForegroundColor Green
        }
        else
        {
            Write-Host "Error: VPN transfer failed!" -ForegroundColor Red
        }
        }
        else {
            Write-Host "Error: VPN destination not empty!" -ForegroundColor Yellow
        }
 
        #Bitlocker backup
        try {
            #Folder check and prep
            $path = ("\\corp.iges.si\dfs\IT_SW\bitlocker\" + $ComputerName + "\")
            if(!(Test-Path $path)){
                Write-Host "Destination does not exist!" -ForegroundColor Red
                New-Item $path -ItemType Directory
                Write-Host "New backup destination created!" -ForegroundColor Green
            }
 
            #Backup
            $s = New-PSSession -ComputerName $ComputerName
            Invoke-Command -Session $s -ScriptBlock {
                $HOSTNAME = HOSTNAME
                New-Item ("D:\"+$HOSTNAME+"\") -ItemType Directory
                $blv = Get-BitLockerVolume
                foreach ($part in $blv) {
                    foreach ($kp in $part.KeyProtector) {
                        if($kp.KeyProtectorType -eq "RecoveryPassword"){
                            $save = ((Get-Date -Format "MM-dd-yyyy") + " - " + $part.MountPoint[0] + " - " + $kp.KeyProtectorId + ".txt")
                            $kp.RecoveryPassword > ("D:\$HOSTNAME\" + $save)
                            if (Test-Path ("D:\$HOSTNAME\" + $save)) {
                                Write-Host "Key" $part.MountPoint[0] "backedup succesfuly!" -ForegroundColor Green
                            }
                            else {
                                Write-Host "Key" $part.MountPoint[0] "failed to backup!" -ForegroundColor RED
                            }
                        }
                    }
                }
            }
            Remove-PSSession -Session $s
            $status =  Move-Item -Path ("\\$ComputerName\d$\$ComputerName") -Destination ("\\corp.iges.si\dfs\IT_SW\bitlocker") -Force -ErrorVariable capturedErrors -ErrorAction SilentlyContinue -PassThru
            if ($status) {
                Write-Host "Backup to the server succesful!" -ForegroundColor Green
            }
            else {
                Write-Host "Failed to copy backup to the server! Backup location: `"D:\`"" -ForegroundColor RED
            }
        }
        catch {
            Write-Host "Error: Bitlocker key backup failed!" -ForegroundColor Red
        }
 
    }
    else {
        Write-Host "Could not establish connection to the computer!" -ForegroundColor Red
    }
}
 
function Set-PromptBehavior {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName,
 
        [Parameter(Mandatory=$true)]
        [ValidateRange(0, 1)]
        [int]$Value
    )
 
    <#
    .SYNOPSIS
    Sets the consent prompt behavior for user account control on a remote computer.
 
    .DESCRIPTION
    This function sets the consent prompt behavior for user account control on a remote computer.
 
    .PARAMETER ComputerName
    Specifies the name of the remote computer.
 
    .PARAMETER Value
    Specifies the consent prompt behavior value. Valid values are 0 or 1.
 
    .EXAMPLE
    Set-PromptBehavior -ComputerName GENISINBXXXXX -Value 1
    Sets the consent prompt behavior on the remote computer to "1".
    #>
 
    Invoke-Command -ComputerName $ComputerName -ScriptBlock {
        param($Value)
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorUser" -Value $Value -Force
    } -ArgumentList $Value
}
 
 
#path za python
C:\Python;
C:\Python\Library\bin;
C:\Python\Library\mingw-w64\bin;
C:\Python\Library\usr\bin;
C:\Python\Scripts;