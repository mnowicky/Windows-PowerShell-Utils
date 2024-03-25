<#
.ABOUT
A PowerShell script for implementing a variety of security hardening configurations on Domain Controllers.

.DESCRIPTION
This script provides options for applying various security hardening settings to Domain Controllers, such as implementing NetCease, disabling SMB1, resetting the Kerberos account, creating and applying Group Policy Objects (GPOs) for various settings, and more. Detailed logging is also implemented to track the actions performed and their results.

.NOTES
File Name      : DomainControllerHardening.ps1
Author         : Matthew Nowicky
Prerequisite   : PowerShell V5.1, Active Directory PowerShell Module
Usage          : To be run with Administrative privileges in a PowerShell environment configured to run scripts and with necessary modules available.
#>

try {
    $host.ui.RawUI.WindowSize = New-Object System.Management.Automation.Host.Size (90,25)
} catch {
    Write-Warning "Unable to set window size. Continuing..."
}
$logArray = @()
$domainFQDN = (Get-ADDomain).DNSRoot
$logDir = "C:\Avasek"
if (-not (Test-Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir | Out-Null
}
$logFilePath = "$logDir\DC Hardening For $($env:COMPUTERNAME).$domainFQDN.txt"

do {

    Write-Host "1.) Impliment NetCease"
    Write-Host "2.) Disable SMB1"
    Write-Host "3.) Reset Kerberos account"
    Write-Host "4.) Create Disable LLMNR GPO"
    Write-Host "5.) Set dSHeuristics for CVE mitigation"
    Write-Host "6.) Disable Spooler Service"
    Write-Host "7.) Protect Admin users from deligation"
    Write-Host "8.) Reset Both Domain & Domain Controller Policies"
    Write-Host "9.) Remove Temporary SDAdmin Holders"
    Write-Host "10.) Disable unnecessary services for DCs"
    Write-Host "11.) Create Enforce LDAP Signing GPO"
    Write-Host "12.) Set Strong Password Policy"
	Write-Host "13.) Show Logs"
    Write-Host "Q: Le Quit."

    # Prompt for user's choice
    $choice = Read-Host "Enter the number of the action you want to perform"

    # Variables
    $adminGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators")
    $domainDistinguishedName = (Get-ADDomain).DistinguishedName
    $timestamp = Get-Date
    $logEntry = @{
        'Timestamp' = $timestamp;
        'Action'    = $null;
        'Result'    = $null;
    }

switch ($choice) {
	"1" {
$gpoName = "NetCease Implementation"
$targetOU = "OU=Domain Controllers," + (Get-ADDomain).DistinguishedName
$regPath = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity"
$regValue = "SrvsvcSessionInfo"
$regData = 1 
$logMessage = ""
try {
    New-GPO -Name $gpoName -Comment "GPO to implement NetCease settings"
    $logMessage += "[$(Get-Date)] - Action: Create GPO - Result: Successfully created GPO '$gpoName'."

    New-GPLink -Name $gpoName -Target $targetOU -LinkEnabled Yes
    $logMessage += "`n[$(Get-Date)] - Action: Link GPO - Result: Successfully linked GPO '$gpoName' to '$targetOU'."

    Set-GPRegistryValue -Name $gpoName -Key $regPath -ValueName $regValue -Type DWord -Value $regData
    $logMessage += "`n[$(Get-Date)] - Action: Set Registry Value - Result: Successfully set registry value in '$regPath' for GPO '$gpoName'."

    Set-GPPermissions -Name $gpoName -TargetName "Domain Controllers" -TargetType Group -PermissionLevel GpoApply
    Set-GPPermissions -Name $gpoName -TargetName "Authenticated Users" -TargetType Group -PermissionLevel GpoRead
    $logMessage += "`n[$(Get-Date)] - Action: Set GPO Permissions - Result: Successfully set permissions for GPO '$gpoName'."

} catch {
    $logMessage += "`n[$(Get-Date)] - Action: Implement NetCease via GPO - Result: Failed with error: $_"
}

Add-Content -Path $logFilePath -Value $logMessage
Write-Output "GPO '$gpoName' has been created, linked, and configured."
}

    "2" { 
        # Disable SMB1 protocol if installed
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB1 -Type DWORD -Value 0 –Force

        $SMB1Status = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name SMB1
        if ($SMB1Status.SMB1 -eq 0) {
            $logMessage = "[$(Get-Date)] - Action: Disable SMB1 - Result: SMB1 has been successfully disabled."
        } else {
            $logMessage = "[$(Get-Date)] - Action: Disable SMB1 - Result: Failed to disable SMB1. Please check manually."
        }
        Add-Content -Path $logFilePath -Value $logMessage
    }

"3" {
    # Reset kERBEROS account 
    $kerberosAccount = Get-ADUser -Identity "krbtgt" -Properties "PwdLastSet"
    $lastPwdResetOld = [DateTime]::FromFileTime($kerberosAccount.PwdLastSet)
    $logMessage = "[$(Get-Date)] - Action: Reset krbtgt account - Previous PwdLastSet: $lastPwdResetOld."
    $newPassword1 = -join ((65..90) + (97..122) + (48..57) + (33..47) | Get-Random -Count 24 | % { [char]$_ })
    $newPassword2 = -join ((65..90) + (97..122) + (48..57) + (33..47) | Get-Random -Count 24 | % { [char]$_ })
    Set-ADAccountPassword -Identity "krbtgt" -Reset -NewPassword (ConvertTo-SecureString -AsPlainText $newPassword1 -Force)
    Set-ADAccountPassword -Identity "krbtgt" -Reset -NewPassword (ConvertTo-SecureString -AsPlainText $newPassword2 -Force)
    $kerberosAccount = Get-ADUser -Identity "krbtgt" -Properties "PwdLastSet"
    $lastPwdResetNew = [DateTime]::FromFileTime($kerberosAccount.PwdLastSet)
    $logMessage += "`n[$(Get-Date)] - Action: Reset krbtgt account - Result: Successfully reset krbtgt account. New PwdLastSet: $lastPwdResetNew."
    Add-Content -Path $logFilePath -Value $logMessage
    Write-Host "The password for $($kerberosAccount.Name) was last set on $($lastPwdResetOld) before resetting."
    Write-Host "The password for $($kerberosAccount.Name) is now set on $($lastPwdResetNew) after resetting."
}
    
    "4" { 
    # GPO creation to disable LLMNR
    $domainDistinguishedName = (Get-ADDomain).DistinguishedName
    $gpoName = "Disable LLMNR for DCs"
    $logMessage = ""
    try {
        New-GPO -Name $gpoName
        $logMessage += "[$(Get-Date)] - Action: Create GPO - Result: Successfully created GPO '$gpoName'."

        New-GPLink -Name $gpoName -Target "OU=Domain Controllers,$domainDistinguishedName" -LinkEnabled Yes
        $logMessage += "`n[$(Get-Date)] - Action: Link GPO - Result: Successfully linked GPO '$gpoName' to 'OU=Domain Controllers,$domainDistinguishedName'."

        $gpoPath = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
        $gpoProperty = "EnableMulticast"
        Set-GPRegistryValue -Name $gpoName -Key $gpoPath -ValueName $gpoProperty -Type DWord -Value 0
        $logMessage += "`n[$(Get-Date)] - Action: Set Registry Value - Result: Successfully set registry value in '$gpoPath' for GPO '$gpoName'."

        Set-GPPermissions -Name $gpoName -TargetName "Authenticated Users" -TargetType Group -PermissionLevel GpoRead
        Set-GPPermissions -Name $gpoName -TargetName "Domain Controllers" -TargetType Group -PermissionLevel GpoApply
        $logMessage += "`n[$(Get-Date)] - Action: Set GPO Permissions - Result: Successfully set permissions for GPO '$gpoName'."

    } catch {
        $logMessage += "`n[$(Get-Date)] - Action: Create GPO to disable LLMNR - Result: Failed with error: $_"
    }
    Add-Content -Path $logFilePath -Value $logMessage
}

    "5" { 
    # Set dSHeuristics to enable mitigation for CVE-2021-42291
    $directoryServiceDN = "CN=Directory Service,CN=Windows NT,CN=Services," + (Get-ADRootDSE).configurationNamingContext
    $directoryService = Get-ADObject -Filter 'ObjectClass -eq "directoryService"' -SearchBase $directoryServiceDN -Properties dSHeuristics

    if ($directoryService) {
        $dsHeuristicsValue = $directoryService.dSHeuristics
        if (-not $dsHeuristicsValue) {
            $dsHeuristicsValue = "0000002"
        } else {
            if ($dsHeuristicsValue.Length -lt 7) {
                $dsHeuristicsValue = $dsHeuristicsValue.PadRight(7, "0")
            }
            $dsHeuristicsValue = $dsHeuristicsValue.Substring(0, 6) + "2" + $dsHeuristicsValue.Substring(7)
        }
        Set-ADObject -Identity $directoryService.DistinguishedName -Replace @{dSHeuristics = $dsHeuristicsValue}

        $logMessage = "[$(Get-Date)] - Action: Set dSHeuristics for CVE-2021-42291 mitigation - Result: Successfully updated dSHeuristics value."
        Add-Content -Path $logFilePath -Value $logMessage
    } else {
        Write-Warning "Failed to fetch the directoryService object from AD. Please check your AD connection and permissions."

        $logMessage = "[$(Get-Date)] - Action: Set dSHeuristics for CVE-2021-42291 mitigation - Result: Failed to fetch the directoryService object from AD."
        Add-Content -Path $logFilePath -Value $logMessage
    }
}
    "6" { 
    # Disable Spooler Service
    $spoolerService = Get-Service -Name Spooler -ComputerName $env:COMPUTERNAME
    $initialStatus = $spoolerService.Status
    $logMessage = "[$(Get-Date)] - Action: Check Spooler Service - Initial Status: $initialStatus."

    if ($initialStatus -eq 'Running') {
        Stop-Service -Name Spooler -Force
        Set-Service -Name Spooler -StartupType Disabled
        $finalStatus = (Get-Service -Name Spooler -ComputerName $env:COMPUTERNAME).Status
        $logMessage += "`n[$(Get-Date)] - Action: Disable Spooler Service - Result: Spooler Service was running and has been stopped. Startup type set to Disabled. Final Status: $finalStatus."
    } else {
        $logMessage += "`n[$(Get-Date)] - Action: Disable Spooler Service - Result: Spooler Service was not running. No action taken."
    }
    Add-Content -Path $logFilePath -Value $logMessage
    $logEntry.Result = "Spooler Service status updated. Initial Status: $initialStatus. Final Status: $finalStatus."
}

    "7" { 
    # Protect users in administrative groups from delegation
    $protectedUsers = @()
    foreach ($group in $adminGroups) {
        $groupMembers = Get-ADGroupMember -Identity $group | Where-Object { $_.objectClass -eq "user" }

        foreach ($user in $groupMembers) {
            $adUser = Get-ADUser -Identity $user.SamAccountName -Properties userAccountControl

            if (-not ($adUser.userAccountControl -band 1048576)) {
                Set-ADUser -Identity $user.SamAccountName -ProtectedFromAccidentalDeletion $true
                $adUser.userAccountControl = $adUser.userAccountControl -bor 1048576
                Set-ADUser -Instance $adUser
                $protectedUsers += $user.SamAccountName
            }
        }
    }
    if ($protectedUsers.Count -gt 0) {
        $logMessage = "[$(Get-Date)] - Action: Protect users in administrative groups from delegation - Result: Protected users: $($protectedUsers -join ', ') These users are now protected from deligation from lesser privledged users."
    } else {
        $logMessage = "[$(Get-Date)] - Action: Protect users in administrative groups from delegation - Result: No users required protection as all current users in all administrator groups are protected from deligation from lesser privledged users."
    }
    Add-Content -Path $logFilePath -Value $logMessage
    $logEntry.Result = "Protected users from delegation."
}

   "8" {
    # DCGPOFix to restore Default Domain Policy and Default Domain Controllers Policy
    $logMessage = ""
    try {
        $dcgpofixOutput = DCGPOFix.exe /ignoreschema /Target:both
        if ($dcgpofixOutput -match "completed successfully") {
            $logMessage += "[$(Get-Date)] - Action: Run DCGPOFix - Result: Successfully ran DCGPOFix to reset the default domain controller and default domain group policy objects to their default state and resync SYSVOL permissions for these GPOs. Output: $dcgpofixOutput"
        } else {
            $logMessage += "[$(Get-Date)] - Action: Run DCGPOFix - Result: DCGPOFix ran with issues. Output: $dcgpofixOutput"
        }
    } catch {
        $logMessage += "[$(Get-Date)] - Action: Run DCGPOFix - Result: Failed to run DCGPOFix. Error: $_"
    }
    Add-Content -Path $logFilePath -Value $logMessage
}

    "9" {
    function SDClean {
        [cmdletbinding()]
        param()

        $orphan_results = @()
        $flagged_object = foreach ($domain in (Get-ADForest).domains) {
            Get-ADObject -Filter 'adminCount -eq 1 -and iscriticalsystemobject -notlike "*"' -Server $domain -Properties whenchanged, whencreated, admincount, isCriticalSystemObject, "msDS-ReplAttributeMetaData", samaccountname | Select-Object @{name='Domain';expression={$domain}}, distinguishedname, whenchanged, whencreated, admincount, SamAccountName, objectclass, isCriticalSystemObject, @{name='adminCountDate';expression={($_ | Select-Object -ExpandProperty "msDS-ReplAttributeMetaData" | foreach {([XML]$_.Replace("`0","")).DS_REPL_ATTR_META_DATA | where { $_.pszAttributeName -eq "admincount"}}).ftimeLastOriginatingChange | Get-Date -Format MM/dd/yyyy}}
        }

        $default_admin_groups = foreach ($domain in (Get-ADForest).domains) {
            Get-ADGroup -Filter 'admincount -eq 1 -and iscriticalsystemobject -like "*"' -Server $domain | Select-Object @{name='Domain';expression={$domain}}, distinguishedname
        }

        foreach ($object in $flagged_object) {
            $udn = ($object).distinguishedname
            $results = foreach ($group in $default_admin_groups) {
                $object | Select-Object @{Name="Group_Domain";Expression={$group.domain}}, @{Name="Group_Distinguishedname";Expression={$group.distinguishedname}}, @{Name="Member";Expression={if (Get-ADgroup -Filter {member -RecursiveMatch $udn} -SearchBase $group.distinguishedname -Server $group.domain) {$True} else {$False}}}, domain, distinguishedname, admincount, adminCountDate, whencreated, objectclass
            }

            if (-not ($results | Where-Object {$_.member})) {
                $orphan_results += $results | Select-Object Domain, objectclass, admincount, adminCountDate, distinguishedname | Get-Unique
            }
        }

        return $orphan_results
    }

    $staleUsers = SDClean

    $clearedUsers = @()
    foreach ($user in $staleUsers) {
        Set-ADUser -Identity $user.SamAccountName -Clear adminCount
        $clearedUsers += $user.SamAccountName
    }

    if ($clearedUsers.Count -gt 0) {
        $logMessage = "[$(Get-Date)] - Action: Remove Temp SDAdmin Holders - Result: Cleared adminCount for users: $($clearedUsers -join ', ') Cleared adminCount for temporary SDAdmin Holders. The system performed a check to identify any users who were temporarily given elevated (administrative) access rights and remove such temporary privileges if found."
    } else {
        $logMessage = "[$(Get-Date)] - Action: Remove Temp SDAdmin Holders - Result: No users required adminCount clearance."
    }

    Add-Content -Path $logFilePath -Value $logMessage
    $logEntry.Result = "Cleared adminCount for temporary SDAdmin Holders. The system performed a check to identify any users who were temporarily given elevated (administrative) access rights and remove such temporary privileges if found."
}

    "10" { 
    # Disable unnecessary services for DCs
    $servicesToDisable = @("wuauserv", "WebClient", "Fax", "WSearch")
    $logMessages = @()
    
    foreach ($service in $servicesToDisable) {
        $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
        
        if ($svc) {
            $initialStatus = $svc.Status
            $logMessage = "[$(Get-Date)] - Action: Evaluate and disable service - Service: $service - Initial Status: $initialStatus."
            
            try {
                Stop-Service -Name $service -Force
                Set-Service -Name $service -StartupType Disabled
                $finalStatus = (Get-Service -Name $service).Status
                $logMessage += " Action Taken: Stopped and Disabled. Final Status: $finalStatus."
            } catch {
                $finalStatus = (Get-Service -Name $service -ErrorAction SilentlyContinue).Status
                $logMessage += " Action Taken: None (Failed to Stop/Disable). Final Status: $finalStatus."
            }
        } else {
            $logMessage = "[$(Get-Date)] - Action: Evaluate and disable service - Service: $service - Initial Status: Not Installed."
            $logMessage += " Action Taken: None. Final Status: Not Installed."
        }
        
        $logMessages += $logMessage
    }
    
    foreach ($logMessage in $logMessages) {
        Add-Content -Path $logFilePath -Value $logMessage
    }

    $logEntry.Result = "Services evaluation and disablement process completed."
}

	"11" { 
    # LDAP signing GPO
    $ldapGpoName = "Enforce LDAP Signing"
    try {
        New-GPO -Name $ldapGpoName
        $logMessage = "[$(Get-Date)] - Action: Create GPO - Result: Successfully created GPO '$ldapGpoName'."
        Add-Content -Path $logFilePath -Value $logMessage
        $domainDistinguishedName = (Get-ADDomain).DistinguishedName
        New-GPLink -Name $ldapGpoName -Target "OU=Domain Controllers,$domainDistinguishedName" -LinkEnabled Yes
        $logMessage = "[$(Get-Date)] - Action: Link GPO - Result: Successfully linked GPO '$ldapGpoName' to 'OU=Domain Controllers,$domainDistinguishedName'."
        Add-Content -Path $logFilePath -Value $logMessage
        $ldapGpoPath = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
        $ldapGpoProperty = "LDAPServerIntegrity"
        Set-GPRegistryValue -Name $ldapGpoName -Key $ldapGpoPath -ValueName $ldapGpoProperty -Type DWord -Value 2
        $logMessage = "[$(Get-Date)] - Action: Set Registry Value - Result: Successfully set registry value for '$ldapGpoProperty' in GPO '$ldapGpoName'."
        Add-Content -Path $logFilePath -Value $logMessage
        
        Set-GPPermissions -Name $ldapGpoName -TargetName "Authenticated Users" -TargetType Group -PermissionLevel GpoRead
        Set-GPPermissions -Name $ldapGpoName -TargetName "Domain Controllers" -TargetType Group -PermissionLevel GpoApply
        $logMessage = "[$(Get-Date)] - Action: Set GPO Permissions - Result: Successfully set permissions for GPO '$ldapGpoName'."
        Add-Content -Path $logFilePath -Value $logMessage
        
        $logEntry.Result = "Successfully enforced LDAP signing via GPO."
    } catch {
        $logMessage = "[$(Get-Date)] - Action: Enforce LDAP Signing via GPO - Result: Failed with error: $_"
        Add-Content -Path $logFilePath -Value $logMessage
        
        $logEntry.Result = "Failed to enforce LDAP signing. Error: $_"
    }
}
	"12" { 
    try {
        # Update Default Domain Password Policy
        Set-ADDefaultDomainPasswordPolicy -Identity $domainFQDN `
            -MinPasswordLength 14 `
            -PasswordHistoryCount 24 `
            -MaxPasswordAge 180.00:00:00 `
            -LockoutDuration 00:20:00 `
            -LockoutObservationWindow 00:20:00 `
            -LockoutThreshold 5 `
            -ComplexityEnabled $true `
            -ReversibleEncryptionEnabled $false

        $logMessage = "[$(Get-Date)] - Action: Update Default Domain Password Policy - Result: Successfully updated policy."
        Add-Content -Path $logFilePath -Value $logMessage
        Write-Host "Password policy updated successfully."

        $logEntry.Result = "Successfully updated password policy."
    } 
    catch {
        $logMessage = "[$(Get-Date)] - Action: Update Default Domain Password Policy - Result: Failed with error: $_"
        Add-Content -Path $logFilePath -Value $logMessage
        Write-Host "Failed to update password policy: $_"

        $logEntry.Result = "Failed to update password policy. Error: $_"
    }
}
	
	"13" {
    Write-Host "Displaying logs:"
    $logs = Get-Content -Path $logFilePath
    $logs | Out-GridView -Title "DC Hardening Logs"
}
	"Q" {
		exit
	 }
    }
    if ($choice -ne "12" -and $choice -ne "Q") {
        $logArray += $logEntry
    }

    Write-Output "Press any key to return to the main menu..."
    $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    Clear-Host

} while ($choice -ne "Q")

Write-Output "Script execution completed."
