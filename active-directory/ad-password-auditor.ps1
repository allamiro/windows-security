
# Active Directory AD Password Weakness Auditor
# Tamir Suliman
# 


### Smartscreen disabled and execution policy is set to Bypass

Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\System -Name EnableSmartScreen -Value 0 -Force
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass –Force


### Check if the DSIinternals installed 


if ((Get-Command -Module  DSInternals)) {

   # Specify Dictionary File Location
   $PassDictFile = "C:\folder\passwordfile.txt"

   # Domain Controller Information
   $DomainController = "dc1host"
   $Domain = "DC=local,DC=domain"

   # Direct/Online  Scan to include Disabled Accounts
   Get-ADReplAccount -All -Server $DomainController -NamingContext $Domain | Test-PasswordQuality -WeakPasswordsFile $PassDictFile -IncludeDisabledAccounts


   # Offline Scan
   #Retrieves the BootKey from the currently running OS.
   reg.exe SAVE HKLM\SYSTEM C:\ADBackup\registery\SYSTEM.hiv
   $ADBkey = "C:\ADBackup\registery\SYSTEM.hiv"
   $ADDBpath ="C:\ADBackup\ntds.dit"
   # Reads the Boot Key (AKA SysKey or System Key) from an online or offline SYSTEM registry hive.
   
   $keyboot= Get-BootKey -SystemHiveFilePath $ADBkey
   Get-ADDBAccount -All -DatabasePath '$ADDBpath -BootKey $keyboot | Test-PasswordQuality -WeakPasswordsFile $PassDictFile'

}



else {

### True if the DSIinternals not installed
    Write-Verbose -Message "Installing DSIinternal Module" -Verbose
    Install-Module DSInternals -Force
    Write-Verbose -Message "Finished installing DSInternals" -Verbose
 
}


# Smartscreen enabled 
Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\System -Name EnableSmartScreen -Value 1 -Force



# References:
#1. https://4sysops.com/archives/find-weak-active-directory-passwords-with-powershell/
#2. https://github.com/MichaelGrafnetter/DSInternals/blob/master/Documentation/PowerShell/Get-BootKey.md
#3. http://woshub.com/auditing-users-password-strength-in-ad/
#4. https://sector.ca/sessions/active-directory-database-security/
