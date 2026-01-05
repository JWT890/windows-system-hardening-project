# windows-rdp-hardening-project

Windows 11 download: https://www.microsoft.com/en-us/software-download/windows11  

In this project, will be going over how to harden a Windows 11 Pro VM to protect from unauthorized attacks with the following steps. Securing RDP is important since it shows security concious thinking when security systems.  

After getting the Windows 11 VM set up, go to the PowerShell Admin command prompt and begin.  

# Hardening Implementation
Step 1: Service Handling  
Start by running the PowerShell command or by going to services.msc and disabling them like below:  
$servicesToDisable = @(  
    'RemoteRegistry',  
    'RemoteAccess',   
    'SSDPSRV',    
    'upnphost',   
    'WMPNetworkSvc',
    'XblAuthManager',  
    'XblGameSave'  
)  

foreach ($service in $servicesToDisable) {  
    Set-Service -Name $service -StartupType Disabled  
    Stop-Service -Name $service -Force -ErrorAction SilentlyContinue  
}  
And after going to look at services.msc with RemoteRegistry as an example:  
<img width="454" height="17" alt="image" src="https://github.com/user-attachments/assets/6d1ae2cd-ec80-413f-a641-21b49d3980b1" />  

Step 2: Windows Defender Configuration  
Next run the command:  
<img width="411" height="24" alt="image" src="https://github.com/user-attachments/assets/82036b80-a48c-4983-8b67-d18a76166704" />  
To enable real time protection.  
Next run the commands:  
<img width="639" height="104" alt="image" src="https://github.com/user-attachments/assets/3bc0f3ea-c75d-4c5b-b287-fbeaa752563d" />  
To enable cloud-delivered protection, enable automatic sample submission, enable PUA protection, network protection, and enable controlled folder access.  

Step 3: Security Policies:  
Create a PowerShell script and write this code to it to implement password security policy:  
$secPolicy = @"  
[Unicode]  
Unicode=yes  
[System Access]  
MinimumPasswordLength = 14  
PasswordComplexity = 1  
MaximumPasswordAge = 90  
MinimumPasswordAge = 1  
LockoutBadCount = 5  
ResetLockoutCount = 30  
LockoutDuration = 30  
[Version]  
signature="`$CHICAGO`$"  
Revision=1  
"@  


$secPolicy | Out-File C:\secpol.cfg -Encoding utf8  


Write-Host "Applying security policy..." -ForegroundColor Cyan  
secedit /configure /db C:\temp.sdb /cfg C:\secpol.cfg /areas SECURITYPOLICY /quiet  


if (Test-Path C:\secpol.cfg) { Remove-Item C:\secpol.cfg }  
if (Test-Path C:\temp.sdb) { Remove-Item C:\temp.sdb }  

Write-Host "Process Complete. Checking current policy:" -ForegroundColor Green  
net accounts  
After running it, go to Local Security Policy -> security settings -> password policy, and verify to confirm:  
<img width="746" height="246" alt="image" src="https://github.com/user-attachments/assets/5b07a781-93e1-463f-a06e-393ae6610399" />  
Then move on to do doing audit policies by typing these commands:  





