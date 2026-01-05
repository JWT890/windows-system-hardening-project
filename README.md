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
<img width="778" height="117" alt="image" src="https://github.com/user-attachments/assets/7d2c7f27-f2dd-47a7-8393-30d679174aab" />    

Step 4: RDP Hardening    
# Enable NLA (Network Level Authentication)    
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -Value 1    

# Set strong encryption    
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'MinEncryptionLevel' -Value 3    

# Disable RDP if not needed, or restrict access    
# To disable:    
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value 1    

# Configure Windows Firewall to allow RDP only from specific IPs    
New-NetFirewallRule -DisplayName "RDP-Restricted" -Direction Inbound -Protocol TCP -LocalPort 3389 -RemoteAddress "192.168.1.0/24" -Action Allow    
You will see this after running the last command:    
<img width="747" height="375" alt="image" src="https://github.com/user-attachments/assets/1723d443-8c58-4ce8-b60d-2366dd18bf2c" />    
Then run Remove-NetFirewallRule -DisplayName "Remote Desktop*"    
You can change the IP address by running this command:    
Allow RDP only from corporate networks
```powershell
New-NetFirewallRule -DisplayName "RDP-Corporate-Network-Only" `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort 3389 `
    -RemoteAddress "10.0.0.0/8", "192.168.1.0/24" `
    -Action Allow `
    -Profile Domain,Private `
    -Enabled True
```

### 2. Block RDP on Public Networks

```powershell
New-NetFirewallRule -DisplayName "RDP-Block-Public" `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort 3389 `
    -Action Block `
    -Profile Public `
    -Enabled True
```

### 3. Allow RDP Only from VPN Network

```powershell
New-NetFirewallRule -DisplayName "RDP-VPN-Only" `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort 3389 `
    -RemoteAddress "172.16.0.0/16" `
    -Action Allow
```
Then run the command:    
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' `
    -Name 'UserAuthentication' -Value 1.    
Then run the command:    
<img width="993" height="40" alt="image" src="https://github.com/user-attachments/assets/12eea0da-6b78-4bb6-88d9-058329ac8552" />    
With the value set to three to make it FIPS compliant.    
Then run the command:    
<img width="993" height="36" alt="image" src="https://github.com/user-attachments/assets/d73599e7-4e7f-42f9-98b8-b8c2632bf69b" />    
To have TSL/SSL enabled.    
Then run the command:    
<img width="769" height="37" alt="image" src="https://github.com/user-attachments/assets/75fd7a70-adb6-4d50-92e4-2251aada1b87" />    
To disable blank RDP passwords.    
Then run DIsable-LocalUser -Name "Guest" to disable the Guest account.    
Then run:
<img width="769" height="93" alt="image" src="https://github.com/user-attachments/assets/71ec08ec-93a6-4760-8984-7346fb8e2f90" />    
To create the RDP-Admins group. Then run the Add-LocalGroupMember -Group "RDP-Administrators" -Member "YourAdminUser" to add your Admin account.    
Then run:    
<img width="879" height="41" alt="image" src="https://github.com/user-attachments/assets/07c1275f-37c7-45c8-9ab2-a62f1f9dc47c" />    
It might work at first so run the command: $registryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" to create the registry path.    
Then run the for loop command:    
<img width="678" height="82" alt="image" src="https://github.com/user-attachments/assets/11d606db-2ca7-44a7-83a2-2c1dec066182" />    
Then run these commands and it should work:    
<img width="736" height="63" alt="image" src="https://github.com/user-attachments/assets/3950dc94-e618-4fb7-b647-7eb3d4f46d44" />    
Then run the commands:    
<img width="890" height="97" alt="image" src="https://github.com/user-attachments/assets/9d8f6728-b767-45c3-b876-729edfcd9afb" />    
to enable RDP audit logging.    
Next is to do RDP Session Restrictions.    
First run the command:    
<img width="920" height="38" alt="image" src="https://github.com/user-attachments/assets/06e05ab3-6d8c-4fed-9695-620a51d52850" />    
To enable idle timeout of 15 minutes.    
Then run the command:    
<img width="917" height="35" alt="image" src="https://github.com/user-attachments/assets/8ebd2926-54a3-4be9-82f3-01179fee1efc" />
To set disconnection timeout to 1 minute.    
Then run the command:    
<img width="879" height="38" alt="image" src="https://github.com/user-attachments/assets/79d9de3b-c4aa-4127-b1d0-feef511ca927" />    
Next up for RDP is disabling risk RDP features.    
Run the command:    
<img width="923" height="38" alt="image" src="https://github.com/user-attachments/assets/baa6f759-b7bd-4643-b435-5833bf019771" />    
To disable clipboard redirection.    
Then run the command:    
<img width="913" height="33" alt="image" src="https://github.com/user-attachments/assets/da49bb85-d25e-4b0e-8031-d12d2385b01b" />    
To disable drive redirection to prevent malware spread.    
Then run the command:    
<img width="919" height="34" alt="image" src="https://github.com/user-attachments/assets/5152be7a-8554-4640-b62a-adfc9ae782d4" />    
To disable printer redirection. 
Next is setting up a monitoring script for RDP connection.    
Run this in PowerShell:    
<img width="588" height="191" alt="image" src="https://github.com/user-attachments/assets/c46ac33f-e5b9-43b8-88dc-03e4d6ba3364" />    
Then run this command to disable RDP when not needed:    
<img width="856" height="36" alt="image" src="https://github.com/user-attachments/assets/a78bba89-b73c-4909-9081-f1f761594844" />    
And run these to stop and disable RDP:    
<img width="612" height="34" alt="image" src="https://github.com/user-attachments/assets/96061f24-22bd-4802-869a-ff72dad5a47b" />    
To re-enable:    
<img width="959" height="64" alt="image" src="https://github.com/user-attachments/assets/df98f71a-8c2c-46bc-bc50-f8da582f48ef" />    
To change the port run the command:
$newPort = 33891.    
Then run:    
<img width="1021" height="32" alt="image" src="https://github.com/user-attachments/assets/f15f4db2-7474-4d5c-a53d-5afb634f81b5" />    
Then run the command to update the firewall rule and get this result:    
<img width="711" height="483" alt="image" src="https://github.com/user-attachments/assets/01fd4af3-e642-4e38-b628-f0f479693372" />    
Then run the command:    
<img width="527" height="22" alt="image" src="https://github.com/user-attachments/assets/65c06cb9-5f4d-4d3f-b203-c40552676716" />    
To restart RDP.    
Then run the command:    
<img width="949" height="37" alt="image" src="https://github.com/user-attachments/assets/99865f16-1c16-493b-a7cf-8a1994864fdd" />
To update Documentation.    
Next step is to enable the bastion Host by running this command:    
<img width="786" height="490" alt="image" src="https://github.com/user-attachments/assets/a2f63996-3400-412f-bf44-c6cf70389533" />    
Then run this command to allow RDP to only internal servers only:    
<img width="708" height="491" alt="image" src="https://github.com/user-attachments/assets/73d3f4c9-cd87-49b6-aebb-5052d8ab21e1" />    
Then run this command to accept RDP only from the Bastion IP:    
<img width="417" height="19" alt="image" src="https://github.com/user-attachments/assets/b6bf1e2f-f208-4dc9-9b06-e8d53bbf9f49" />    
Then run this commands to set the firewall and remove any other RDP rules:    
<img width="769" height="547" alt="image" src="https://github.com/user-attachments/assets/848b8ba6-96ef-46d7-8db2-2ce36129f464" />    
Next is to enable MFA with DUO. Go to https://signup.duo.com/ and enter in you information, then go check your email.    
After verifying it and setting up with DUO after scanning the QR code, you will see the admin menu:    
<img width="1886" height="777" alt="image" src="https://github.com/user-attachments/assets/75c4028a-5986-4134-9fbd-622f97cd0202" />    
Then go to applications and search for Microsoft RDP and click on add and copy down the integration and secret keys and API hostname.    
Then go to the searchbar and type: https://dl.duosecurity.com/duo-win-login-latest.exe to download the installer.    
You will be prompted to enter the API hostname and the respective keys.    
Then check these boxes:    
<img width="496" height="382" alt="image" src="https://github.com/user-attachments/assets/35d30c83-7234-4b02-a078-66d582ae00f5" />    
Then click next until you see install and click install, then wait a few minutes and then reboot.    
Then to verify DUO, run the command:    
<img width="951" height="378" alt="image" src="https://github.com/user-attachments/assets/c33a53b0-9996-4315-8c63-8053873386ef" />    
Then to verify failmode:    
<img width="829" height="160" alt="image" src="https://github.com/user-attachments/assets/4db557a3-71f8-420d-a28d-a599487bc866" />    
Then to verify autopush:    
<img width="833" height="168" alt="image" src="https://github.com/user-attachments/assets/2acf6c80-3bb2-4519-948a-30a2dbfa6cb7" />    

Step 5: Comprehensive Logging & Monitoring:    
First run this command
<img width="893" height="37" alt="image" src="https://github.com/user-attachments/assets/2de9883d-8040-470b-a5f7-a73735412197" />
To enable detailed RDP logging.    
Then run these commands:    
<img width="897" height="144" alt="image" src="https://github.com/user-attachments/assets/a682d424-83d2-46ba-96ec-d0a59cf9a0ea" />    
To enable RDP connection logging.    
Then run the RDP_monitoring script from above and then run the command: wecutil qc to configure WIndows Event forwarding.    
You will see this and make sure to press y:    
<img width="845" height="33" alt="image" src="https://github.com/user-attachments/assets/553ff1fc-a3a0-46d7-80de-179057ea6f2f" />    
Next is scheduled disable for maintenance windows.    
Run the command:    
<img width="1215" height="39" alt="image" src="https://github.com/user-attachments/assets/b100e665-ca8d-4d3a-9a9d-7e82e45402b3" />    
To create a scheduled task to disable RDP after a specific time.    
Or run it as a script to download from above:    
<img width="1096" height="140" alt="image" src="https://github.com/user-attachments/assets/7b03b372-407a-4a59-867c-010e18d53523" />

Step 6: Detection and Response    
Next create a alert system script to alert for recent RDP login failures. the script to run is alert2.ps1 which can be gotten from above to run.    
Run it in PowerShell admin like so with this command: powershell -ExecutionPolicy Bypass -File "C:\path\to\the\file\alert2.ps1" and hit enter to see this result.    
<img width="453" height="80" alt="image" src="https://github.com/user-attachments/assets/bdf67dee-6362-463b-bd64-b1682cadb294" />    
The result is because there haven't been any RDP logins yet.    
Next create a baseline file to check the current configurations, download file will above to do as baseline2.ps1.    
Run in the command line or as a file and it will generate a baseline based off what is configured, might be a few bugs too.    
Result:    
<img width="1209" height="808" alt="image" src="https://github.com/user-attachments/assets/89653eab-b2b7-4c35-9026-9d354198dfff" />    
<img width="1198" height="805" alt="image" src="https://github.com/user-attachments/assets/325dc27a-7444-425c-a76e-ab1163664dfa" />
*Note that RDP is disabled, might be a bug*    
<img width="1195" height="820" alt="image" src="https://github.com/user-attachments/assets/fee26dd8-ec9c-4e0e-ac86-9213222817c2" />    
<img width="1192" height="462" alt="image" src="https://github.com/user-attachments/assets/3f94f8d7-ef4b-40a7-8651-8b5a491f1215" />    
*Successful logins might be a bug too*    












































