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

# 1. Save with UTF-8 encoding (which secedit requires for 'Unicode=yes' templates)
$secPolicy | Out-File C:\secpol.cfg -Encoding utf8

# 2. Run the configuration
Write-Host "Applying security policy..." -ForegroundColor Cyan
secedit /configure /db C:\temp.sdb /cfg C:\secpol.cfg /areas SECURITYPOLICY /quiet

# 3. Clean up only if files exist to avoid red error text
if (Test-Path C:\secpol.cfg) { Remove-Item C:\secpol.cfg }
if (Test-Path C:\temp.sdb) { Remove-Item C:\temp.sdb }

Write-Host "Process Complete. Checking current policy:" -ForegroundColor Green
net accounts
