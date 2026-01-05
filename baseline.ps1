<#
.SYNOPSIS
    Dynamic Windows Security Baseline Generator
.DESCRIPTION
    Automatically detects and reports on all security configurations
    with smart recommendations based on your environment
#>

#Requires -RunAsAdministrator

param(
    [switch]$ExportJSON,
    [switch]$ExportCSV,
    [switch]$OpenReport = $true,
    [string]$OutputPath = "C:\SecurityBaseline"
)

# Colors for output
$colors = @{
    Pass = "Green"
    Fail = "Red"
    Warn = "Yellow"
    Info = "Cyan"
    Header = "Magenta"
}

function Write-Status {
    param($Message, $Status = "Info")
    $color = $colors[$Status]
    Write-Host "[$Status] $Message" -ForegroundColor $color
}

# Create output directory
New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null

$timestamp = Get-Date -Format "yyyy-MM-dd_HHmmss"
$reportFile = "$OutputPath\SecurityBaseline_$timestamp.html"

Write-Host "`n╔════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║   DYNAMIC SECURITY BASELINE GENERATOR                 ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan

# =====================================================
# COLLECT SYSTEM INFORMATION
# =====================================================
Write-Status "Collecting system information..." "Info"

$systemInfo = Get-CimInstance Win32_OperatingSystem
$computerInfo = Get-CimInstance Win32_ComputerSystem
$biosInfo = Get-CimInstance Win32_BIOS

$baselineData = @{
    Timestamp = Get-Date
    Hostname = $env:COMPUTERNAME
    Domain = $env:USERDOMAIN
    OSVersion = $systemInfo.Caption
    OSBuild = $systemInfo.BuildNumber
    Architecture = $systemInfo.OSArchitecture
    LastBoot = $systemInfo.LastBootUpTime
    Manufacturer = $computerInfo.Manufacturer
    Model = $computerInfo.Model
    TotalMemoryGB = [math]::Round($systemInfo.TotalVisibleMemorySize / 1MB, 2)
    Checks = @{}
}

# =====================================================
# DYNAMIC SECURITY CHECKS
# =====================================================

$allChecks = @()

# Check 1: Windows Defender
Write-Status "Checking Windows Defender..." "Info"
try {
    $defender = Get-MpComputerStatus
    $defenderChecks = @(
        @{Name="Real-Time Protection"; Value=$defender.RealTimeProtectionEnabled; Expected=$true},
        @{Name="Behavior Monitoring"; Value=$defender.BehaviorMonitorEnabled; Expected=$true},
        @{Name="IOAV Protection"; Value=$defender.IoavProtectionEnabled; Expected=$true},
        @{Name="Network Inspection"; Value=$defender.NISEnabled; Expected=$true},
        @{Name="Cloud Protection"; Value=$defender.MAPSReporting -ne 0; Expected=$true},
        @{Name="Automatic Sample Submission"; Value=$defender.SubmitSamplesConsent -ne 0; Expected=$true}
    )
    
    foreach ($check in $defenderChecks) {
        $status = if ($check.Value -eq $check.Expected) { "Pass" } else { "Fail" }
        $allChecks += [PSCustomObject]@{
            Category = "Windows Defender"
            Check = $check.Name
            Status = $status
            Current = $check.Value
            Expected = $check.Expected
            Risk = if ($status -eq "Fail") { "High" } else { "None" }
        }
    }
    $baselineData.Checks.Defender = $defenderChecks
} catch {
    Write-Status "Windows Defender not available" "Warn"
}

# Check 2: BitLocker
Write-Status "Checking BitLocker..." "Info"
try {
    $bitlocker = Get-BitLockerVolume -ErrorAction SilentlyContinue
    if ($bitlocker) {
        foreach ($vol in $bitlocker) {
            $status = if ($vol.ProtectionStatus -eq "On") { "Pass" } else { "Fail" }
            $allChecks += [PSCustomObject]@{
                Category = "Disk Encryption"
                Check = "BitLocker on $($vol.MountPoint)"
                Status = $status
                Current = "$($vol.ProtectionStatus) - $($vol.EncryptionPercentage)%"
                Expected = "On - 100%"
                Risk = if ($status -eq "Fail") { "Medium" } else { "None" }
            }
        }
        $baselineData.Checks.BitLocker = $bitlocker | Select-Object MountPoint, ProtectionStatus, EncryptionPercentage
    } else {
        $allChecks += [PSCustomObject]@{
            Category = "Disk Encryption"
            Check = "BitLocker"
            Status = "Fail"
            Current = "Not Available/Configured"
            Expected = "Enabled"
            Risk = "Medium"
        }
    }
} catch {
    Write-Status "BitLocker check failed" "Warn"
}

# Check 3: Firewall
Write-Status "Checking Firewall..." "Info"
$firewallProfiles = Get-NetFirewallProfile
foreach ($profile in $firewallProfiles) {
    $status = if ($profile.Enabled) { "Pass" } else { "Fail" }
    $inboundStatus = if ($profile.DefaultInboundAction -eq "Block") { "Secure" } else { "Review" }
    
    $allChecks += [PSCustomObject]@{
        Category = "Firewall"
        Check = "$($profile.Name) Profile"
        Status = $status
        Current = "Enabled: $($profile.Enabled), Inbound: $($profile.DefaultInboundAction)"
        Expected = "Enabled: True, Inbound: Block"
        Risk = if ($status -eq "Fail") { "Critical" } else { "None" }
    }
}
$baselineData.Checks.Firewall = $firewallProfiles | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction

# Check 4: RDP Configuration
Write-Status "Checking RDP..." "Info"
$rdpEnabled = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -ErrorAction SilentlyContinue).fDenyTSConnections
$nla = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -ErrorAction SilentlyContinue).UserAuthentication
$encryption = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -ErrorAction SilentlyContinue).MinEncryptionLevel
$secLayer = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -ErrorAction SilentlyContinue).SecurityLayer

$rdpChecks = @(
    @{Name="RDP Status"; Value=($rdpEnabled -eq 1); Expected=$true; Display="Disabled"},
    @{Name="Network Level Authentication"; Value=($nla -eq 1); Expected=$true; Display="Enabled"},
    @{Name="Encryption Level"; Value=($encryption -ge 3); Expected=$true; Display="High/FIPS"},
    @{Name="Security Layer"; Value=($secLayer -eq 2); Expected=$true; Display="SSL/TLS"}
)

foreach ($check in $rdpChecks) {
    $status = if ($check.Value -eq $check.Expected) { "Pass" } else { "Fail" }
    $allChecks += [PSCustomObject]@{
        Category = "RDP Security"
        Check = $check.Name
        Status = $status
        Current = $check.Display
        Expected = $check.Display
        Risk = if ($status -eq "Fail") { "High" } else { "None" }
    }
}
$baselineData.Checks.RDP = $rdpChecks

# Check 5: UAC
Write-Status "Checking UAC..." "Info"
$uac = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue
$uacLevel = $uac.ConsentPromptBehaviorAdmin
$secureDesktop = $uac.PromptOnSecureDesktop

$uacStatus = if ($uacLevel -eq 2 -and $secureDesktop -eq 1) { "Pass" } else { "Fail" }
$allChecks += [PSCustomObject]@{
    Category = "User Account Control"
    Check = "UAC Configuration"
    Status = $uacStatus
    Current = "Level: $uacLevel, Secure Desktop: $secureDesktop"
    Expected = "Level: 2, Secure Desktop: 1"
    Risk = if ($uacStatus -eq "Fail") { "Medium" } else { "None" }
}
$baselineData.Checks.UAC = @{Level=$uacLevel; SecureDesktop=$secureDesktop}

# Check 6: Critical Services
Write-Status "Checking services..." "Info"
$riskyServices = @('RemoteRegistry', 'RemoteAccess', 'SSDPSRV', 'upnphost', 'WMPNetworkSvc')
foreach ($svc in $riskyServices) {
    $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($service) {
        $status = if ($service.StartType -eq 'Disabled') { "Pass" } else { "Warn" }
        $allChecks += [PSCustomObject]@{
            Category = "Service Security"
            Check = $service.DisplayName
            Status = $status
            Current = "$($service.Status) / $($service.StartType)"
            Expected = "Disabled"
            Risk = if ($status -eq "Warn") { "Low" } else { "None" }
        }
    }
}

# Check 7: Password Policy
Write-Status "Checking password policy..." "Info"
$secpol = secedit /export /cfg "$env:TEMP\secpol.cfg" 2>&1 | Out-Null
$secpolContent = Get-Content "$env:TEMP\secpol.cfg" -ErrorAction SilentlyContinue
Remove-Item "$env:TEMP\secpol.cfg" -Force -ErrorAction SilentlyContinue

if ($secpolContent) {
    $minPwdLength = ($secpolContent | Select-String "MinimumPasswordLength").ToString().Split('=')[1].Trim()
    $pwdComplexity = ($secpolContent | Select-String "PasswordComplexity").ToString().Split('=')[1].Trim()
    $maxPwdAge = ($secpolContent | Select-String "MaximumPasswordAge").ToString().Split('=')[1].Trim()
    
    $pwdChecks = @(
        @{Name="Minimum Length"; Current=$minPwdLength; Expected=14; Op="ge"},
        @{Name="Complexity"; Current=$pwdComplexity; Expected=1; Op="eq"},
        @{Name="Maximum Age"; Current=$maxPwdAge; Expected=90; Op="le"}
    )
    
    foreach ($check in $pwdChecks) {
        $status = switch ($check.Op) {
            "ge" { if ([int]$check.Current -ge [int]$check.Expected) { "Pass" } else { "Fail" } }
            "le" { if ([int]$check.Current -le [int]$check.Expected) { "Pass" } else { "Warn" } }
            "eq" { if ($check.Current -eq $check.Expected) { "Pass" } else { "Fail" } }
        }
        
        $allChecks += [PSCustomObject]@{
            Category = "Password Policy"
            Check = $check.Name
            Status = $status
            Current = $check.Current
            Expected = $check.Expected
            Risk = if ($status -eq "Fail") { "High" } else { if ($status -eq "Warn") { "Low" } else { "None" } }
        }
    }
}

# Check 8: Recent Security Events
Write-Status "Analyzing security events..." "Info"
$eventChecks = @(
    @{Name="Failed Logins (24h)"; ID=4625; LogName="Security"},
    @{Name="Successful Logins (24h)"; ID=4624; LogName="Security"},
    @{Name="Account Lockouts (24h)"; ID=4740; LogName="Security"}
)

foreach ($event in $eventChecks) {
    $count = (Get-WinEvent -FilterHashtable @{LogName=$event.LogName; Id=$event.ID; StartTime=(Get-Date).AddHours(-24)} -ErrorAction SilentlyContinue | Measure-Object).Count
    
    $status = "Info"
    $risk = "None"
    if ($event.Name -like "*Failed*" -and $count -gt 50) {
        $status = "Warn"
        $risk = "Medium"
    }
    if ($event.Name -like "*Lockout*" -and $count -gt 0) {
        $status = "Warn"
        $risk = "Low"
    }
    
    $allChecks += [PSCustomObject]@{
        Category = "Security Events"
        Check = $event.Name
        Status = $status
        Current = $count
        Expected = "Monitor"
        Risk = $risk
    }
}

# =====================================================
# GENERATE REPORTS
# =====================================================
Write-Status "Generating report..." "Info"

# Calculate summary
$totalChecks = $allChecks.Count
$passCount = ($allChecks | Where-Object {$_.Status -eq "Pass"}).Count
$failCount = ($allChecks | Where-Object {$_.Status -eq "Fail"}).Count
$warnCount = ($allChecks | Where-Object {$_.Status -eq "Warn"}).Count
$infoCount = ($allChecks | Where-Object {$_.Status -eq "Info"}).Count
$complianceScore = [math]::Round(($passCount / ($passCount + $failCount + $warnCount)) * 100, 1)

# HTML Report
$html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Security Baseline - $($env:COMPUTERNAME)</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Arial, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px; }
        .container { max-width: 1200px; margin: 0 auto; background: white; border-radius: 10px; box-shadow: 0 10px 40px rgba(0,0,0,0.3); overflow: hidden; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; }
        .header h1 { font-size: 2.5em; margin-bottom: 10px; }
        .header .subtitle { opacity: 0.9; font-size: 1.1em; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; padding: 30px; background: #f8f9fa; }
        .summary-card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); text-align: center; }
        .summary-card h3 { color: #666; font-size: 0.9em; text-transform: uppercase; margin-bottom: 10px; }
        .summary-card .value { font-size: 2.5em; font-weight: bold; }
        .pass .value { color: #10b981; }
        .fail .value { color: #ef4444; }
        .warn .value { color: #f59e0b; }
        .score .value { color: #667eea; }
        .content { padding: 30px; }
        .category { margin-bottom: 30px; }
        .category h2 { color: #333; border-left: 4px solid #667eea; padding-left: 15px; margin-bottom: 15px; }
        table { width: 100%; border-collapse: collapse; background: white; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        th { background: #667eea; color: white; padding: 15px; text-align: left; font-weight: 600; }
        td { padding: 12px 15px; border-bottom: 1px solid #e5e7eb; }
        tr:hover { background: #f9fafb; }
        .badge { display: inline-block; padding: 4px 12px; border-radius: 12px; font-size: 0.85em; font-weight: 600; }
        .badge-pass { background: #d1fae5; color: #065f46; }
        .badge-fail { background: #fee2e2; color: #991b1b; }
        .badge-warn { background: #fef3c7; color: #92400e; }
        .badge-info { background: #dbeafe; color: #1e40af; }
        .risk-critical { color: #dc2626; font-weight: bold; }
        .risk-high { color: #ea580c; font-weight: bold; }
        .risk-medium { color: #f59e0b; }
        .risk-low { color: #84cc16; }
        .risk-none { color: #10b981; }
        .footer { background: #f8f9fa; padding: 20px; text-align: center; color: #666; border-top: 1px solid #e5e7eb; }
        .recommendations { background: #fef3c7; border-left: 4px solid #f59e0b; padding: 20px; margin: 20px 0; border-radius: 4px; }
        .recommendations h3 { color: #92400e; margin-bottom: 10px; }
        .recommendations ul { margin-left: 20px; }
        .recommendations li { margin: 5px 0; color: #78350f; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Security Baseline Report</h1>
            <div class="subtitle">
                $($env:COMPUTERNAME) | $($baselineData.OSVersion)<br>
                Generated: $(Get-Date -Format "MMMM dd, yyyy HH:mm:ss")
            </div>
        </div>
        
        <div class="summary">
            <div class="summary-card score">
                <h3>Compliance Score</h3>
                <div class="value">$complianceScore%</div>
            </div>
            <div class="summary-card pass">
                <h3>Passed</h3>
                <div class="value">$passCount</div>
            </div>
            <div class="summary-card fail">
                <h3>Failed</h3>
                <div class="value">$failCount</div>
            </div>
            <div class="summary-card warn">
                <h3>Warnings</h3>
                <div class="value">$warnCount</div>
            </div>
        </div>
        
        <div class="content">
"@

# Group checks by category
$categories = $allChecks | Group-Object Category

foreach ($cat in $categories) {
    $html += "<div class='category'><h2>$($cat.Name)</h2><table><thead><tr><th>Check</th><th>Status</th><th>Current</th><th>Expected</th><th>Risk</th></tr></thead><tbody>"
    
    foreach ($check in $cat.Group) {
        $badgeClass = "badge-$($check.Status.ToLower())"
        $riskClass = "risk-$($check.Risk.ToLower())"
        $html += "<tr><td>$($check.Check)</td><td><span class='badge $badgeClass'>$($check.Status)</span></td><td>$($check.Current)</td><td>$($check.Expected)</td><td class='$riskClass'>$($check.Risk)</td></tr>"
    }
    
    $html += "</tbody></table></div>"
}

# Add recommendations
$criticalIssues = $allChecks | Where-Object {$_.Risk -eq "Critical" -or $_.Risk -eq "High"}
if ($criticalIssues) {
    $html += @"
    <div class="recommendations">
        <h3>⚠️ Priority Recommendations</h3>
        <ul>
"@
    foreach ($issue in $criticalIssues) {
        $html += "<li><strong>$($issue.Category) - $($issue.Check):</strong> Current: $($issue.Current), Expected: $($issue.Expected)</li>"
    }
    $html += "</ul></div>"
}

$html += @"
        </div>
        <div class="footer">
            Report generated by Dynamic Security Baseline Generator<br>
            System: $($env:COMPUTERNAME) | User: $($env:USERNAME) | $(Get-Date)
        </div>
    </div>
</body>
</html>
"@

$html | Out-File -FilePath $reportFile -Encoding UTF8

# Export JSON
if ($ExportJSON) {
    $jsonFile = "$OutputPath\SecurityBaseline_$timestamp.json"
    $baselineData | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonFile -Encoding UTF8
    Write-Status "JSON exported: $jsonFile" "Pass"
}

# Export CSV
if ($ExportCSV) {
    $csvFile = "$OutputPath\SecurityBaseline_$timestamp.csv"
    $allChecks | Export-Csv -Path $csvFile -NoTypeInformation
    Write-Status "CSV exported: $csvFile" "Pass"
}

# =====================================================
# DISPLAY SUMMARY
# =====================================================
Write-Host "`n╔════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                  BASELINE SUMMARY                      ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan

Write-Host "Compliance Score: " -NoNewline
if ($complianceScore -ge 80) { Write-Host "$complianceScore%" -ForegroundColor Green }
elseif ($complianceScore -ge 60) { Write-Host "$complianceScore%" -ForegroundColor Yellow }
else { Write-Host "$complianceScore%" -ForegroundColor Red }

Write-Host "`nResults:"
Write-Host "  ✓ Pass: $passCount" -ForegroundColor Green
Write-Host "  ✗ Fail: $failCount" -ForegroundColor Red
Write-Host "  ⚠ Warn: $warnCount" -ForegroundColor Yellow
Write-Host "  ℹ Info: $infoCount" -ForegroundColor Cyan

Write-Host "`nReport saved: $reportFile" -ForegroundColor Cyan

if ($OpenReport) {
    Write-Host "`nOpening report..." -ForegroundColor Yellow
    Start-Process $reportFile
}

Write-Host "`n[✓] Baseline generation complete!`n" -ForegroundColor Green
