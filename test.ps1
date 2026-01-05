#Requires -RunAsAdministrator

function Test-FullSecuritySuite {
    $reportPath = "$PSScriptRoot\Security_Suite_Report.txt"
    $testResults = @()
    $reportContent = @()

    Clear-Host
    $header = @"
╔═══════════════════════════════════════════════════════════╗
║          SECURITY TESTING & SIEM VALIDATION               ║
║          Testing RDP, SMB, and WinRM Hardening            ║
╚═══════════════════════════════════════════════════════════╝
"@
    Write-Host $header -ForegroundColor Cyan
    $reportContent += "SECURITY AUDIT REPORT - $(Get-Date)"
    $reportContent += "Host: $($env:COMPUTERNAME)"
    $reportContent += "------------------------------------------------"

    # --- TEST 1: NLA Configuration ---
    Write-Host "`n[TEST 1] Network Level Authentication (NLA)" -ForegroundColor Yellow
    $nla = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp').UserAuthentication
    if ($nla -eq 1) {
        Write-Host "✓ PASS: NLA is enabled" -ForegroundColor Green
        $testResults += [PSCustomObject]@{Test="RDP-NLA"; Status="PASS"; Value="Enabled"}
    } else {
        Write-Host "✗ FAIL: NLA is disabled" -ForegroundColor Red
        $testResults += [PSCustomObject]@{Test="RDP-NLA"; Status="FAIL"; Value="Disabled"}
    }

    # --- TEST 2: Encryption Level ---
    Write-Host "[TEST 2] RDP Encryption Level" -ForegroundColor Yellow
    $encryption = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp').MinEncryptionLevel
    $encName = switch($encryption) { 1 {"Low"}; 2 {"Client Compatible"}; 3 {"High"}; 4 {"FIPS"}; Default {"Unknown"} }
    if ($encryption -ge 3) {
        Write-Host "✓ PASS: Encryption is $encName" -ForegroundColor Green
        $testResults += [PSCustomObject]@{Test="RDP-Encrypt"; Status="PASS"; Value=$encName}
    } else {
        Write-Host "✗ FAIL: Encryption is $encName" -ForegroundColor Red
        $testResults += [PSCustomObject]@{Test="RDP-Encrypt"; Status="FAIL"; Value=$encName}
    }

    # --- TEST 3: Firewall & Ports ---
    Write-Host "[TEST 3] Critical Port Audit" -ForegroundColor Yellow
    $ports = @{3389="RDP"; 445="SMB"; 5985="WinRM"}
    foreach ($p in $ports.Keys) {
        $isListening = Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue
        $fw = Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq 'True' -and ($_.DisplayName -like "*$p*" -or $_.Name -like "*$p*") }
        $status = if ($fw) { "Open" } else { "Closed" }
        $listen = if ($isListening) { "Active" } else { "Inactive" }
        Write-Host "  Port $p ($($ports[$p])): FW $status / Service $listen" -ForegroundColor Gray
        $testResults += [PSCustomObject]@{Test="Port-$p"; Status=$status; Value="Service-$listen"}
    }

    # --- TEST 4: Audit Policy ---
    Write-Host "[TEST 4] Logon Audit Policy" -ForegroundColor Yellow
    $logonAudit = auditpol /get /subcategory:"Logon"
    if ($logonAudit -like "*Success and Failure*") {
        Write-Host "✓ PASS: Logon auditing active" -ForegroundColor Green
        $testResults += [PSCustomObject]@{Test="Audit-Logon"; Status="PASS"; Value="Full"}
    } else {
        Write-Host "✗ FAIL: Audit policy insufficient" -ForegroundColor Red
        $testResults += [PSCustomObject]@{Test="Audit-Logon"; Status="FAIL"; Value="Missing"}
    }

    # --- TEST 5: SIEM Injection (Event ID 9999) ---
    Write-Host "[TEST 5] Generating SIEM Heartbeat" -ForegroundColor Yellow
    try {
        $source = "SecurityTestSuite"
        if (![System.Diagnostics.EventLog]::SourceExists($source)) { New-EventLog -LogName Application -Source $source }
        Write-EventLog -LogName Application -Source $source -EventId 9999 -EntryType Warning -Message "SIEM Connectivity Test"
        Write-Host "✓ SENT: Check SIEM for Event ID 9999" -ForegroundColor Cyan
        $testResults += [PSCustomObject]@{Test="SIEM-Test"; Status="SENT"; Value="ID 9999"}
    } catch { 
        Write-Host "✗ FAILED to write event" -ForegroundColor Red 
    }

    # --- TEST 6: Simulated Failed Login (Event ID 4625) ---
    Write-Host "[TEST 6] Simulating Brute Force (Event ID 4625)" -ForegroundColor Yellow
    # This triggers a local failed logon attempt
    $dummy = net use \\127.0.0.1\C$ /user:FakeUser BadPassword123 2>&1
    Write-Host "✓ TRIGGERED: Failed logon attempt created" -ForegroundColor Green
    $testResults += [PSCustomObject]@{Test="Attack-Sim"; Status="DONE"; Value="ID 4625"}

    # Finalizing Report
    $testResults | ForEach-Object { $reportContent += "$($_.Test): $($_.Status) ($($_.Value))" }
    $reportContent | Out-File -FilePath $reportPath -Encoding utf8
    
    Write-Host "`nSummary Table:" -ForegroundColor Cyan
    $testResults | Format-Table -AutoSize
    Write-Host "[>] Full report saved to: $reportPath" -ForegroundColor White
}

Test-FullSecuritySuite
