# Check for RDP brute force attempts (10+ failures in 5 minutes)

Write-Host "=== Checking for RDP Brute Force Attempts ===" -ForegroundColor Cyan

# Method 1: Using Get-WinEvent (Modern approach)
try {
    $startTime = (Get-Date).AddMinutes(-5)
    
    # Get failed logon events (Event ID 4625)
    $events = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        Id = 4625
        StartTime = $startTime
    } -ErrorAction SilentlyContinue
    
    if ($events) {
        # Group by source IP address (index 19 in the event properties)
        $grouped = $events | Group-Object {
            try {
                $_.Properties[19].Value  # Source IP is at index 19
            } catch {
                "Unknown"
            }
        }
        
        # Find IPs with 10+ failed attempts
        $bruteForce = $grouped | Where-Object {$_.Count -ge 10}
        
        if ($bruteForce) {
            Write-Host "`n[!] ALERT: Potential RDP brute force detected!" -ForegroundColor Red
            foreach ($attack in $bruteForce) {
                Write-Host "    Source IP: $($attack.Name)" -ForegroundColor Yellow
                Write-Host "    Failed Attempts: $($attack.Count)" -ForegroundColor Yellow
                Write-Host "    Time Window: Last 5 minutes`n" -ForegroundColor Yellow
            }
        } else {
            Write-Host "[+] No brute force detected (less than 10 failures)" -ForegroundColor Green
        }
    } else {
        Write-Host "[+] No failed RDP attempts in the last 5 minutes" -ForegroundColor Green
    }
    
} catch {
    Write-Host "[-] Error checking for brute force: $_" -ForegroundColor Red
}

# Method 2: Using Get-EventLog (Legacy but simpler - for older systems)
Write-Host "`n--- Alternative Check (Get-EventLog) ---" -ForegroundColor Cyan

try {
    $failedLogins = Get-EventLog -LogName Security -After (Get-Date).AddMinutes(-5) -ErrorAction SilentlyContinue |
        Where-Object {$_.EventID -eq 4625}
    
    if ($failedLogins) {
        Write-Host "[!] Found $($failedLogins.Count) failed login attempts in last 5 minutes" -ForegroundColor Yellow
        
        # Group by username
        $byUser = $failedLogins | Group-Object {$_.ReplacementStrings[5]}
        
        foreach ($user in $byUser | Where-Object {$_.Count -ge 5}) {
            Write-Host "    Username: $($user.Name) - Attempts: $($user.Count)" -ForegroundColor Yellow
        }
    } else {
        Write-Host "[+] No failed login attempts found" -ForegroundColor Green
    }
    
} catch {
    Write-Host "[-] Get-EventLog method not available or no events found" -ForegroundColor Yellow
}
