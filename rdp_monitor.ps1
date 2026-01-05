# Monitor recent RDP connections (last 24 hours)
Get-EventLog -LogName Security -After (Get-Date).AddHours(-24) | 
    Where-Object {$_.EventID -eq 4624 -and $_.Message -match "Logon Type:\s+10"} |
    Select-Object TimeGenerated, 
                  @{N='User';E={$_.ReplacementStrings[5]}}, 
                  @{N='SourceIP';E={$_.ReplacementStrings[18]}} |
    Format-Table -AutoSize

# Check for failed RDP attempts (potential brute force)
Get-EventLog -LogName Security -After (Get-Date).AddHours(-1) |
    Where-Object {$_.EventID -eq 4625} |
    Group-Object {$_.ReplacementStrings[5]} |
    Where-Object {$_.Count -ge 5} |
    Select-Object Count, Name
