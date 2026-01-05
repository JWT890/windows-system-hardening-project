$action = New-ScheduledTaskAction -Execute 'PowerShell.exe' `
    -Argument '-Command "Set-ItemProperty -Path ''HKLM:\System\CurrentControlSet\Control\Terminal Server'' -Name ''fDenyTSConnections'' -Value 1"'

$trigger = New-ScheduledTaskTrigger -Daily -At "6:00PM"

Register-ScheduledTask -TaskName "Disable-RDP-After-Hours" `
    -Action $action -Trigger $trigger -RunLevel Highest
