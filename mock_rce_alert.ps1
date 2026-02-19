# Mock RCE Alert Test - Direct simulation
Write-Host "Creating mock RCE alert for testing..." -ForegroundColor Yellow

# This simulates what the RCE detector should emit when it finds
# a browser spawning PowerShell

$mockAlert = @{
    id = $null
    threat_type = "RCE_EXPLOIT"
    severity = "CRITICAL"
    target = "brave.exe (PID: 1516) -> powershell.exe (PID: 99999)"
    timestamp = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    entropy = $null
    additional_info = @{
        parent_process_name = "brave.exe"
        child_process_name = "powershell.exe"
    }
}

Write-Host "Mock alert created:" -ForegroundColor Green
Write-Host ($mockAlert | ConvertTo-Json -Depth 3) -ForegroundColor White

# This would be emitted by the RCE detector in a real scenario
Write-Host "In a real scenario, this would trigger:" -ForegroundColor Red
Write-Host "1. RCE Alert Modal in frontend" -ForegroundColor Yellow
Write-Host "2. Threat log entry" -ForegroundColor Yellow
Write-Host "3. AI explanation request" -ForegroundColor Yellow
