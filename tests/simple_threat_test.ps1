# Simple Threat Test - Create processes that Ghost Layer should detect
Write-Host "SIMPLE THREAT TEST" -ForegroundColor Red
Write-Host "Creating suspicious PowerShell processes..." -ForegroundColor Yellow

# Create multiple PowerShell processes that should trigger alerts
1..3 | ForEach-Object {
    Start-Process powershell -ArgumentList "-Command Write-Host \"THREAT_PROCESS_$_\"; Start-Sleep 2" -WindowStyle Hidden
    Write-Host "Created threat process $_" -ForegroundColor Green
    Start-Sleep -Milliseconds 500
}

Write-Host "Test complete!" -ForegroundColor Green
Write-Host "Check Ghost Layer dashboard at http://localhost:1420" -ForegroundColor Cyan
Write-Host "You should see threat alerts in the Threat Logs section" -ForegroundColor White
