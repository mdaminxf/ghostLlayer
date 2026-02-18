# Simple RCE Detection Test
Write-Host "=== Ghost Layer RCE Test ===" -ForegroundColor Green

# Test 1: Chrome spawning cmd.exe
Write-Host "Test 1: Chrome -> cmd.exe" -ForegroundColor Yellow
$chrome = Start-Process -FilePath "cmd.exe" -ArgumentList "/c echo Fake Chrome && timeout /t 5 >nul" -PassThru -WindowStyle Hidden
Write-Host "Chrome PID: $($chrome.Id)" -ForegroundColor Cyan

Start-Sleep -Seconds 1
$cmd1 = Start-Process -FilePath "cmd.exe" -ArgumentList "/c echo Malicious cmd && timeout /t 3 >nul" -PassThru
Write-Host "Malicious cmd PID: $($cmd1.Id)" -ForegroundColor Red

# Test 2: Word spawning powershell.exe  
Write-Host "Test 2: Word -> powershell.exe" -ForegroundColor Yellow
$word = Start-Process -FilePath "cmd.exe" -ArgumentList "/c echo Fake Word && timeout /t 5 >nul" -PassThru -WindowStyle Hidden
Write-Host "Word PID: $($word.Id)" -ForegroundColor Cyan

Start-Sleep -Seconds 1
$ps1 = Start-Process -FilePath "powershell.exe" -ArgumentList "-Command Write-Host Malicious PS; Start-Sleep 3" -PassThru
Write-Host "Malicious PS PID: $($ps1.Id)" -ForegroundColor Red

# Test 3: Normal process
Write-Host "Test 3: Normal notepad.exe" -ForegroundColor Green
$notepad = Start-Process -FilePath "notepad.exe" -PassThru
Write-Host "Notepad PID: $($notepad.Id)" -ForegroundColor Green

Write-Host "=== Test Complete ===" -ForegroundColor Green
Write-Host "Check Ghost Layer dashboard for alerts!" -ForegroundColor Cyan

# Cleanup
Start-Sleep -Seconds 10
Get-Process | Where-Object { $_.ProcessName -in @("cmd", "notepad", "powershell") } | Stop-Process -Force -ErrorAction SilentlyContinue
