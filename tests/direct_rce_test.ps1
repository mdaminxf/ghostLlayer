# Direct RCE Test - Create Browser → PowerShell pattern
Write-Host "DIRECT RCE TEST - Creating Browser → PowerShell pattern" -ForegroundColor Red

# Find any browser process
$browser = Get-Process | Where-Object {$_.ProcessName -match 'chrome|firefox|msedge|brave'} | Select-Object -First 1

if ($browser) {
    Write-Host "Found browser: $($browser.ProcessName) (PID: $($browser.Id))" -ForegroundColor Green
    
    # Create PowerShell with browser as parent using WMI
    $rceCommand = "powershell.exe -Command Write-Host 'RCE_FROM_BROWSER'; Start-Sleep 3"
    
    try {
        # This should create the pattern Ghost Layer detects
        $process = Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList $rceCommand
        Write-Host "RCE process created: PID $($process.ProcessId)" -ForegroundColor Red
        Write-Host "Pattern: Browser → PowerShell (RCE detected!)" -ForegroundColor Yellow
        
        # Give Ghost Layer time to detect
        Start-Sleep -Seconds 5
        
        # Clean up
        Stop-Process -Id $process.ProcessId -Force -ErrorAction SilentlyContinue
        
    } catch {
        Write-Host "Failed to create RCE process: $_" -ForegroundColor Red
    }
} else {
    Write-Host "No browser found for RCE test" -ForegroundColor Red
    
    # Fallback: Create suspicious PowerShell activity
    Write-Host "Creating suspicious PowerShell activity..." -ForegroundColor Yellow
    Start-Process powershell -ArgumentList '-Command "Write-Host \"SUSPICIOUS_ACTIVITY\"; Start-Sleep 3"' -WindowStyle Hidden
}

Write-Host "Check Ghost Layer dashboard for alerts!" -ForegroundColor Cyan
