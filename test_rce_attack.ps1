# Simulate RCE Attack - Browser spawning PowerShell
# This should trigger the Ghost Layer RCE detector

Write-Host "🚨 SIMULATING RCE ATTACK" -ForegroundColor Red
Write-Host "Looking for browser processes..." -ForegroundColor Yellow

# Find any running browser
$browsers = @("chrome", "brave", "firefox", "msedge")
$targetBrowser = $null

foreach ($browser in $browsers) {
    $process = Get-Process -Name $browser -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($process) {
        $targetBrowser = $process
        Write-Host "Found browser: $($browser) (PID: $($process.Id))" -ForegroundColor Green
        break
    }
}

if ($targetBrowser) {
    Write-Host "🎯 SIMULATING: Browser spawning PowerShell (RCE Pattern)" -ForegroundColor Red
    Write-Host "Parent: $($targetBrowser.ProcessName) (PID: $($targetBrowser.Id))" -ForegroundColor Yellow
    Write-Host "Child: powershell.exe (will be spawned)" -ForegroundColor Yellow
    
    # This simulates the RCE attack - browser spawning PowerShell
    # In a real attack, this would be malicious code execution
    Start-Process powershell -ArgumentList '-Command "Write-Host \"[MALICIOUS] RCE Payload Executed from Browser PID $($targetBrowser.Id)\"; Start-Sleep 5"' -WindowStyle Hidden
    
    Write-Host "✅ RCE Attack simulation launched!" -ForegroundColor Red
    Write-Host "Check Ghost Layer dashboard for CRITICAL alert!" -ForegroundColor Yellow
} else {
    Write-Host "❌ No browser found. Starting PowerShell directly (may not trigger RCE detection)" -ForegroundColor Yellow
    
    # Fallback - just start PowerShell (shouldn't trigger RCE alert)
    Start-Process powershell -ArgumentList '-Command "Write-Host \"Test Process - No Browser Parent\"; Start-Sleep 3"'
}
