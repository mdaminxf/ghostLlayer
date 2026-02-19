# Force RCE Detection Test
# This will directly create the browser->PowerShell pattern

Write-Host "🔥 FORCING RCE DETECTION TEST" -ForegroundColor Red
Write-Host "Creating browser->PowerShell spawn pattern..." -ForegroundColor Yellow

# Get Brave process
$brave = Get-Process -Name "brave" -ErrorAction SilentlyContinue | Select-Object -First 1

if ($brave) {
    Write-Host "Target Brave PID: $($brave.Id)" -ForegroundColor Green
    
    # Force spawn PowerShell with explicit parent process
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "powershell.exe"
    $psi.Arguments = "-Command Write-Host 'RCE ATTACK FROM BRAVE PID $($brave.Id)'; Start-Sleep 10"
    $psi.WindowStyle = "Hidden"
    
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $psi
    $process.Start()
    
    Write-Host "✅ PowerShell spawned from Brave context!" -ForegroundColor Red
    Write-Host "New PowerShell PID: $($process.Id)" -ForegroundColor Yellow
    Write-Host "CHECK DASHBOARD NOW!" -ForegroundColor Red
    
} else {
    Write-Host "❌ Brave not found" -ForegroundColor Red
}
