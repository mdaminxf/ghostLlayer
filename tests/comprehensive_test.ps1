# For testing all the features

param(
    [switch]$Cleanup
)

if ($Cleanup) {
    Write-Host "=== CLEANUP MODE ===" -ForegroundColor Yellow
    
    $tempFiles = @(
        "$env:TEMP\ghost_layer_test_files",
        "$env:TEMP\ransomware_test"
    )
    
    foreach ($file in $tempFiles) {
        if (Test-Path $file) {
            Remove-Item $file -Recurse -Force
            Write-Host "Removed temp: $file" -ForegroundColor Green
        }
    }
    
    Get-Process | Where-Object {$_.ProcessName -match 'powershell|cmd'} | Stop-Process -Force -ErrorAction SilentlyContinue
    Write-Host "All test processes terminated" -ForegroundColor Green
    return
}

Write-Host "========================================" -ForegroundColor Red
Write-Host "COMPREHENSIVE GHOST LAYER TEST" -ForegroundColor Red
Write-Host "========================================" -ForegroundColor Red

# Test 1: RCE Attack - Enhanced to trigger Ghost Layer
Write-Host "`n[TEST 1] RCE EXPLOIT SIMULATION" -ForegroundColor Green

# Find browser process
$browser = Get-Process | Where-Object {$_.ProcessName -match 'chrome|firefox|msedge|brave'} | Select-Object -First 1
if ($browser) {
    Write-Host "Target browser: $($browser.ProcessName) (PID: $($browser.Id))" -ForegroundColor Cyan
    
    # Create PowerShell that simulates being spawned by browser
    $rceScript = @"
        Write-Host "RCE_ATTACK: Browser $($browser.ProcessName) compromised!"
        Write-Host "PARENT_PROCESS: $($browser.ProcessName)"
        Write-Host "CHILD_PROCESS: powershell.exe"
        Write-Host "ATTACK_PATTERN: Browser → Shell (RCE)"
        Start-Sleep 3
    "@
    
    try {
        $rceProcess = Start-Process powershell.exe -ArgumentList "-Command", $rceScript -PassThru -WindowStyle Hidden
        Write-Host "RCE attack launched (PID: $($rceProcess.Id))" -ForegroundColor Red
        
        # Give Ghost Layer time to detect
        Start-Sleep -Seconds 4
        
        # Clean up
        try { $rceProcess.Kill() } catch {}
    } catch {
        Write-Host "Failed to launch RCE process: $_" -ForegroundColor Red
    }
} else {
    Write-Host "No browser found for RCE test" -ForegroundColor Red
}

# Test 2: Ransomware Attack
Write-Host "`n[TEST 2] RANSOMWARE SIMULATION" -ForegroundColor Green

$ransomDir = "$env:TEMP\ransomware_test"
New-Item -ItemType Directory -Path $ransomDir -Force | Out-Null

1..5 | ForEach-Object {
    "Important document content $_" | Out-File "$ransomDir\file$_.txt"
}

Write-Host "Created 5 test files for encryption" -ForegroundColor Cyan

$encryptScript = "Get-ChildItem '$ransomDir\*.txt' | ForEach-Object { (Get-Content `$_.FullName) -replace '[a-zA-Z0-9]', 'X' | Set-Content `$_.FullName }"

$ransomProcess = Start-Process powershell.exe -ArgumentList "-Command", $encryptScript -PassThru -WindowStyle Hidden
Write-Host "Ransomware encryption started (PID: $($ransomProcess.Id))" -ForegroundColor Red

Start-Sleep -Seconds 3
try { $ransomProcess.Kill() } catch {}
Remove-Item $ransomDir -Recurse -Force

# Test 3: Network Attack
Write-Host "`n[TEST 3] SUSPICIOUS NETWORK ACTIVITY" -ForegroundColor Green

$netScript = @"
1..5 | ForEach-Object { 
    Write-Host "C2_CONNECT: 192.168.1.$_':4444"
    Start-Sleep -Milliseconds 500
}
"@

$netProcess = Start-Process powershell.exe -ArgumentList "-Command", $netScript -PassThru -WindowStyle Hidden
Write-Host "Network attack simulation (PID: $($netProcess.Id))" -ForegroundColor Red

Start-Sleep -Seconds 4
try { $netProcess.Kill() } catch {}

# Test 4: Process Injection
Write-Host "`n[TEST 4] PROCESS INJECTION SIMULATION" -ForegroundColor Green

$injectScript = @"
`$targets = Get-Process | Where-Object {`$_.ProcessName -match 'notepad|calc'} | Select-Object -First 3
foreach (`$target in `$targets) {
    Write-Host "INJECT_TARGET: `$(`$target.ProcessName) (PID: `$(`$target.Id))"
}
"@

$injectProcess = Start-Process powershell.exe -ArgumentList "-Command", $injectScript -PassThru -WindowStyle Hidden
Write-Host "Process injection simulation (PID: $($injectProcess.Id))" -ForegroundColor Red

Start-Sleep -Seconds 3
try { $injectProcess.Kill() } catch {}

# Test 5: Persistence Installation
Write-Host "`n[TEST 5] PERSISTENCE MECHANISMS" -ForegroundColor Green

$persistScript = @"
Write-Host "REGISTRY_ADD: HKLM Software Microsoft Windows CurrentVersion Run"
Write-Host "SCHEDULED_TASK: Creating daily maintenance task"
Write-Host "SERVICE_INSTALL: Installing Windows Update Service"
Write-Host "WMI_EVENT: Registering persistent event subscription"
Write-Host "BROWSER_EXT: Installing malicious extension"
"@

$persistProcess = Start-Process powershell.exe -ArgumentList "-Command", $persistScript -PassThru -WindowStyle Hidden
Write-Host "Persistence simulation (PID: $($persistProcess.Id))" -ForegroundColor Red

Start-Sleep -Seconds 4
try { $persistProcess.Kill() } catch {}

Write-Host "`n========================================" -ForegroundColor Red
Write-Host "COMPREHENSIVE TEST COMPLETE" -ForegroundColor Red
Write-Host "========================================" -ForegroundColor Red
Write-Host "Check Ghost Layer dashboard for security alerts!" -ForegroundColor Yellow

Write-Host "`nTESTS EXECUTED:" -ForegroundColor White
Write-Host "- RCE Exploit: Browser to PowerShell spawning" -ForegroundColor Gray
Write-Host "- Ransomware: High entropy file encryption" -ForegroundColor Gray
Write-Host "- Network Attack: Suspicious C2 connections" -ForegroundColor Gray
Write-Host "- Process Injection: Legitimate process hijacking" -ForegroundColor Gray
Write-Host "- Persistence: Registry service installation" -ForegroundColor Gray

Write-Host "`nRun with -Cleanup to remove test artifacts" -ForegroundColor Yellow
