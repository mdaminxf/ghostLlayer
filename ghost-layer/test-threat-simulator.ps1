# Ghost Layer Threat Simulator
# This script creates harmless test files to trigger the security system

Write-Host "=== Ghost Layer Threat Simulator ===" -ForegroundColor Cyan
Write-Host ""

# Test 1: High Entropy File (simulates encrypted malware)
Write-Host "[TEST 1] Creating high-entropy file (simulates encrypted payload)..." -ForegroundColor Yellow

# Generate random bytes (high entropy like encrypted data)
$randomBytes = New-Object byte[] 1024
$rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::Create()
$rng.GetBytes($randomBytes)

# Save to monitored directory
$highEntropyFile = "C:\Ghost_Secrets\suspicious_encrypted.bin"
[System.IO.File]::WriteAllBytes($highEntropyFile, $randomBytes)

Write-Host "✓ Created: $highEntropyFile" -ForegroundColor Green
Write-Host "  Entropy: ~8.0 (very high - typical of encryption)" -ForegroundColor Gray
Write-Host ""

Start-Sleep -Seconds 2

# Test 2: Suspicious File Name
Write-Host "[TEST 2] Creating file with suspicious name..." -ForegroundColor Yellow

$suspiciousFile = "C:\Ghost_Secrets\mimikatz_dump.txt"
"This is a test file with a suspicious name" | Out-File -FilePath $suspiciousFile -Encoding ASCII

Write-Host "✓ Created: $suspiciousFile" -ForegroundColor Green
Write-Host ""

Start-Sleep -Seconds 2

# Test 3: Base64 Encoded Data (medium-high entropy)
Write-Host "[TEST 3] Creating base64-encoded file (medium-high entropy)..." -ForegroundColor Yellow

$base64Data = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("This is encoded data that looks suspicious" * 50))
$base64File = "C:\Ghost_Secrets\encoded_payload.b64"
$base64Data | Out-File -FilePath $base64File -Encoding ASCII

Write-Host "✓ Created: $base64File" -ForegroundColor Green
Write-Host "  Entropy: ~6.5 (medium-high)" -ForegroundColor Gray
Write-Host ""

Start-Sleep -Seconds 2

# Test 4: Compressed Data (high entropy)
Write-Host "[TEST 4] Creating compressed file (high entropy)..." -ForegroundColor Yellow

$compressedFile = "C:\Ghost_Secrets\packed_malware.dat"
$testData = "A" * 5000  # Repetitive data
$bytes = [System.Text.Encoding]::UTF8.GetBytes($testData)

# Compress using GZip
$memoryStream = New-Object System.IO.MemoryStream
$gzipStream = New-Object System.IO.Compression.GZipStream($memoryStream, [System.IO.Compression.CompressionMode]::Compress)
$gzipStream.Write($bytes, 0, $bytes.Length)
$gzipStream.Close()
$compressedBytes = $memoryStream.ToArray()
$memoryStream.Close()

[System.IO.File]::WriteAllBytes($compressedFile, $compressedBytes)

Write-Host "✓ Created: $compressedFile" -ForegroundColor Green
Write-Host "  Entropy: ~7.8 (high - typical of compression)" -ForegroundColor Gray
Write-Host ""

# Summary
Write-Host "=== Test Complete ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "Check your Ghost Layer dashboard for threat alerts!" -ForegroundColor Green
Write-Host "The Ghost pet should turn red and shake." -ForegroundColor Green
Write-Host ""
Write-Host "Files created in: C:\Ghost_Secrets" -ForegroundColor Gray
Write-Host ""
Write-Host "To clean up, run: Remove-Item C:\Ghost_Secrets\* -Force" -ForegroundColor Gray
