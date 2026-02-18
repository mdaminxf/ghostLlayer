@echo off
echo ========================================
echo Ghost Layer RCE Detection Test Runner
echo ========================================
echo.

echo Starting Ghost Layer RCE detection tests...
echo Make sure Ghost Layer is running in another terminal!
echo.

pause

echo.
echo Running PowerShell Test Suite...
echo ----------------------------------------
powershell -ExecutionPolicy Bypass -File "rce_test_simulator.ps1"

echo.
echo.
echo Running Python Test Suite...
echo ----------------------------------------
python test_rce_detection.py

echo.
echo.
echo ========================================
echo Tests Complete!
echo ========================================
echo.
echo Check your Ghost Layer dashboard for:
echo   - RCE alerts (Chrome->cmd, Word->PowerShell)
echo   - AI explanations for detected threats
echo   - Process termination logs
echo.
echo Expected: 2 RCE alerts, 1 suspicious process alert
echo Expected: No alerts for normal processes
echo.

pause
