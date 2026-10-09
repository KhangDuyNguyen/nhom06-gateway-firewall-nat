@echo off
REM Chay bo tu kiem thu: 17 kich ban, in PASS/FAIL, luu logs\selftest-report.txt
cd /d "%~dp0.."
call "%~dp0_compile.bat" || (pause & exit /b 1)
java -cp out nhom06.test.SelfTest
pause
