@echo off
REM Bien dich toan bo du an (Windows)
cd /d "%~dp0.."
if not exist out mkdir out
if not exist logs mkdir logs
dir /s /b src\*.java > sources.txt
javac -encoding UTF-8 -d out @sources.txt
if errorlevel 1 (echo LOI BIEN DICH & del sources.txt & pause & exit /b 1)
del sources.txt
echo Bien dich thanh cong. Xem thu muc out
pause
