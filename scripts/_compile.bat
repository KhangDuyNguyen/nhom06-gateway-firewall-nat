@echo off
REM Bien dich toan bo ma nguon (duoc cac script khac goi, khong dung lai)
cd /d "%~dp0.."
if not exist out mkdir out
if not exist logs mkdir logs
dir /s /b src\*.java > sources.txt
javac -encoding UTF-8 -d out @sources.txt
set ERR=%errorlevel%
del sources.txt
if not "%ERR%"=="0" (
  echo.
  echo LOI BIEN DICH - xem thong bao phia tren.
  exit /b 1
)
exit /b 0
