@echo off
REM ==================================================================
REM  NHOM 06 - MO TOAN BO DEMO BANG MOT LAN NHAP DUP
REM  Bien dich -> External Server -> Internal Service -> Gateway
REM  -> Client 127.0.0.11 -> trinh duyet mo web dashboard
REM ==================================================================
cd /d "%~dp0.."
echo Dang bien dich...
call "%~dp0_compile.bat" || (pause & exit /b 1)

start "NHOM06 - EXTERNAL SERVER (Internet)" cmd /k java -cp out nhom06.server.ExternalServer
timeout /t 1 /nobreak >nul
start "NHOM06 - INTERNAL SERVICE (LAN)" cmd /k java -cp out nhom06.internal.InternalService
timeout /t 1 /nobreak >nul
start "NHOM06 - GATEWAY NAT-PAT + FIREWALL" cmd /k java -cp out nhom06.gateway.GatewayServer config/gateway.properties
timeout /t 3 /nobreak >nul
start "NHOM06 - CLIENT 127.0.0.11" cmd /k java -cp out nhom06.client.InternalClient 127.0.0.11
timeout /t 1 /nobreak >nul
start "" http://127.0.0.1:8088

echo.
echo Da mo 4 cua so va web dashboard: http://127.0.0.1:8088
echo Dung tat ca: scripts\stop-all.bat
timeout /t 5 >nul
