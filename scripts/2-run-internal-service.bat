@echo off
cd /d "%~dp0.."
title INTERNAL SERVICE (LAN)
java -cp out nhom06.internal.InternalService 127.0.0.20 7000
pause
