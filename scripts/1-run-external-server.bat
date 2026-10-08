@echo off
cd /d "%~dp0.."
title EXTERNAL SERVER (Internet)
java -cp out nhom06.server.ExternalServer 127.0.0.3 9000 9001
pause
