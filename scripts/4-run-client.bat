@echo off
cd /d "%~dp0.."
set IP=%1
if "%IP%"=="" set IP=127.0.0.11
title CLIENT NOI BO %IP%
java -cp out nhom06.client.InternalClient %IP%
pause
