@echo off
cd /d "%~dp0.."
title GATEWAY NAT-PAT + FIREWALL
java -cp out nhom06.gateway.GatewayServer config/gateway.properties
pause
