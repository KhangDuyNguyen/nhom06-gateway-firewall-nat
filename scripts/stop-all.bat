@echo off
REM Dung moi chuong trinh Java cua nhom 06 (Gateway, Server, Client...)
powershell -NoProfile -Command "$p = Get-CimInstance Win32_Process | Where-Object { $_.Name -eq 'java.exe' -and $_.CommandLine -like '*nhom06.*' }; if (-not $p) { Write-Host 'Khong co chuong trinh nao dang chay.' } else { $p | ForEach-Object { Stop-Process -Id $_.ProcessId -Force; Write-Host ('Da dung PID ' + $_.ProcessId) } }"
echo Xong. Co the dong cac cua so CMD con lai.
timeout /t 4 >nul 2>&1 || ping -n 5 127.0.0.1 >nul
