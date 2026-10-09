@echo off
REM Kiem thu tai. Vi du: scripts\loadtest.bat clients=100 messages=50
REM Them --live de ban vao Gateway demo dang chay (xem truc tiep tren web).
cd /d "%~dp0.."
call "%~dp0_compile.bat" || (pause & exit /b 1)
java -cp out nhom06.test.LoadTest %*
pause
