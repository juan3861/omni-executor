@echo off
setlocal
set "TMP=F:\AetherMind_Temp"
set "TEMP=F:\AetherMind_Temp"
set "TMPDIR=F:\AetherMind_Temp"
set "PYTHONUTF8=1"
if not exist "F:\AetherMind_Temp" mkdir "F:\AetherMind_Temp"
"C:\Users\juanp\AppData\Local\Programs\Python\Python311\python.exe" "F:\AetherMind_Universal_Agent\src\am_ua\cli.py" %*
exit /b %ERRORLEVEL%
