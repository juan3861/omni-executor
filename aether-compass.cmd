@echo off
setlocal
set "TMP=F:\AetherMind_Temp"
set "TEMP=F:\AetherMind_Temp"
set "TMPDIR=F:\AetherMind_Temp"
set "PY_EXE=C:\Users\juanp\AppData\Local\Programs\Python\Python311\python.exe"
if not exist "%PY_EXE%" set "PY_EXE=python"
"%PY_EXE%" "F:\AetherMind_Universal_Agent\tools\project_compass.py" %*
exit /b %ERRORLEVEL%
