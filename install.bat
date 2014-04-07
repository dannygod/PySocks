@echo off
if not exist %PYTHON_PATH%\python.exe goto AUTO_DETECT_PYTHON
set PYPATH=%PYTHON_PATH%\python.exe
goto COPY_PYTHON

:AUTO_DETECT_PYTHON
if not exist C:\Python27\python.exe goto NOT_FOUND_PYTHON
set PYPATH=C:\Python27\python.exe

:COPY_PYTHON
echo %PYPATH%
copy /Y %PYPATH% /B python27.exe
echo install finish
pause
exit

:NOT_FOUND_PYTHON
echo Cannot find python, please set a PYTHON_PATH env variable
pause
