@echo off

call .\setenv.bat

rem opencard.core.*
set CLASSES=%CLASSES%;%OCF_HOME%\lib\base-core.jar

rem opencard.opt.util
set CLASSES=%CLASSES%;%OCF_HOME%\lib\base-opt.jar

rem bouncy castle (crypto provider)
set CLASSES=%CLASSES%;%MISC%\bcprov-jdk15on-150.jar

echo Server Compilation...
echo %SERVER_JAVA_HOME%

%SERVER_JAVA_HOME%\bin\javac.exe --enable-preview --release 17 -classpath %CLASSES% -g -d %OUT% %SRC%\%PROJECT%\%PKGSERVER%\*.java %SRC%\%PROJECT%\%PKGSERVER%\Models\*.java 
if errorlevel 1 goto error
echo %SERVER%.class compiled: OK
echo .



goto end

:error
echo ***************
echo    ERROR !
echo ***************
pause
goto end

:end
cls
