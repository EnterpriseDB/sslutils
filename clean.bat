@echo off

SET PPSP_BUILD_ERROR=

vcbuild /? > nul 2>&1

IF NOT "%ERRORLEVEL%" == "0" SET PPSP_BUILD_ERROR="Please set the environments properly for the Visual Studio" && GOTO error

vcbuild sslutils.proj /clean
GOTO end

:error
 echo ERROR: %PPSP_BUILD_ERROR% 1>&2

:end

