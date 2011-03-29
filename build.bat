@echo on

SET PPSP_BUILD_ERROR=

REM ----- Visual Studio Environment Check
vcbuild /? > nul 2>&1

IF NOT "%ERRORLEVEL%" == "0" SET PPSP_BUILD_ERROR=Please set the environments properly for the Visual Studio && GOTO error

REM ------ PostgreSQL/AS PATH Check
IF "%PGPATH%" == "" SET PPSP_BUILD_ERROR=Set the 'PGPATH' environment variable. && GOTO error

IF "%USE_PGXS%" == "1" GOTO use-pgxs
GOTO build

:use-pgxs
 IF NOT EXIST "%PGPATH%\bin\pg_config.exe" SET PPSP_BUILD_ERROR=Not a valid PostgreSQL/Advanced Server Path. Couldn't find '%PGPATH%\bin\pg_config.exe'. && GOTO error
 IF "%PGSHAREPATH%" == "" SET PGSHAREPATH=%PGPATH%\share
 IF "%PGLIBPATH%" == "" SET PGLIBPATH=%PGPATH%\lib
 GOTO build


:build
echo %PGSHAREPATH%
echo %PGLIBPATH%
 vcbuild sslutils.proj %*
 IF NOT "%ERRORLEVEL%" == "0" SET PPSP_BUILD_ERROR="Failed to build sslutils" && GOTO error
 IF NOT EXIST "sslutils.dll" SET PPSP_BUILD_ERROR="Failed to generate the sslutils.dll" && GOTO error
 IF NOT EXIST "sslutils.sql" SET PPSP_BUILD_ERROR="Failed to generate the sslutils.sql" && GOTO error
 IF NOT EXIST "uninstall_sslutils.sql" SET PPSP_BUILD_ERROR="Failed to generate the uninstall_sslutils.sql" && GOTO error

 echo "Successfully Build sslutils"
 GOTO end

:error
 echo ERROR: %PPSP_BUILD_ERROR% 1>&2
 IF NOT "%INTERACTIVE%" == "0" GOTO end
 exit 1

:end

