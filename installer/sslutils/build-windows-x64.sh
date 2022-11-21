#!/bin/bash

################################################################################
# sslutils Build preparation
################################################################################

_prep_sslutils_windows_x64() {

    echo "##############################################"
    echo "# sslutils : WIN-X64 : Build preparation #"
    echo "##############################################"

    SSLU_PACKAGE_PATH=$WD/sslutils
    SSLU_PLATFORM=windows-x64
    SSLU_STAGING=$SSLUTILS_CACHE_DIR/${SSLU_PLATFORM}.build/sslutils-$PG_MAJOR_VERSION
    SSLU_SOURCE=$SSLU_PACKAGE_PATH/source
    SSLU_SSH=$PG_SSH_WINDOWS_X64
    SSLU_REPO=$PG_PATH_WINDOWS_X64

    # Remove any existing source directory that might exists, and create a clean one
    if [ -e $SSLU_SOURCE/sslutils.$SSLU_PLATFORM ]; then
        echo "Removing existing source directory (sslutils.$SSLU_PLATFORM/sslutils.$SSLU_PLATFORM)"
        rm -rf $SSLU_SOURCE/sslutils.$SSLU_PLATFORM || _die "Couldn't remove the existing source directory ($SSLU_SOURCE/sslutils.$SSLU_PLATFORM)"
    fi
    cp -r $SSLU_SOURCE/sslutils $SSLU_SOURCE/sslutils.$SSLU_PLATFORM || _die "Couldn't copy the source directory (sslutils.$SSLU_PLATFORM)"

    # Remove any existing staging directory that might exist, and create a clean one
    if [ -e $SSLU_STAGING ];
    then
        echo "Removing existing staging directory"
        rm -rf $SSLU_STAGING || _die "Couldn't remove the existing staging directory ($SSLU_STAGING)"
    fi

    echo "Creating staging directory ($SSLU_STAGING)"
    mkdir -p $SSLU_STAGING || _die "Couldn't create the staging directory"
    chmod 755 $SSLU_STAGING || _die "Couldn't set the permissions on the staging directory"

    if [ -f $SSLU_PACKAGE_PATH/source/sslutils-$SSLU_PLATFORM.zip ];
    then
        echo "Removing existing sslutils archive"
        rm -rf $SSLU_PACKAGE_PATH/source/sslutils-$SSLU_PLATFORM.zip || _die "Couldn't remove the existing sslutils archive"
    fi

    if [ -f $SSLU_STAGING/sslutils-output-$SSLU_PLATFORM.zip ];
    then
        echo "Removing existing output archive"
        rm -rf $SSLU_STAGING/sslutils-output-$SSLU_PLATFORM.zip || _die "Couldn't remove the existing output archive"
    fi

    # Cleanup the build host
    ssh $SSLU_SSH "cd $SSLU_REPO; cmd /c del /F /Q sslutils.zip"
    ssh $SSLU_SSH "cd $SSLU_REPO; cmd /c del /F /Q vc-build-sslutils-x64.bat"
    ssh $SSLU_SSH "cd $SSLU_REPO; cmd /c rd /S /Q sslutils.$SSLU_PLATFORM"

    cd $SSLU_SOURCE
    echo "Archieving sslutils sources"
    zip -r sslutils-$SSLU_PLATFORM.zip sslutils.$SSLU_PLATFORM || _die "Couldn't create archieve of the sslutils sources (sslutils-$SSLU_PLATFORM.zip)"

    # Cleanup local files
    if [ -f $SSLU_PACKAGE_PATH/scripts/$SSLU_PLATFORM/vc-build-sslutils-x64.bat ];
    then
        echo "Removing existing vc-build-sslutils-x64 script"
        rm -rf $SSLU_PACKAGE_PATH/scripts/$SSLU_PLATFORM/vc-build-sslutils-x64.bat || _die "Couldn't remove the existing vc-build-sslutils script"
    fi
    mkdir -p $SSLU_PACKAGE_PATH/scripts/$SSLU_PLATFORM

    # Copy sources on windows VM
    echo "Copying pem_agent sources to Windows VM"
    rsync -av sslutils-$SSLU_PLATFORM.zip $SSLU_SSH:$PG_CYGWIN_PATH_WINDOWS_X64 || _die "Couldn't copy the sslutils archieve to windows-x64 VM (sslutils-$SSLU_PLATFORM.zip)"
    ssh $SSLU_SSH "cd $SSLU_REPO; cmd /c unzip sslutils-$SSLU_PLATFORM.zip" || _die "Couldn't extract sslutils archieve on windows-x64 VM (sslutils-$SSLU_PLATFORM.zip)"

}

################################################################################
# sslutils Build
################################################################################

_build_sslutils_windows_x64() {

    echo "##################################"
    echo "# sslutils : WIN-X64 : Build #"
    echo "##################################"

    SSLU_PACKAGE_PATH=$WD/sslutils
    SSLU_PLATFORM=windows-x64
    SSLU_STAGING=$SSLUTILS_CACHE_DIR/${SSLU_PLATFORM}.build/sslutils-$PG_MAJOR_VERSION
    SSLU_SOURCE=$SSLU_PACKAGE_PATH/source/sslutils.$SSLU_PLATFORM
    SSLU_SSH=$PG_SSH_WINDOWS_X64
    SSLU_REPO=$PG_PATH_WINDOWS_X64
    SSLU_SOURCE_PLAT=$SSLU_REPO\\\\sslutils.$SSLU_PLATFORM

    if [ "${PG_MAJOR_VERSION}" = "9.0" -o "${PG_MAJOR_VERSION}" = "9.1" ]; then
        OPENSSLPATH="%PGBUILD%\\OpenSSL"
        GETTEXTPATH="%PGBUILD%\\gettext"
    else
        OPENSSLPATH=$PG_PGBUILD_OPENSSL_WINDOWS_X64
        GETTEXTPATH="%PGBUILD%"
    fi

    mkdir -p $SSLU_PACKAGE_PATH/scripts/$SSLU_PLATFORM

    if [ ${PG_MAJOR_VERSION} -lt 11 ]; then
        VC_ENV_CMD="$PG_VSINSTALLDIR_WINDOWS_X64\VC\vcvarsall.bat"
    else
        VC_ENV_CMD="$PG_VSINSTALLDIR_WINDOWS_X64\Professional\VC\Auxiliary\Build\vcvarsall.bat"
    fi


    cat <<EOT > "vc-build-sslutils-x64.bat"
REM Setting Visual Studio Environment
CALL  "${VC_ENV_CMD}" amd64

@SET PGBUILD=$PG_PGBUILD_WINDOWS_X64
@SET PGPATH=$PG_PATH_WINDOWS_X64\output
@SET OPENSSLPATH=$OPENSSLPATH
@SET GETTEXTPATH=$GETTEXTPATH
@SET USE_PGXS=1
@SET ARCH=x64

@vcbuid 2>null || goto use_msbuild

@vcbuild sslutils.proj RELEASE || exit 1
goto end

:use_msbuild
msbuild %1 /p:Configuration=Release || exit 1

:end

EOT

    # Zip up the scripts directories and copy them to the build host, then unzip
    echo "Copying scripts source tree to Windows build VM"
    scp vc-build-sslutils-x64.bat $SSLU_SSH:$SSLU_SOURCE_PLAT || _die "Failed to copy the vc-build-sslutils-x64.bat  to the windows-x64 build host"
    ssh $SSLU_SSH "cd $SSLU_SOURCE_PLAT; cmd /c vc-build-sslutils-x64.bat" || _die "Failed to build sslutils on the build host"

    mkdir -p $SSLU_STAGING/lib
    mkdir -p $SSLU_STAGING/share
    mkdir -p $SSLU_STAGING/doc

    echo "Copying libraries from the windows-x64 VM to staging directory"
    scp $SSLU_SSH:$SSLU_SOURCE_PLAT\\\\sslutils.dll $SSLU_STAGING/lib/sslutils.dll || _die "Failed to copy sslutils.dll"
    scp $SSLU_SSH:$SSLU_SOURCE_PLAT\\\\/*.sql $SSLU_STAGING/share/ || _die "Failed to copy sslutils*sql file"
    scp $SSLU_SSH:$SSLU_SOURCE_PLAT\\\\sslutils.control $SSLU_STAGING/share/sslutils.control || _die "Failed to copy sslutils.control"
    scp $SSLU_SSH:$SSLU_SOURCE_PLAT\\\\README.sslutils $SSLU_STAGING/doc/README.sslutils || _die "Failed to copy README.sslutils"

    echo "Removing last successful staging directory ($SSLUTILS_CACHE_DIR/$SSLU_PLATFORM)"
    rm -rf $SSLUTILS_CACHE_DIR/$SSLU_PLATFORM || _die "Couldn't remove the last successful staging directory"
    mkdir -p $SSLUTILS_CACHE_DIR/$SSLU_PLATFORM || _die "Couldn't create the last successful staging directory"
    chmod ugo+w $SSLUTILS_CACHE_DIR/$SSLU_PLATFORM || _die "Couldn't set the permissions on the successful staging directory"

    echo "Copying the complete build to the successful staging directory"
    cp -rp $SSLUTILS_CACHE_DIR/${SSLU_PLATFORM}.build/* $SSLUTILS_CACHE_DIR/$SSLU_PLATFORM || _die "Couldn't copy the existing staging directory"

    cd $WD
}

################################################################################
# sslutils : Post Process
################################################################################

_postprocess_sslutils_windows_x64() {

    echo "#########################################"
    echo "# sslutils : WIN-X64 : Post Process #"
    echo "#########################################"

    SSLU_PLATFORM=windows-x64
    SSLU_PACKAGE_PATH=$SSLUTILS_CACHE_DIR/$SSLU_PLATFORM/sslutils-$PG_MAJOR_VERSION
    # SSLU_BUILD_PLATFORM=windows

    cd $SSLU_PACKAGE_PATH

    # Make all the files readable under the given directory
    find "$SSLU_PACKAGE_PATH" -exec chmod a+r {} \;
    # Make all the directories readable, writable and executable under the given directory
    find "$SSLU_PACKAGE_PATH" -type d -exec chmod 755 {} \;
    # Make all the shared objects readable and executable under the given directory
    find "$SSLU_PACKAGE_PATH" -name "*.dll" -exec chmod a+rx {} \;

    cd $WD

}

