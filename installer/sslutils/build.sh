#!/bin/bash

SSLUTILS_CACHE_DIR=$WD/sslutils/staging
# Read the various build scripts

# Windows x64
if [ $PG_ARCH_WINDOWS_X64 = 1 ];
then
    source $WD/sslutils/build-windows-x64.sh
fi

################################################################################
# sslutils : Build preparation
################################################################################

_prep_sslutils() {

    # Per-platform prep
    cd $WD
    if [ ! -e $WD/sslutils/source ]; then
        mkdir -p $WD/sslutils/source
    fi

    if [ -e $WD/sslutils/source/sslutils ]; then
        rm -rf $WD/sslutils/source/sslutils
    fi

    mkdir -p $WD/sslutils/source

    cd $WD/pvt_packages/PEM
    git pull

    cp -r $WD/pvt_packages/sslutils $WD/sslutils/source/sslutils

    # Windows-x64
    if [ $PG_ARCH_WINDOWS_X64 = 1 ];
    then
        _prep_sslutils_windows_x64 
    fi

}

################################################################################
# Build sslutils
################################################################################

_build_sslutils() {

    # Windows-x64
    if [ $PG_ARCH_WINDOWS_X64 = 1 ];
    then
        _build_sslutils_windows_x64 
    fi

}

################################################################################
# Postprocess sslutils
################################################################################
#
# Note that this is the only step run if we're executed with -skipbuild so it must
# be possible to run this against a pre-built tree.
_postprocess_sslutils() {

    cd $WD/sslutils

    # Windows-x64
    if [ $PG_ARCH_WINDOWS_X64 = 1 ];
    then
        _postprocess_sslutils_windows_x64 
    fi

    rm -f ${SSLUTILS_CACHE_DIR}/sslutils-$PG_MAJOR_VERSION.tar.gz
    rm -f ${WD}/tarballs/sslutils-$PG_MAJOR_VERSION.tar.gz

    if [ -d "${SSLUTILS_CACHE_DIR}" ]; then
        cd ${SSLUTILS_CACHE_DIR}
        FILENAME=""
        for filename in `ls ${SSLUTILS_CACHE_DIR}`
        do
            if [[ ! $filename =~ "build" ]]; then
                FILENAME="$FILENAME $filename"
            fi
        done
        tar czf sslutils-$PG_MAJOR_VERSION.tar.gz $FILENAME
        mv sslutils-$PG_MAJOR_VERSION.tar.gz ${WD}/tarballs/
    fi

    cd ${WD}

}

