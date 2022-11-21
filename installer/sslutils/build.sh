#!/bin/bash

SSLUTILS_CACHE_DIR=$WD/sslutils/staging
# Read the various build scripts

# Mac OS X
if [ $PG_ARCH_OSX = 1 ];
then
    source $WD/sslutils/build-osx.sh
fi

# Linux
if [ $PG_ARCH_LINUX = 1 ];
then
    source $WD/sslutils/build-linux.sh
fi

# Linux x64
if [ $PG_ARCH_LINUX_X64 = 1 ];
then
    source $WD/sslutils/build-linux-x64.sh
fi

# Windows
if [ $PG_ARCH_WINDOWS = 1 ];
then
    source $WD/sslutils/build-windows.sh
fi

# Windows x64
if [ $PG_ARCH_WINDOWS_X64 = 1 -a $PG_MAJOR_VERSION != "8.4" ];
then
    source $WD/sslutils/build-windows-x64.sh
fi

# Solaris x64
if [ $PG_ARCH_SOLARIS_X64 = 1 -a $PG_MAJOR_VERSION != "8.4" ];
then
    source $WD/sslutils/build-solaris-x64.sh
fi

# Solaris sparc
if [ $PG_ARCH_SOLARIS_SPARC = 1 -a $PG_MAJOR_VERSION != "8.4" ];
then
    source $WD/sslutils/build-solaris-sparc.sh
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

    cp -r $WD/pvt_packages/PEM/plugins/sslutils $WD/sslutils/source/sslutils

    # Mac OS X
    if [ $PG_ARCH_OSX = 1 ];
    then
        #_prep_sslutils_osx 
        echo "Not yet supported (ssutils -  Mac OS X )"
    fi

    # Linux
    if [ $PG_ARCH_LINUX = 1 ];
    then
        _prep_sslutils_linux 
    fi

    # Linux x64
    if [ $PG_ARCH_LINUX_X64 = 1 ];
    then
        _prep_sslutils_linux_x64 
    fi

    # Windows
    if [ $PG_ARCH_WINDOWS = 1 ];
    then
        _prep_sslutils_windows 
    fi

    # Windows-x64
    if [ $PG_ARCH_WINDOWS_X64 = 1 -a $PG_MAJOR_VERSION != "8.4" ];
    then
        _prep_sslutils_windows_x64 
    fi

    # Solaris x64
    if [ $PG_ARCH_SOLARIS_X64 = 1 -a $PG_MAJOR_VERSION != "8.4" ]; then
        #_prep_sslutils_solaris_x64 
        echo "Not yet supported (ssutils - Solaris x64)"
    fi

    # Solaris sparc
    if [ $PG_ARCH_SOLARIS_SPARC = 1 -a $PG_MAJOR_VERSION != "8.4" ]; then
        #_prep_sslutils_solaris_sparc 
        echo "Not yet supported (ssutils - Solaris sparc)"
    fi

}

################################################################################
# Build sslutils
################################################################################

_build_sslutils() {

    # Mac OSX
    if [ $PG_ARCH_OSX = 1 ];
    then
        #_build_sslutils_osx 
        echo "Not yet supported (sslutils - Mac OSX)"
    fi

    # Linux
    if [ $PG_ARCH_LINUX = 1 ];
    then
        _build_sslutils_linux 
    fi

    # Linux x64
    if [ $PG_ARCH_LINUX_X64 = 1 ];
    then
        _build_sslutils_linux_x64 
    fi

    # Windows
    if [ $PG_ARCH_WINDOWS = 1 ];
    then
        _build_sslutils_windows 
    fi

    # Windows-x64
    if [ $PG_ARCH_WINDOWS_X64 = 1 -a $PG_MAJOR_VERSION != "8.4" ];
    then
        _build_sslutils_windows_x64 
    fi

    # Solaris x64
    if [ $PG_ARCH_SOLARIS_X64 = 1 -a $PG_MAJOR_VERSION != "8.4" ]; then
        #_build_sslutils_solaris_x64 
        echo "Not yet supported (ssutils - Solaris x64)"
    fi

    # Solaris sparc
    if [ $PG_ARCH_SOLARIS_SPARC = 1 -a $PG_MAJOR_VERSION != "8.4" ]; then
        #_build_sslutils_solaris_sparc 
        echo "Not yet supported (ssutils - Solaris sparc)"
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

    # Mac OSX
    if [ $PG_ARCH_OSX = 1 ];
    then
        #_postprocess_sslutils_osx 
        echo "Not yet supported (sslutils - Mac OSX)"
    fi

    # Linux
    if [ $PG_ARCH_LINUX = 1 ];
    then
        _postprocess_sslutils_linux 
    fi

    # Linux x64
    if [ $PG_ARCH_LINUX_X64 = 1 ];
    then
        _postprocess_sslutils_linux_x64 
    fi

    # Windows
    if [ $PG_ARCH_WINDOWS = 1 ];
    then
        _postprocess_sslutils_windows 
    fi

    # Windows-x64
    if [ $PG_ARCH_WINDOWS_X64 = 1 -a $PG_MAJOR_VERSION != "8.4" ];
    then
        _postprocess_sslutils_windows_x64 
    fi

    # Solaris x64
    if [ $PG_ARCH_SOLARIS_X64 = 1 -a $PG_MAJOR_VERSION != "8.4" ]; then
        #_postprocess_sslutils_solaris_x64 
        echo "Not yet supported (ssutils - Solaris x64)"
    fi

    # Solaris sparc
    if [ $PG_ARCH_SOLARIS_SPARC = 1 -a $PG_MAJOR_VERSION != "8.4" ]; then
        #_postprocess_sslutils_solaris_sparc 
        echo "Not yet supported (ssutils - Solaris sparc)"
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

