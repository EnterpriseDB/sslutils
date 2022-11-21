#!/bin/bash

################################################################################
# sslutils Build preparation
################################################################################

_prep_sslutils_osx() {

    echo "#######################################"
    echo "# sslutils : OSX : Build preparation #"
    echo "#######################################"

    SSLU_PACKAGE_PATH=$WD/sslutils
    SSLU_PLATFORM=osx
    SSLU_STAGING=$SSLUTILS_CACHE_DIR/${SSLU_PLATFORM}.build/sslutils-$PG_MAJOR_VERSION
    SSLU_SOURCE=$SSLU_PACKAGE_PATH/source

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

}

################################################################################
# sslutils Build
################################################################################

_build_sslutils_osx() {

    echo "##############################"
    echo "# sslutils : OSX : Build #"
    echo "##############################"

    SSLU_PACKAGE_PATH=$WD/sslutils
    SSLU_PLATFORM=osx
    SSLU_STAGING=$SSLUTILS_CACHE_DIR/${SSLU_PLATFORM}.build/sslutils-$PG_MAJOR_VERSION
    SSLU_SOURCE=$SSLU_PACKAGE_PATH/source/sslutils.$SSLU_PLATFORM
    PG_PATH=$WD/server/staging/$SSLU_PLATFORM/sslutils-$PG_MAJOR_VERSION

    cd $SSLU_SOURCE
    PATH=$PG_PATH/bin:$PATH make USE_PGXS=1 || _die "Failed to build the sslutils for $SSLU_PLATFORM"

    # Copying the binaries
    mkdir -p $SSLU_STAGING/lib || _die "Failed to create lib directory"
    mkdir -p $SSLU_STAGING/share || _die "Failed to create share directory"
    mkdir -p $SSLU_STAGING/doc || _die "Failed to create doc directory"

    cp -R $SSLU_SOURCE/sslutils.so $SSLU_STAGING/lib || _die "Failed to copy the sslutils binary"
    cp -R $SSLU_SOURCE/*.sql $SSLU_STAGING/share || _die "Failed to copy the share files for the sslutils"
    cp -R $SSLU_SOURCE/sslutils.control $SSLU_STAGING/share || _die "Failed to copy the share files for the sslutils"
    cp -R $SSLU_SOURCE/README.sslutils $SSLU_STAGING/doc || _die "Failed to copy README.sslutils"

    chmod a+rx $SSLU_STAGING/lib/* || _die "Failed to set permissions"
    chmod a+r $SSLU_STAGING/share/* || _die "Failed to set permissions"
    chmod a+r $SSLU_STAGING/doc/* || _die "Failed to set permissions"

    echo "Removing last successful staging directory ($SSLUTILS_CACHE_DIR/$SSLU_PLATFORM)"
    rm -rf $SSLUTILS_CACHE_DIR/$SSLU_PLATFORM || _die "Couldn't remove the last successful staging directory"
    mkdir -p $SSLUTILS_CACHE_DIR/$SSLU_PLATFORM || _die "Couldn't create the last successful staging directory"
    chmod ugo+w $SSLUTILS_CACHE_DIR/$SSLU_PLATFORM || _die "Couldn't set the permissions on the successful staging directory"

    echo "Copying the complete build to the successful staging directory"
    cp -rp $SSLUTILS_CACHE_DIR/${SSLU_PLATFORM}.build/* $SSLUTILS_CACHE_DIR/$SSLU_PLATFORM || _die "Couldn't copy the existing staging directory"

}


################################################################################
# sslutils Post Process
################################################################################

_postprocess_sslutils_osx() {

    echo "#####################################"
    echo "# sslutils : OSX : Post Process #"
    echo "#####################################"

    SSLU_PACKAGE_PATH=$WD/sslutils
    SSLU_PLATFORM=osx
    SSLU_STAGING=$SSLUTILS_CACHE_DIR/$SSLU_PLATFORM/sslutils-$PG_MAJOR_VERSION

    cd $SSLU_PACKAGE_PATH

    # Make all the files readable under the given directory
    find "$SSLU_PACKAGE_PATH" -exec chmod a+r {} \;
    # Make all the directories readable, writable and executable under the given directory
    find "$SSLU_PACKAGE_PATH" -type d -exec chmod 755 {} \;
    # Make all the shared objects readable and executable under the given directory
    find "$SSLU_PACKAGE_PATH" -name "*.dylib" -exec chmod a+rx {} \;

    cd $WD

}

