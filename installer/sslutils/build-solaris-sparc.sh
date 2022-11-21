#!/bin/bash

################################################################################
# SQL-Profiler Build preparation
################################################################################

_prep_profiler_solaris_sparc() {

    echo "##################################################"
    echo "# sslutils : SOLARIS-X64 : Build preparation #"
    echo "##################################################"

    SSLU_PACKAGE_PATH=$WD/sslutils
    SSLU_PLATFORM=solaris-sparc
    SSLU_STAGING=$SSLUTILS_CACHE_DIR/$SSLU_PLATFORM/sslutils-$PG_MAJOR_VERSION
    SSLU_SOURCE=$SSLU_PACKAGE_PATH/source
    SSLU_SSH=$PG_SSH_SOLARIS_SPARC
    SSLU_REPO=$PG_PATH_SOLARIS_SPARC

    # Remove any existing source directory that might exists, and create a clean one
    if [ -e $SSLU_SOURCE/sslutils.$SSLU_PLATFORM ]; then
        echo "Removing existing source directory (profiler.$SSLU_PLATFORM/sslutils.$SSLU_PLATFORM)"
        rm -rf $SSLU_SOURCE/sslutils.$SSLU_PLATFORM || _die "Couldn't remove the existing source directory ($SSLU_SOURCE/sslutils.$SSLU_PLATFORM)"
    fi
    cp -r $SSLU_SOURCE/sslutils $SSLU_SOURCE/sslutils.$SSLU_PLATFORM || _die "Couldn't copy the source directory (profiler.$SSLU_PLATFORM)"

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
    ssh $SSLU_SSH "cd $SSLU_REPO; rm -rf sslutils.zip"
    ssh $SSLU_SSH "cd $SSLU_REPO; rm -rf sslutils.$SSLU_PLATFORM"

    cd $SSLU_SOURCE
    echo "Archieving sslutils sources"
    zip -r sslutils-$SSLU_PLATFORM.zip sslutils.$SSLU_PLATFORM || _die "Couldn't create archieve of the sslutils sources (profiler-$SSLU_PLATFORM.zip)"

    # Copy sources on $SSLU_PLATFORM VM/Machine
    echo "Copying pem_agent sources to $SSLU_PLATFORM"
    scp sslutils-$SSLU_PLATFORM.zip $SSLU_SSH:$SSLU_REPO || _die "Couldn't copy the profiler archieve to $SSLU_PLATFORM VM (profiler-$SSLU_PLATFORM.zip)"
    ssh $SSLU_SSH "cd $SSLU_REPO; unzip sslutils-$SSLU_PLATFORM.zip" || _die "Couldn't extract sslutils archieve on $SSLU_PLATFORM VM (profiler-$SSLU_PLATFORM.zip)"

}

################################################################################
# SQL-Profiler Build
################################################################################

_build_profiler_solaris_sparc() {

    echo "#####################################"
    echo "# sslutils : SOLARIS-X64: Build #"
    echo "#####################################"

    SSLU_PACKAGE_PATH=$WD/sslutils
    SSLU_PLATFORM=solaris-sparc
    SSLU_STAGING=$SSLUTILS_CACHE_DIR/$SSLU_PLATFORM/sslutils-$PG_MAJOR_VERSION
    SSLU_SOURCE=$SSLU_PACKAGE_PATH/source/sslutils.$SSLU_PLATFORM
    SSLU_SSH=$PG_SSH_SOLARIS_SPARC
    SSLU_REPO=$PG_PATH_SOLARIS_SPARC
    SSLU_SOURCE_PLAT=$SSLU_REPO/sslutils.$SSLU_PLATFORM
    PG_PATH=$PG_PGHOME_SOLARIS_SPARC

    # Build sslutils
    ssh $SSLU_SSH "source setenv.sh; cd $SSLU_SOURCE_PLAT; gmake USE_PGXS=1 PG_CONFIG=$PG_PATH/bin/pg_config" || _die "Failed to build the sslutils for $SSLU_PLATFORM"
    ssh $SSLU_SSH "source setenv.sh; cd $SSLU_SOURCE_PLAT; chrpath --replace \"\\\$ORIGIN:/usr/sfw/lib/64\" sslutils.so" || _die "Failed to change the rpath for the sslutils for $SSLU_PLATFORM"

    mkdir -p $SSLU_STAGING/lib
    mkdir -p $SSLU_STAGING/share
    mkdir -p $SSLU_STAGING/doc

    echo "Copying libraries from the $SSLU_PLATFORM VM to staging directory"
    scp $SSLU_SSH:$SSLU_SOURCE_PLAT/sslutils.so $SSLU_STAGING/lib/sslutils.so || _die "Failed to copy sslutils.so"
    scp $SSLU_SSH:$SSLU_SOURCE_PLAT/*.sql $SSLU_STAGING/share/ || _die "Failed to copy sqls"
    scp $SSLU_SSH:$SSLU_SOURCE_PLAT/sslutils.control $SSLU_STAGING/share/sslutils.control || _die "Failed to copy sslutils.control"
    scp $SSLU_SSH:$SSLU_SOURCE_PLAT/README.sslutils $SSLU_STAGING/doc/README.sslutils || _die "Failed to copy README.sslutils"

    cd $WD
}

################################################################################
# SQL-Profiler : Post Process
################################################################################

_postprocess_profiler_solaris_sparc() {

    echo "#############################################"
    echo "# sslutils : SOLARIS-X64 : Post Process #"
    echo "#############################################"

    SSLU_PLATFORM=solaris-sparc
    SSLU_PACKAGE_PATH=$SSLUTILS_CACHE_DIR/$SSLU_PLATFORM/sslutils-$PG_MAJOR_VERSION
    # SSLU_BUILD_PLATFORM=solaris-sparc

    cd $SSLU_PACKAGE_PATH

    # Make all the files readable under the given directory
    find "$SSLU_PACKAGE_PATH" -exec chmod a+r {} \;
    # Make all the directories readable, writable and executable under the given directory
    find "$SSLU_PACKAGE_PATH" -type d -exec chmod 755 {} \;
    # Make all the shared objects readable and executable under the given directory
    find "$SSLU_PACKAGE_PATH" -name "*.so" -exec chmod a+rx {} \;

    cd $WD

}

