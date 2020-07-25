#!/bin/bash
CWD=`pwd`
INCL=${CWD}/utils/build_helpers/include.sh
source ${INCL}

PATCH=nss-3.48_sign.patch
PATCH2=nss-3.48_build.patch
PATCH3=nss-3.48-standalone-1.patch
BDIR=${BUILD_LIBS}/${NSS}_lf

echo -e "\t * Building sancov-instrumented nss"
if [ ! -d ${BDIR} ]; then
    mkdir -p ${BDIR}
fi

CF="-g -O0  "
# # CF="-g -O0 -fsanitize=address -fsanitize-recover=undefined,integer -fsanitize-coverage=edge,indirect-calls,8bit-counters"
# CF="-g -O0 -fsanitize-coverage=edge,indirect-calls,8bit-counters"
DF="-DFUZZER_DISABLE_SIGNCHECK -DNSS_DISABLE_GTESTS"

pushd ${SRC_LIBS}/${NSS} >/dev/null
    echo -e "\t\t - install nss"
    # cp ../../../../utils/patches/${PATCH} .
    cp ../../../../utils/patches/${PATCH2} .
    cp ../../../../utils/patches/${PATCH3} .
    # patch if we have not patched already
    patch -p1  --silent < ${PATCH2} >/dev/null 2>&1
    patch -Np1  --silent < ${PATCH3} >/dev/null 2>&1
    pushd nss >/dev/null 
    ./build.sh -c --clang
    pushd  ../dist                                                         &&
        rm -r Debug/lib/pkgconfig
        install -v -m755 Debug/lib/*              $BDIR/lib              &&
install -v -m777 -d                           $BDIR/include      &&
cp -v -RL {public,private}/nss              $BDIR/include      &&
cp -v -RL Debug/include/nspr              $BDIR/include      &&
chmod 777                                  $BDIR/include/*    &&

install -v -m755 Debug/bin/* $BDIR/bin &&
    if [ -f ${BDIR}/bin/vfychain ] &&
        [ -f ${BDIR}/lib/libnss3.so ]; then
        echo -e "\t\t - Testing install..\033[0;32m OK\n"
    else
        echo -e "\t\t - Testing install..\033[0;31m FAILED\n"
    fi
    echo -en "\e[0m"
popd >/dev/null
popd >/dev/null
popd >/dev/null
