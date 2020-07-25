#!/bin/bash
CWD=`pwd`
INCL=${CWD}/utils/build_helpers/include.sh
source ${INCL}

PATCH=wolfssl-4.2.0_sign.patch
BDIR=${BUILD_LIBS}/${WOLFSSL}_lf

echo -e "\t * Building sancov-instrumented WOLFSSL"
if [ ! -d ${BDIR} ]; then
    mkdir -p ${BDIR}
fi

CF="-g -O0"
DF="-DFUZZER_DISABLE_SIGNCHECK"

pushd ${SRC_LIBS}/${WOLFSSL} >/dev/null
    echo -e "\t\t - Configuring"
    CC="../../../../../../my_afl/afl-clang"  CXX="../../../../../../my_afl/afl-clang++" CFLAGS="$CF $DF " CXXFLAGS="$CF $DF" ./configure --prefix=${BDIR} 
    make clean
    echo -e "\t\t - Compiling"
    # make > /dev/null  2>&1
    make
    echo -e "\t\t - Installing"
    make install
    # make install > /dev/null 2>&1
    ${BDIR}/bin/wolfssl-config test 2> /tmp/.wolfsslvtest
    if [ -f ${BDIR}/bin/wolfssl-config ] &&
        [ -f ${BDIR}/lib/libwolfssl.so ] ; then
        echo -e "\t\t - Testing install..\033[0;32m OK\n"
    else
        echo -e "\t\t - Testing install..\033[0;31m FAILED\n"
    fi
    echo -en "\e[0m"
popd >/dev/null
