#!/bin/bash
CWD=`pwd`
INCL=${CWD}/utils/build_helpers/include.sh
source ${INCL}
PATCH=gnutls-3.6.11_sign.patch
BDIR=${BUILD_LIBS}/${GNUTLS}_lf

echo -e "\t * Building sancov-instrumented GNUTLS"
if [ ! -d ${BDIR} ]; then
    mkdir -p ${BDIR}
fi

CF="-g -O0"
DF="-DFUZZER_DISABLE_SIGNCHECK"

pushd ${SRC_LIBS}/${GNUTLS} >/dev/null
    echo -e "\t\t - Configuring"
    # clean up just in case
    # patch away the signature checking if we have not patched already
    CC="../../../../../../my_afl/afl-clang"  CXX="../../../../../../my_afl/afl-clang++"  CFLAGS="$CF $DF "   CXXFLAGS="$CF $DF"  ./configure   --prefix=${BDIR}  --exec-prefix=${BDIR}  --disable-doc --enable-ssl3-supporit --disable-guile --enable-sha1-support
    echo -e "\t\t - Adding dependencies"
    # there is an issue with multiple builds in openssl
    # make depend > /dev/null 2>&1
    make clean
    echo -e "\t\t - Compiling"
    # make > /dev/null  2>&1
    make 
    echo -e "\t\t - Installing"
    make install 
    # make install > /dev/null 2>&1
    ${BDIR}/bin/certtool test 2> /tmp/.gnutlsvtest
    echo $test
    if [ -f ${BDIR}/bin/certtool ] &&
        [ -f ${BDIR}/lib/libgnutls.so ] ; then
        echo -e "\t\t - Testing install..\033[0;32m OK\n"
    else
        echo -e "\t\t - Testing install..\033[0;31m FAILED\n"
    fi
    echo -en "\e[0m"
popd >/dev/null
