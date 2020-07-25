#!/bin/bash
CWD=`pwd`
INCL=${CWD}/utils/build_helpers/include.sh
source ${INCL}

PATCH=mbedtls_2.16.3_sign.patch
BDIR=${BUILD_LIBS}/${MBEDTLS}_lf

echo -e "\t * Building sancov-instrumented MBEDTLS"
if [ ! -d ${BDIR} ]; then
    mkdir -p ${BDIR}
fi

CF="-g -O0 "
DF="-DFUZZER_DISABLE_SIGNCHECK"

# if ! [ -d ${SRC_LIBS}/${MBEDTLS}  ]; then
    # echo -e "\t\t - Downloading GNUTLS in ${SRC_LIBS}/gnutls"
    # wget -P ${SRC_LIBS} ${MBEDTLS_ST} 2>/dev/null
    # pushd ${SRC_LIBS} >/dev/null
        # if [ -f mbedtls-2.16.1.tar.gz ]; then
            # echo -e "\t\t - Extracting OpenSSL"
            # tar xzf mbedtls-2.16.1.tar.gz
            # mv mbedtls-2.16.1 ${MBEDTLS}
        # fi
    # popd >/dev/null
# fi

pushd ${SRC_LIBS}/${MBEDTLS} >/dev/null
echo -e "\t\t - Configuring"
    find . -iname '*cmake*' -not -name CMakeLists.txt -exec rm -rf {} +
    CC="../../../../../../my_afl/afl-clang"  CXX="../../../../../../my_afl/afl-clang++" CFLAGS="$CF $DF " CXXFLAGS="$CF $DF"  cmake -DUSE_SHARED_MBEDTLS_LIBRARY=On -DFUZZER_DISABLE_SIGNCHECK=1 -DCMAKE_INSTALL_PREFIX=${BDIR} .
    echo -e "\t\t - Compiling"
    make clean > /dev/null  2>&1
    make 
    echo -e "\t\t - Installing"
    make install 
   sudo  ldconfig
    ${BDIR}/bin/cert_app test 2> /tmp/.mbedtlsvtest
    if [ -f ${BDIR}/bin/cert_app ] &&
        [ -f ${BDIR}/lib/libmbedtls.so ] ; then
        echo -e "\t\t - Testing install..\033[0;32m OK\n"
    else
        echo -e "\t\t - Testing install..\033[0;31m FAILED\n"
    fi
    echo -en "\e[0m"
popd >/dev/null
