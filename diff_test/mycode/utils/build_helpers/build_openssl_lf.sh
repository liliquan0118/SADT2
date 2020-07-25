CWD=`pwd`
INCL=${CWD}/utils/build_helpers/include.sh
source ${INCL}
# PATCH=openssl-1.1.1d_sign.patch
BDIR=${BUILD_LIBS}/${OPENSSL}_lf
echo -e "\t * Building sancov-instrumented OpenSSL"
if [ ! -d ${BDIR} ]; then
    mkdir -p ${BDIR}
fi
CF="-g -O0"
DF="-DFUZZER_DISABLE_SIGNCHECK"
pushd ${SRC_LIBS}/${OPENSSL} >/dev/null
    echo -e "\t\t - Configuring"
    # patch away the signature checking if we have not patched already
    CC="../../../../../../my_afl/afl-clang $CF $DF" CXX="../../../../../../my_afl/afl-clang++ $CF $DF" CFLAGS="-g -O0" CXXFLAGS="-g -O0" ./config no-shared -fPIC --prefix=${BDIR} \
        --openssldir=${BDIR}/openssl > /dev/null 2>&1
    echo -e "\t\t - Adding dependencies"
    # there is an issue with multiple builds in openssl
    make clean > /dev/null 2>&1
    make depend > /dev/null 2>&1
    echo -e "\t\t - Compiling"
    make > /dev/null  2>&1
    echo -e "\t\t - Installing"
    make install > /dev/null 2>&1
    ${BDIR}/bin/openssl test 2> /tmp/.opensslvtest
    if [ -f ${BDIR}/bin/openssl ] &&
        [ -f ${BDIR}/lib/libssl.a ]
         then
        echo -e "\t\t - Testing install..\033[0;32m OK\n"
    else
        echo -e "\t\t - Testing install..\033[0;31m FAILED\n"
    fi
    echo -en "\e[0m"
popd >/dev/null
