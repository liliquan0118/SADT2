CWD=`pwd`
INCL=${CWD}/utils/build_helpers/include.sh
source ${INCL}

PATCH=libressl-3.0.2_sign.patch
BDIR=${BUILD_LIBS}/${LIBRESSL}_lf

echo -e "\t * Building sancov-instrumented LibreSSL"
if [ ! -d ${BDIR} ]; then
    mkdir -p ${BDIR}
fi

LC="-g -O0 "
DF="-DFUZZER_DISABLE_SIGNCHECK"

if ! [ -d ${SRC_LIBS}/${LIBRESSL}  ]; then
    echo -e "\t\t - LibreSSL was not downloaded properly"
    exit 1
fi

pushd ${SRC_LIBS}/${LIBRESSL} >/dev/null
    echo -e "\t\t - Configuring"
    # clean up just in case
    make -j10 clean > /dev/null 2>&1
    make -j10 distclean > /dev/null 2>&1
    # patch away the signature checking if we have not patched already
    ./configure --disable-shared --with-pic --prefix=${BDIR} \
--exec-prefix=${BDIR} CC="../../../../../../my_afl/afl-clang" CFLAGS="$LC $DF"> /dev/null  2>&1
    echo -e "\t\t - Adding dependencies"
    echo -e "\t\t - Compiling"
    make clean
    make -j10 > /dev/null  2>&1
    echo -e "\t\t - Installing"
    make -j10 install > /dev/null 2>&1
    # clean up for next install
    make -j10 clean > /dev/null 2>&1
    make -j10 distclean > /dev/null 2>&1
    ${BDIR}/bin/openssl h 2> /tmp/ttest
    if [ -f ${BDIR}/bin/openssl ] &&
        [ -f ${BDIR}/lib/libssl.a ] ; then
        echo -e "\t\t - Testing install..\033[0;32m OK\n"
    else
        echo -e "\t\t - Testing install..\033[0;31m FAILED\n"
    fi
    echo -en "\e[0m"
popd >/dev/null
