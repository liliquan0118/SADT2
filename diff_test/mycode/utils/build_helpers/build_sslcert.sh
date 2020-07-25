#!/bin/bash

CWD=`pwd`
INCL=${CWD}/utils/build_helpers/include.sh

echo -e "#!/bin/bash
OPENSSL=openssl
LIBRESSL=libressl
BORINGSSL=boringssl
GNUTLS=gnutls
WOLFSSL=wolfssl
MBEDTLS=mbedtls
NSS=nss

CWD=${CWD}
BUILDS=${CWD}/examples/builds
BUILD_LIBS=${CWD}/examples/builds/libs
BUILD_APPS=${CWD}/examples/builds/apps
SRC_APPS=${CWD}/examples/src/apps
SRC_LIBS=${CWD}/examples/src/libs" > ${INCL}


source ${INCL}

if [ -d examples ] && [ -d utils ]; then
    mkdir -p ${SRC_LIBS} ${BUILD_LIBS} ${SRC_APPS} ${BUILD_APPS}
else
    echo "Please run this from the git root directory!"
    exit 1
fi



source ${CWD}/utils/build_helpers/include.sh

mkdir -p ${BUILDS}
# ignore everything in these directories
echo "*" > ${BUILDS}/.gitignore

echo "[+] Extracting files"
pushd ${SRC_LIBS} >/dev/null
if [ -f  openssl-1.1.1d.tar.gz ]; then
    tar xzf openssl-1.1.1d.tar.gz
    mv  openssl-1.1.1d ${OPENSSL}
fi

if [ -f  gnutls-3.6.11.tar.xz ]; then
    tar xvf gnutls-3.6.11.tar.xz
    mv   gnutls-3.6.11 ${GNUTLS}
fi
if [ -f  mbedtls-2.16.3-apache.tgz ]; then
    tar xvfz mbedtls-2.16.3-apache.tgz
    mv mbedtls-2.16.3  ${MBEDTLS}
fi
if [ -f  wolfssl-4.2.0.zip ]; then
    unzip wolfssl-4.2.0
    mv  wolfssl-4.2.0 ${WOLFSSL}
fi
if [ -f  nss-3.48.tar.gz ]; then
    tar xzf nss-3.48.tar.gz
    mv   nss-3.48 ${NSS}
fi

if [ -f  nspr-4.24.tar.gz ]; then
    tar xzf nspr-4.24.tar.gz
    cp -r nspr-4.24/nspr nss/
fi
if [ -f  libressl-3.0.2.tar.gz ]; then
    tar xzf libressl-3.0.2.tar.gz
    mv  libressl-3.0.2 ${LIBRESSL}
fi
popd >/dev/null

echo "[+] Building Libraries"
# ${CWD}/utils/build_helpers/build_openssl_lf.sh
# # ${CWD}/utils/build_helpers/build_boringssl_lf.sh
# ${CWD}/utils/build_helpers/build_libressl_lf.sh
# ${CWD}/utils/build_helpers/build_gnutls_lf.sh
# ${CWD}/utils/build_helpers/build_wolfssl_lf.sh
${CWD}/utils/build_helpers/build_nss_lf.sh
# ${CWD}/utils/build_helpers/build_mbedtls_lf.sh
