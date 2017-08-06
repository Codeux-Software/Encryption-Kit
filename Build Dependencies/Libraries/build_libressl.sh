#!/bin/bash

set -e

pushd "${LIBRARY_WORKING_DIRECTORY_LOCATION}"

curl -LO "http://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-${LIBRARY_LIBRESSL_VERSION}.tar.gz" --retry 5

tar -xvf "./libressl-${LIBRARY_LIBRESSL_VERSION}.tar.gz"

mv "./libressl-${LIBRARY_LIBRESSL_VERSION}" "./libressl-source"

cd "./libressl-source"

./configure \
--enable-static \
--disable-dependency-tracking \
--disable-silent-rules \
--disable-shared \
--prefix="${SHARED_RESULT_ROOT_LOCATION}"

make
make install

mv "${SHARED_RESULT_LIBRARY_LOCATION}/libcrypto.a" "${SHARED_RESULT_LIBRARY_STATIC_LOCATION}"
mv "${SHARED_RESULT_LIBRARY_LOCATION}/libssl.a" "${SHARED_RESULT_LIBRARY_STATIC_LOCATION}"
mv "${SHARED_RESULT_LIBRARY_LOCATION}/libtls.a" "${SHARED_RESULT_LIBRARY_STATIC_LOCATION}"

popd
