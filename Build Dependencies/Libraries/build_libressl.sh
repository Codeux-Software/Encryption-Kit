#!/bin/bash

set -e

pushd "${LIBRARY_WORKING_DIRECTORY_LOCATION}"

curl -LO "http://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-${LIBRARY_LIBRESSL_VERSION}.tar.gz" --retry 5

tar -xvzf "./libressl-${LIBRARY_LIBRESSL_VERSION}.tar.gz"

mv "./libressl-${LIBRARY_LIBRESSL_VERSION}" "./libressl-source"

cd "./libressl-source"

./configure --disable-shared --enable-static --host x86_64-apple-darwin \
--disable-dependency-tracking \
--prefix="${SHARED_RESULT_ROOT_LOCATION}" \
LDFLAGS="${LDFLAGS}" \
CFLAGS="${CFLAGS}" \
CPPLAGS="${CPPFLAGS}"

make
make install

popd
