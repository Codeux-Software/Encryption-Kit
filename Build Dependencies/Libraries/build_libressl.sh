#!/bin/bash

set -e

pushd "${LIBRARY_WORKING_DIRECTORY_LOCATION}"

curl -LO "http://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-${LIBRARY_LIBRESSL_VERSION}.tar.gz" --retry 5

tar -xvzf "./libressl-${LIBRARY_LIBRESSL_VERSION}.tar.gz"

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

popd
