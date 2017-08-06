#!/bin/bash

set -e

pushd "${LIBRARY_WORKING_DIRECTORY_LOCATION}"

curl -LO "https://www.gnupg.org/ftp/gcrypt/libgcrypt/libgcrypt-${LIBRARY_GCRYPT_VERSION}.tar.bz2"  --retry 5

tar -xvf "./libgcrypt-${LIBRARY_GCRYPT_VERSION}.tar.bz2"

mv "./libgcrypt-${LIBRARY_GCRYPT_VERSION}" "./libgcrypt-source"

cd "./libgcrypt-source"

./configure \
--enable-static \
--disable-asm \
--disable-dependency-tracking \
--disable-silent-rules \
--prefix="${SHARED_RESULT_ROOT_LOCATION}" \
--with-libgpg-error-prefix="${SHARED_RESULT_ROOT_LOCATION}"

make
make install

mv "${SHARED_RESULT_LIBRARY_LOCATION}/libgcrypt.a" "${SHARED_RESULT_LIBRARY_STATIC_LOCATION}"

popd
