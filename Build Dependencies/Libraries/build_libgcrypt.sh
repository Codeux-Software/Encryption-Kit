#!/bin/bash

set -e

pushd "${LIBRARY_WORKING_DIRECTORY_LOCATION}"

curl -LO "ftp://ftp.gnupg.org/gcrypt/libgcrypt/libgcrypt-${LIBRARY_GCRYPT_VERSION}.tar.bz2"  --retry 5

tar -xvzf "./libgcrypt-${LIBRARY_GCRYPT_VERSION}.tar.bz2"

mv "./libgcrypt-${LIBRARY_GCRYPT_VERSION}" "./libgcrypt-source"

cd "./libgcrypt-source"

./configure --disable-shared --enable-static --enable-threads=posix --host x86_64-apple-darwin \
--prefix="${SHARED_RESULT_ROOT_LOCATION}" \
--with-sysroot="${PLATFORM_BUILD_SDK_ROOT_LOCATION}" \
--with-libgpg-error-prefix="${SHARED_RESULT_ROOT_LOCATION}" \
LDFLAGS="${LDFLAGS}" \
CFLAGS="${CFLAGS}" \
CPPLAGS="${CPPFLAGS}"

make
make install

popd
