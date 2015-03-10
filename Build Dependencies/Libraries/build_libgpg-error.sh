#!/bin/bash

set -e

pushd "${LIBRARY_WORKING_DIRECTORY_LOCATION}"

curl -LO "ftp://ftp.gnupg.org/gcrypt/libgpg-error/libgpg-error-${LIBRARY_GPG_ERROR_VERSION}.tar.bz2" --retry 5

tar -xvzf "./libgpg-error-${LIBRARY_GPG_ERROR_VERSION}.tar.bz2"

mv "./libgpg-error-${LIBRARY_GPG_ERROR_VERSION}" "./libgpg-error-source"

cd "./libgpg-error-source"

./configure --disable-shared --enable-static --enable-threads=posix --host x86_64-apple-darwin \
--prefix="${SHARED_RESULT_ROOT_LOCATION}" \
--with-sysroot="${PLATFORM_BUILD_SDK_ROOT_LOCATION}" \
LDFLAGS="${LDFLAGS}" \
CFLAGS="${CFLAGS}" \
CPPLAGS="${CPPFLAGS}"

make
make install

popd
