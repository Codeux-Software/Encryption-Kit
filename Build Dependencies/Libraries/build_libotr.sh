#!/bin/bash

set -e

pushd "${LIBRARY_WORKING_DIRECTORY_LOCATION}"

curl -LO "https://otr.cypherpunks.ca/libotr-${LIBRARY_OTR_VERSION}.tar.gz" --retry 5

tar -xvzf "./libotr-${LIBRARY_OTR_VERSION}.tar.gz"

mv "./libotr-${LIBRARY_OTR_VERSION}" "./libotr-source"

cd "./libotr-source"

./configure --disable-shared --enable-static --host x86_64-apple-darwin \
--prefix="${SHARED_RESULT_ROOT_LOCATION}" \
--with-libgcrypt-prefix="${SHARED_RESULT_ROOT_LOCATION}" \
LDFLAGS="${LDFLAGS}" \
CFLAGS="${CFLAGS}" \
CPPLAGS="${CPPFLAGS}"

make
make install

popd
