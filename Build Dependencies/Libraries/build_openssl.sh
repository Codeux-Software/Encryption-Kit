#!/bin/bash

set -e

pushd "${LIBRARY_WORKING_DIRECTORY_LOCATION}"

curl -LO "http://www.openssl.org/source/openssl-${LIBRARY_OPENSSL_VERSION}.tar.gz" --retry 5

tar -xvzf "./openssl-${LIBRARY_OPENSSL_VERSION}.tar.gz"

mv "./openssl-${LIBRARY_OPENSSL_VERSION}" "./openssl-source"

cd "./openssl-source"

./Configure darwin64-x86_64-cc no-ssl2 no-ssl3 no-shared --prefix="${SHARED_RESULT_ROOT_LOCATION}" 

make
make install

popd
