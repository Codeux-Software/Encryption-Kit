#!/bin/bash

export PLATFORM_BUILD_SDK_VERSION="macosx10.10"

export LIBRARY_OPENSSL_VERSION="1.0.2"
export LIBRARY_GPG_ERROR_VERSION="1.18"
export LIBRARY_GCRYPT_VERSION="1.6.3"
export LIBRARY_OTR_VERSION="4.1.0"

export LIBRARIES_TO_BUILD=()

LIBRARIES_TO_BUILD+=("openssl")
LIBRARIES_TO_BUILD+=("libgpg-error")
LIBRARIES_TO_BUILD+=("libgcrypt")
LIBRARIES_TO_BUILD+=("libotr")

export ROOT_DIRECTORY="/private/tmp/com.codeux.frameworks.encryptionKit/"

export SHARED_RESULT_ROOT_LOCATION="${ROOT_DIRECTORY}Library-Build-Results/"
export SHARED_RESULT_BINARY_LOCATION="${ROOT_DIRECTORY}Library-Build-Results/bin"
export SHARED_RESULT_LIBRARY_LOCATION="${ROOT_DIRECTORY}Library-Build-Results/lib"
export SHARED_RESULT_INCLUDE_LOCATION="${ROOT_DIRECTORY}Library-Build-Results/include"

export WORKING_DIRECTORY="${ROOT_DIRECTORY}Library-Build-Source/"

export PATH="${PATH}:${SHARED_RESULT_BINARY_LOCATION}"

export PLATFORM_BUILD_SDK_ROOT_LOCATION=$(xcrun -sdk ${PLATFORM_BUILD_SDK_VERSION} --show-sdk-path)

export LDFLAGS="-L${SHARED_RESULT_LIBRARY_LOCATION}"
export CFLAGS=" -arch x86_64 -isysroot ${PLATFORM_BUILD_SDK_ROOT_LOCATION} -I${SHARED_RESULT_INCLUDE_LOCATION}"
export CPPFLAGS=" -arch x86_64 -isysroot ${PLATFORM_BUILD_SDK_ROOT_LOCATION} -I${SHARED_RESULT_INCLUDE_LOCATION}"

function deleteOldAndCreateDirectory {
	if [ -d "$1" ]; then
		rm -rf "$1"
	fi

	mkdir -p "$1"
}

deleteOldAndCreateDirectory "${WORKING_DIRECTORY}"
deleteOldAndCreateDirectory "${SHARED_RESULT_ROOT_LOCATION}"

for LIBRARY_TO_BUILD in ${LIBRARIES_TO_BUILD[@]}
do
	export LIBRARY_WORKING_DIRECTORY_LOCATION="${WORKING_DIRECTORY}${LIBRARY_TO_BUILD}/"

	deleteOldAndCreateDirectory "${LIBRARY_WORKING_DIRECTORY_LOCATION}"

	./Libraries/build_${LIBRARY_TO_BUILD}.sh
done
