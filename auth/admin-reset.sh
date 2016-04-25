#!/usr/bin/env bash
# UN-TESTED
# globals
BUILD_ROOT=$(cd -P -- "$(dirname -- "$0")" && pwd -P)
SQLITE_DB=${BUILD_ROOT}/db/auth.db

read -sp "Please enter a new admin password: " PASSWORD && printf "\n"

    pushd ${BUILD_ROOT} && \
      export HASH=`${BUILD_ROOT}/pbkdf2_sha256_hash.py ${PASSWORD} | awk '{print $2}'` && \
      sqlite3 ${SQLITE_DB} "UPDATE USERS SET password='yourpasswordhashhere' WHERE Id=1;" && \
      popd
