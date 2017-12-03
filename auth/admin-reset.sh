#!/usr/bin/env bash

# globals
CWD=$(cd -P -- "$(dirname -- "$0")" && pwd -P)
SQLITE_DB=${CWD}/db/auth.db

read -sp "Please enter a new admin password: " PASSWORD && printf "\n"

    pushd ${CWD} && \
      export HASH=`${CWD}/pbkdf2_sha256_hash.py ${PASSWORD} | awk '{print $2}'` && \
      sqlite3 ${SQLITE_DB} "UPDATE USERS SET password='${HASH}' WHERE id=1;" && \
      popd && \
      printf "rc=$?\n"
