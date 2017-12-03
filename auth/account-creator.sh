#!/usr/bin/env bash

# globals
CWD=$(cd -P -- "$(dirname -- "$0")" && pwd -P)
SQLITE_DB=${CWD}/db/auth.db

read -p "Please enter a username: " USERNAME
read -sp "Please enter a password: " PASSWORD && printf "\n"
read -p "Expiry date? (YYYY-MM-DD): " EXPIRES
read -p "Please specify access group (0=user 1=admin): " PRIVILEGE

if [[ ! ${EXPIRES} =~ [0-9]{4}-[0-9]{2}-[0-9]{2} ]]; then
    printf "invalid date=${EXPIRES} (e.g. YYYY-MM-DD)\n"
    exit 1
fi

if [[ -n "${USERNAME}" && -n "${PASSWORD}" && -n "${EXPIRES}" && -n "${PRIVILEGE}" ]]; then
    printf "adding username=${USERNAME} expires=${EXPIRES} privilege=${PRIVILEGE}\n"
    pushd ${CWD} && \
      export HASH=`${CWD}/pbkdf2_sha256_hash.py ${PASSWORD} | awk '{print $2}'` && \
      sqlite3 ${SQLITE_DB} "INSERT INTO USERS (privilege, expires, username, password) VALUES (${PRIVILEGE}, '${EXPIRES}', '${USERNAME}', '${HASH}');" && \
      popd
else
    printf "invalid input user=\"${USERNAME}\" password=\"${PASSWORD}\" expires=\"${EXPIRES}\" privilege=\"${PRIVILEGE}\"\n"
    exit 1
fi
