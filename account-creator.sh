#!/bin/bash

# This script will assist in creating new users.

# Feel free to enhance this script further

USERNAME=
PASSWORD=
EXPIRES=
PRIVILEGE=
BUILD_ROOT=/opt/netflix-proxy
SQLITE_DB=${BUILD_ROOT}/auth/db/auth.db



echo "This script will assist in creating new users for the netflix-proxy admin page"
echo "Please answer the following questions:"

read -p "Please enter a username: " USERNAME
read -p "Please enter a password: " PASSWORD
read -p "Expiry date? (YYYY-MM-DD): " EXPIRES
read -p "Please specify a PRIVILEGE level (0=user 1=admin): " PRIVILEGE


# This will add a new user to the DB based on value provided above

pushd ${BUILD_ROOT} && \
  export HASH=`${BUILD_ROOT}/auth/pbkdf2_sha256_hash.py ${PASSWORD}` && \
  sqlite3 ${SQLITE_DB} "INSERT INTO USERS (privilege, expires, username, password) VALUES (${PRIVILEGE}, '${EXPIRES}', '${USERNAME}', '${HASH}');" && \
  popd

# Perhaps add a way to remove the user as well? Then again there are expiry dates.
