#!/usr/bin/env bash

# Note, this script assumes Ubuntu or Debian Linux and it will most likely fail on any other distribution.

# bomb on any error
set -e

# fix terminfo
# http://ashberlin.co.uk/blog/2010/08/24/color-in-ubuntu-init-scripts/
if [[ $(infocmp | grep 'hpa=') == "" ]]; then
  (infocmp; printf '\thpa=\\E[%sG,\n' %i%p1%d) > tmp-${$}.tic && \
    tic -s tmp-$$.tic -o /etc/terminfo && \
    rm tmp-$$.tic && \
    exec ${0} $@
fi

# gobals
BUILD_ROOT=$(cd -P -- "$(dirname -- "$0")" && pwd -P)
[ -e "${BUILD_ROOT}/scripts/globals" ] && . ${BUILD_ROOT}/scripts/globals

# import functions
[ -e "/lib/lsb/init-functions" ] && . /lib/lsb/init-functions
[ -e "${BUILD_ROOT}/scripts/functions" ] && . ${BUILD_ROOT}/scripts/functions


CURRENT_VERSION=`$(which sqlite3) ${BUILD_ROOT}/auth/db/auth.db "PRAGMA user_version"`
printf "Current database schema version is ${CURRENT_VERSION}\n"

UPDATE_SCRIPT="${BUILD_ROOT}/auth/db/updates/${CURRENT_VERSION}-to-${SCHEMA_VERSION}.sql"
if [ -e "${UPDATE_SCRIPT}" ]; then
	printf "Updating database schema to ${SCHEMA_VERSION}\n"
	log_action_begin_msg "Updating database schema from  ${CURRENT_VERSION} to ${SCHEMA_VERSION}"
	$(which sqlite3) ${BUILD_ROOT}/auth/db/auth.db < $UPDATE_SCRIPT &>> ${BUILD_ROOT}/netflix-proxy.log
	log_action_end_msg $?
fi
printf "Done!\n"