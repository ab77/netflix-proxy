#!/usr/bin/env bash

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
CWD=$(cd -P -- "$(dirname -- "$0")" && pwd -P)
[ -e "${CWD}/scripts/globals" ] && . ${CWD}/scripts/globals

# import functions
[ -e "/lib/lsb/init-functions" ] && . /lib/lsb/init-functions
[ -e "${CWD}/scripts/functions" ] && . ${CWD}/scripts/functions


CURRENT_VERSION=$(sudo $(which sqlite3) ${CWD}/auth/db/auth.db "PRAGMA user_version")
printf "Current database schema version is ${CURRENT_VERSION}\n"

UPDATE_SCRIPT="${CWD}/auth/db/updates/${CURRENT_VERSION}-to-${SCHEMA_VERSION}.sql"
if [ -e "${UPDATE_SCRIPT}" ]; then
	log_action_begin_msg "Updating database schema from  ${CURRENT_VERSION} to ${SCHEMA_VERSION}"
	sudo $(which sqlite3) ${CWD}/auth/db/auth.db < $UPDATE_SCRIPT &>> ${CWD}/update.log
	log_action_end_msg $?
fi
printf "Done!\n"
