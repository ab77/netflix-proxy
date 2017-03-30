#!/usr/bin/env bash

CDW=$(cd -P -- "$(dirname -- "$0")" && pwd -P)
. ${CDW}/functions

if [[ "${get_public6_prefix}" == "/64" ]]; then
    if [[ "${1}" == "-a" ]]; then
        ndp_proxy_add_delete 'add'
    elif [[ "${1}" == "-d" ]]; then
        ndp_proxy_add_delete 'delete'
    else
        printf "usage\n\t${0} -a|-d\n"
    fi
fi
