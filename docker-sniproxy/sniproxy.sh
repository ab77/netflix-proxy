#!/usr/bin/env bash

# set environment from linked container information
RESOLVER_IP=$(grep caching-resolver /etc/hosts | awk '{print $1}')

if [ -z ${RESOLVER_IP} ]; then
    RESOLVER_IP=8.8.8.8
fi

# update sniproxy config
printf "Setting sniproxy resolver to ${RESOLVER_IP}\n"
sed -i "s/8.8.8.8/${RESOLVER_IP}/" /data/conf/sniproxy.conf

# launch sniproxy
/usr/sbin/sniproxy -c /data/conf/sniproxy.conf -f
