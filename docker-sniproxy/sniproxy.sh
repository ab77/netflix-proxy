#!/usr/bin/env bash

# globals
RANDOM_IPS=10

# import common functions
CDW=$(cd -P -- "$(dirname -- "$0")" && pwd -P)
. ${CDW}/functions

# set environment from linked container information
RESOLVER_IP=$(grep caching-resolver /etc/hosts | awk '{print $1}')

if [ -z ${RESOLVER_IP} ]; then
    RESOLVER_IP=8.8.8.8
fi

# update sniproxy config
printf "Setting sniproxy resolver to ${RESOLVER_IP}\n"
sed -i -r "s/nameserver ([0-9]{1,3}+\.[0-9]{1,3}+\.[0-9]{1,3}+\.[0-9]{1,3})/nameserver ${RESOLVER_IP}/" /data/conf/sniproxy.conf

# add source IP loadbalancing (if using IPv6)
if [[ $(get_ip6addr) != "" ]]; then
    add_source_ipv6_lb ${RANDOM_IPS}
fi

# launch sniproxy
/usr/sbin/sniproxy -c /data/conf/sniproxy.conf -f
