#!/bin/bash

# bomb on any error
set -e

# change to working directory
root="/opt/netflix-proxy"
pushd $root

# obtain the interface with the default gateway say
int=$(ip route | grep default | awk '{print $5}')

# obtain IP address of the Internet facing interface
ipaddr=$(ip addr show dev $int | grep inet | grep -v inet6 | awk '{print $2}' | grep -Po '[0-9]{1,3}+\.[0-9]{1,3}+\.[0-9]{1,3}+\.[0-9]{1,3}+(?=\/)')

# get the current date
date=$(/bin/date +'%Y%m%d')

echo "Updating db.override with ipaddr"=$ipaddr "and date="$date
$(which sed) -i "s/127.0.0.1/${ipaddr}/g" data/db.override
$(which sed) -i "s/YYYYMMDD/${date}/g" data/db.override

echo "Building docker containers"
$(which docker) build -t bind docker-bind
$(which docker) build -t sniproxy docker-sniproxy

echo "Starting Docker containers"
$(which docker) run --name bind -d -v /opt/netflix-proxy/data:/data -p 53:53/udp -t bind
$(which docker) run --name sniproxy -d -v /opt/netflix-proxy/data:/data --net=host -t sniproxy

echo "Testing DNS"
$(which dig) netflix.com @$ipaddr

echo "Testing proxy"
echo "GET /" | $(which openssl) s_client -servername netflix.com -connect $ipaddr:443

# configure upstart
cp init/* /etc/init

# change back to original directory
popd

echo "Done!"
