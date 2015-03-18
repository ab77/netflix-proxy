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


# obtain client (home) ip address
clientip=$(echo $SSH_CONNECTION | awk '{print $1}')

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

# configure iptables
iptables -I INPUT 1 -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -I INPUT 2 -p icmp -j ACCEPT
iptables -I INPUT 3 -i lo -j ACCEPT
iptables -I INPUT 4 -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT
iptables -I INPUT 5 -s $clientip/32 -p tcp -m tcp --dport 80 -j ACCEPT
iptables -I INPUT 6 -s $clientip/32 -p tcp -m tcp --dport 443 -j ACCEPT
iptables -I INPUT 7 -j REJECT --reject-with icmp-host-prohibited
iptables -D FORWARD 1
iptables -I FORWARD 4 -j REJECT --reject-with icmp-host-prohibited
iptables -I DOCKER 1 -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -I DOCKER 2 -p icmp -j ACCEPT
iptables -I DOCKER 3 -s $clientip/32 -p udp -m udp --dport 53 -j ACCEPT
iptables -I DOCKER 4 -j REJECT --reject-with icmp-host-prohibited
iptables-save > /etc/iptables.rules
grep -q 'pre-up iptables-restore < /etc/iptables.rules' /etc/network/interfaces || printf '\tpre-up iptables-restore < /etc/iptables.rules\n'  >> /etc/network/interfaces

# change back to original directory
popd

echo "Change your DNS to" $ipaddr "and start watching Netflix out of region."
echo "Done!"
