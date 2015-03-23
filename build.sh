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

# configure iptables
iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -p icmp -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT
iptables -A INPUT -s $clientip/32 -p tcp -m tcp --dport 80 -j ACCEPT
iptables -A INPUT -s $clientip/32 -p tcp -m tcp --dport 443 -j ACCEPT
iptables -A INPUT -j REJECT --reject-with icmp-host-prohibited
iptables -A FORWARD -j REJECT --reject-with icmp-host-prohibited
iptables -A DOCKER -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A DOCKER -p icmp -j ACCEPT
iptables -A DOCKER -s $clientip/32 -p udp -m udp --dport 53 -j ACCEPT
iptables -A DOCKER -j REJECT --reject-with icmp-host-prohibited
iptables-save > /etc/iptables.rules
grep -q 'pre-up iptables-restore < /etc/iptables.rules' /etc/network/interfaces || printf '\tpre-up iptables-restore < /etc/iptables.rules\n'  >> /etc/network/interfaces

echo "Updating db.override with ipaddr"=$ipaddr "and date="$date
$(which sed) -i "s/127.0.0.1/${ipaddr}/g" data/db.override
$(which sed) -i "s/YYYYMMDD/${date}/g" data/db.override

echo "Building docker containers"
#$(which docker) build -t bind docker-bind
#$(which docker) build -t sniproxy docker-sniproxy

echo "Starting Docker containers"
$(which docker) run --name bind -d -v /opt/netflix-proxy/data:/data -p 53:53/udp -t ab77/bind
$(which docker) run --name sniproxy -d -v /opt/netflix-proxy/data:/data --net=host -t ab77/sniproxy

echo "Testing DNS"
$(which dig) netflix.com @$ipaddr

echo "Testing proxy"
echo "GET /" | $(which openssl) s_client -servername netflix.com -connect $ipaddr:443

# configure upstart
cp init/* /etc/init

# change back to original directory
popd

echo "Change your DNS to" $ipaddr "and start watching Netflix out of region."
echo "Done!"
