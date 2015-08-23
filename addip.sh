#!/bin/bash

# Note, this script assumes Ubuntu Linux and it will most likely fail on any other distribution.

# bomb on any error
set -e

# change to working directory
root="/opt/netflix-proxy"

# obtain the interface with the default gateway
int=$(ip route | grep default | awk '{print $5}')

# obtain IP address of the Internet facing interface
ipaddr=$(ip addr show dev $int | grep inet | grep -v inet6 | awk '{print $2}' | grep -Po '[0-9]{1,3}+\.[0-9]{1,3}+\.[0-9]{1,3}+\.[0-9]{1,3}+(?=\/)')
extip=$($(which dig) +short myip.opendns.com @resolver1.opendns.com)

# obtain client (home) ip address
clientip=$(echo $SSH_CONNECTION | awk '{print $1}')

# get the current date
date=$(/bin/date +'%Y%m%d')

# display usage
usage() {
	echo "Usage: $0 [-r 0|1] [-b 0|1] [-c <ip>]" 1>&2; \
	printf "\t-c\tspecify client-ip instead of being taken from ssh_connection\n"; \
	exit 1;
}

# process options
while getopts "c:" o; do
	case "${o}" in
		c)
			c=${OPTARG}
			;;
		*)
			usage
			;;
	esac
done
shift $((OPTIND-1))
if [[ -n "${c}" ]]; then
	clientip="${c}"
fi

# diagnostics info
echo "clientip="$clientip "ipaddr="$ipaddr "extip"=$extip

# switch to working directory
pushd ${root}

# configure iptables
sudo iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo iptables -A INPUT -p icmp -j ACCEPT
sudo iptables -A INPUT -i lo -j ACCEPT
sudo iptables -A INPUT -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT
sudo iptables -A INPUT -s $clientip/32 -p tcp -m tcp --dport 80 -j ACCEPT
sudo iptables -A INPUT -s $clientip/32 -p tcp -m tcp --dport 443 -j ACCEPT
sudo iptables -A INPUT -j REJECT --reject-with icmp-host-prohibited
sudo iptables -A FORWARD -j REJECT --reject-with icmp-host-prohibited
sudo iptables -A DOCKER -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo iptables -A DOCKER -p icmp -j ACCEPT
sudo iptables -A DOCKER -s $clientip/32 -p udp -m udp --dport 53 -j ACCEPT
sudo iptables -A DOCKER -j REJECT --reject-with icmp-host-prohibited
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | sudo debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | sudo debconf-set-selections
sudo apt-get -y install iptables-persistent

echo "Testing DNS"
$(which dig) netflix.com @$ipaddr

echo "Testing proxy"
echo "GET /" | $(which openssl) s_client -servername netflix.com -connect $ipaddr:443

# configure upstart
sudo cp init/* /etc/init

# change back to original directory
popd

echo "Change your DNS to" $extip "and start watching Netflix out of region."
echo "Done!"
