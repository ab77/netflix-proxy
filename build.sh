#!/bin/bash

# Note, this script assumes Ubuntu Linux and it will most likely fail on any other distribution.

# bomb on any error
set -e

# default timeout
timeout=3

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
	echo "Usage: $0 [-r 0|1] [-b 0|1] [-c <ip>] [-i 0|1] [-d 0|1] [-t 0|1]" 1>&2; \
	printf "\t-r\tenable (1) or disable (0) DNS recursion (default: 1)\n"; \
	printf "\t-b\tgrab docker images from repository (0) or build locally (1) (default: 0)\n"; \
	printf "\t-c\tspecify client-ip instead of being taken from ssh_connection\n"; \
	printf "\t-i\tskip iptables steps\n"; \
	printf "\t-d\tskip Docker steps\n"; \
	printf "\t-t\tskip testing steps\n"; \
	exit 1;
}

# process options
while getopts ":r:b:c:i:d:t:" o; do
	case "${o}" in
		r)
			r=${OPTARG}
			((r == 0|| r == 1)) || usage
			;;
		b)
			b=${OPTARG}
			((b == 0|| b == 1)) || usage
			;;
		c)
			c=${OPTARG}
			;;
		i)
			i=${OPTARG}
			((i == 0|| i == 1)) || usage
			;;
		d)
			d=${OPTARG}
			((d == 0|| d == 1)) || usage
			;;
		t)
			t=${OPTARG}
			((t == 0|| t == 1)) || usage
			;;
		*)
			usage
			;;
	esac
done
shift $((OPTIND-1))

if [[ -z "${r}" ]]; then
	r=1
fi

if [[ -z "${b}" ]]; then
	b=0
fi

if [[ -n "${c}" ]]; then
	clientip="${c}"
fi

if [[ -z "${i}" ]]; then
	i=0
fi

if [[ -z "${d}" ]]; then
	d=0
fi

if [[ -z "${t}" ]]; then
	t=0
fi

# diagnostics info
echo "clientip="$clientip "ipaddr="$ipaddr "extip"=$extip "-r"=${r} "-b"=${b} "-i"=${i} "-d"=${d}

# prepare BIND config
if [[ ${r} == 0 ]]; then
        printf "disabling DNS recursion...\n"
        printf "\t\tallow-recursion { none; };\n\t\trecursion no;\n\t\tadditional-from-auth no;\n\t\tadditional-from-cache no;\n" | sudo tee ${root}/docker-bind/named.recursion.conf
else
        printf "WARNING: enabling DNS recursion...\n"
        printf "\t\tallow-recursion { trusted; };\n\t\trecursion yes;\n\t\tadditional-from-auth yes;\n\t\tadditional-from-cache yes;\n" | sudo tee ${root}/docker-bind/named.recursion.conf
fi

# switch to working directory
pushd ${root}

if [[ ${i} == 0 ]]; then
	# configure iptables
	sudo iptables -N FRIENDS
	sudo iptables -A FRIENDS -s $clientip/32 -j ACCEPT
	sudo iptables -A FRIENDS -j DROP
	sudo iptables -N ALLOW
	sudo iptables -A INPUT -j ALLOW
	sudo iptables -A FORWARD -j ALLOW
	sudo iptables -A ALLOW -p icmp -j ACCEPT
	sudo iptables -A ALLOW -i lo -j ACCEPT
	sudo iptables -A ALLOW -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT
	sudo iptables -A ALLOW -m state --state RELATED,ESTABLISHED -j ACCEPT
	sudo iptables -A ALLOW -p tcp -m tcp --dport 80 -j FRIENDS
	sudo iptables -A ALLOW -p tcp -m tcp --dport 443 -j FRIENDS
	sudo iptables -A ALLOW -p tcp -m tcp --dport 43867 -j FRIENDS
	sudo iptables -A ALLOW -p udp -m udp --dport 53 -j FRIENDS
	sudo iptables -A ALLOW -j REJECT --reject-with icmp-host-prohibited
	echo iptables-persistent iptables-persistent/autosave_v4 boolean true | sudo debconf-set-selections
	echo iptables-persistent iptables-persistent/autosave_v6 boolean true | sudo debconf-set-selections
	sudo apt-get -y install iptables-persistent
	$(which grep) -vi docker /etc/iptables/rules.v4 > /tmp/rules.v4 && sudo cp /tmp/rules.v4 /etc/iptables/rules.v4 && sudo rm /tmp/rules.v4
	$(which grep) -vi docker /etc/iptables/rules.v6 > /tmp/rules.v6 && sudo cp /tmp/rules.v6 /etc/iptables/rules.v6 && sudo rm /tmp/rules.v6

	# socialise Docker with iptables-persistent: https://groups.google.com/forum/#!topic/docker-dev/4SfOwCOmw-E
	if [ ! -f "/etc/init/docker.conf.bak" ]; then
		sudo $(which sed) -i.bak 's/start on (local-filesystems and net-device-up IFACE!=lo)/start on (local-filesystems and net-device-up IFACE!=lo and started iptables-persistent)/' /etc/init/docker.conf
	fi
	
	if [ ! -f "/etc/init.d/iptables-persistent.bak" ]; then
		sudo $(which sed) -i.bak '/load_rules$/{N;s/load_rules\n\t;;/load_rules\n\tinitctl emit -n started JOB=iptables-persistent\n\t;;/}' /etc/init.d/iptables-persistent && \
		sudo $(which sed) -i'' 's/stop)/stop)\n\tinitctl emit stopping JOB=iptables-persistent/' /etc/init.d/iptables-persistent
	fi	
fi

echo "Updating db.override with ipaddr"=$extip "and date="$date
sudo $(which sed) -i "s/127.0.0.1/${extip}/g" data/db.override
sudo $(which sed) -i "s/YYYYMMDD/${date}/g" data/db.override

if [[ ${d} == 0 ]]; then
	if [[ "${b}" == "1" ]]; then
		echo "Building docker containers"
		sudo $(which docker) build -t bind docker-bind
		sudo $(which docker) build -t sniproxy docker-sniproxy
	
		echo "Starting Docker containers (local)"
		sudo $(which docker) run --name bind -d -v ${root}/data:/data --net=host -t bind
		sudo $(which docker) run --name sniproxy -d -v ${root}/data:/data --net=host -t sniproxy
	else
		echo "Starting Docker containers (from repository)"
		sudo $(which docker) run --name bind -d -v ${root}/data:/data --net=host -t ab77/bind
		sudo $(which docker) run --name sniproxy -d -v ${root}/data:/data --net=host -t ab77/sniproxy
	fi
fi

# add upstart scripts
#if [ -d "/etc/init" ]; then
#	sudo cp ./upstart/* /etc/init/
#fi

# add systemd scripts
#if [ -d "/etc/systemd/system" ]; then
#        sudo cp ./systemd/* /etc/systemd/system/
#fi

# configure appropriate init system (http://unix.stackexchange.com/a/164092/78029)
if [[ `/sbin/init --version` =~ upstart ]]; then
	sudo cp ./upstart/* /etc/init/;

elif [[ `systemctl` =~ -\.mount ]]; then
	sudo cp ./systemd/* /etc/systemd/system/;
fi

if [[ ${t} == 0 ]]; then
	echo "Testing DNS"
	$(which dig) +time=$timeout netflix.com @$extip || $(which dig) +time=$timeout netflix.com @$ipaddr

	echo "Testing proxy"
	echo "GET /" | $(which timeout) $timeout $(which openssl) s_client -servername netflix.com -connect $extip:443 || echo "GET /" | $(which timeout) $timeout $(which openssl) s_client -servername netflix.com -connect $ipaddr:443
fi

# change back to original directory
popd

echo "Change your DNS to" $extip "and start watching Netflix out of region."
echo "Done!"
