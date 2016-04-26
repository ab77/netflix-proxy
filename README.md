# netflix-proxy [![Build Status](https://travis-ci.org/ab77/netflix-proxy.svg?branch=master)](https://travis-ci.org/ab77/netflix-proxy) [![Docker Pulls](https://img.shields.io/docker/pulls/ab77/sniproxy.svg?maxAge=2592000)](https://hub.docker.com/r/ab77/sniproxy/) [![Docker Stars](https://img.shields.io/docker/stars/ab77/bind.svg?maxAge=2592000)](https://hub.docker.com/r/ab77/bind/)  [![](https://www.paypalobjects.com/en_GB/i/btn/btn_donate_SM.gif)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=5UUCDR8YXWERQ)
`Docker` packaged smart DNS proxy to watch `Netflix`, `Hulu`[n2], `HBO Now` and others out of region using `BIND` and `SNIProxy`[n1]. Bypasses [The Great Firewall](https://github.com/ab77/netflix-proxy/issues/153#issuecomment-211442063) and works for blocked sites too, such as [PornHub](http://www.pornhub.com/). 

This solution will only work with devices supporting Server Name Indication (SNI)[n7]. To test, open a web browser on the device you are planning to watch content and go to [this](https://sni.velox.ch/) site (`https://sni.velox.ch/`).

**Update March/2016**: IPv6 addresses of common hosting providers are now blocked in the same way as IPv4. Netflix could to be "tagging" accounts too, so if your account is tagged, the only device that will work out of region is the desktop web browser (i.e. Chrome)[n11]. Netflix and BBC iPlayer are also perfoming geo checks on their media hosts, so the relevant media domains are now proxied by default[n8]. Please note, that proxying media delivery could increase the bandwidth bill you get from your VPS provider. However, since most VPS providers offer 1TB per month inclusive with each server and most home ISPs don't offer anywhere near that amount, it should be a moot point in most situations.

If you feel all of this is too complicated, I don't blame you. If you want change, vote with your wallet by cancelling your Netflix subscription and/or sign the petition:

[![](https://raw.githubusercontent.com/ab77/netflix-proxy/master/static/petition.png)](https://act.openmedia.org/netflix)

Please see the [**Wiki**](https://github.com/ab77/netflix-proxy/wiki) page(s) for some common troubleshooting ideas.

**Unblocked Netflix?** Great success! [Vote](http://www.poll-maker.com/poll622505x596e406D-26) now and see the [results](http://www.poll-maker.com/results622505xfcC7F6aA-26).

[![](https://raw.githubusercontent.com/ab77/netflix-proxy/master/static/poll_results.png)](http://www.poll-maker.com/results622505xfcC7F6aA-26)

# Supported Services
The following are supported out of the box, however adding additional services is trivial and is done by updating `zones.override` file and running `docker restart bind`:
* Netflix
* Hulu[n2]
* HBO Now 
* Amazon Instant Video
* Crackle
* Pandora
* Vudu
* blinkbox
* BBC iPlayer[n5]
* NBC Sports and potentially many [more](https://github.com/ab77/netflix-proxy/blob/data/conf/zones.override)

# License
This project is **free**, covered by the [MIT License](https://github.com/ab77/netflix-proxy/blob/master/LICENSE.md). It is provided without any warranty and can be used for any purpose, including private and commercial. However, if you are planning to use it for commercial purposes (i.e make money off it), please do not expect me to provide support for free, as it would be unfair. A commercial support model can always be negotiated, if required. Please [contact](https://www.upwork.com/freelancers/~016da2a2dc195af5ec) me if this is something that interests you.

# Instructions
The following paragraphs show how to get this solution up and running with a few different Cloud providers I've tried so far. Note, OpenVZ **won't work**, make sure to get a proper virtual machine using KVM or Xen. These instructions are based on the assumption, that access to the US region access is desired. If a different region is required (e.g. France), you may struggle with HE tunnel broker, as their entire network appears to be [geo-located](https://www.maxmind.com/en/geoip-demo) in the US. Instead, you could try to find a small hosting provider in the desired region and install with native IPv6 (or even just IPv4) instead of tunnel. To do this, run the build normally, but omit all parameters to `build.sh`.

[![](https://raw.githubusercontent.com/ab77/netflix-proxy/master/static/digitalocean.png)](https://m.do.co/c/937b01397c94)

The following is based on a standard Ubuntu Docker image provided by `DigitalOcean`, but should in theory work on any Linux distribution **with** Docker pre-installed. Do **not** enable native IPv6 on the host.

1. Head over to [Digital Ocean](https://m.do.co/c/937b01397c94) to get **$10 USD credit**
2. Create a Droplet in a location closest to you using `Docker 1.x` on `Ubuntu 14.04` (find in under `One-click Apps` tab).
3. Create a free [tunnel broker](https://tunnelbroker.net/register.php) account.
4. Create a [regular tunnel](https://tunnelbroker.net/new_tunnel.php).
5. Set the `IPv4 Endpoint` to the Droplet IP, pick a tunnel server in a location closest[n14] to you and click `Create Tunnel`.
6. SSH to your server and run `ping6 netflix.com`; if you get `Network is unreachable` proceed to the next step, otherwise remove native IPv6 first.
7. Run: `git clone https://github.com/ab77/netflix-proxy /opt/netflix-proxy && cd /opt/netflix-proxy && ./build.sh -u <tunnelbroker-username> -p <tunnelbroker-password>`, making sure to specify your HE tunnel username and password correctly.
8. Make sure to **record the URL and credentials** for the `netflix-proxy` admin site.
9. Set your DNS server to the IP given at the end of the script, then go to [this](http://ipinfo.io/) site to make sure the same IP is displayed.
10. Finally, enjoy `Netflix` and others out of region.
11. Enjoy or raise a new [issue](https://github.com/ab77/netflix-proxy/issues/new) if something doesn't work quite right (also `#netflix-proxy` on [freenode](https://webchat.freenode.net/?channels=netflix-proxy)).

### Authorising Additional IPs
If you want to share your system with friends and family, you can authorise their home IP address(s) using the `netflix-proxy` admin site, located at `http://<ipaddr>:8080/`, where `ipaddr` is the public IP address of your VPS. Login using `admin` account with the password you recorded during the build, in step 8 above. If you've forgottedn your admin credentials, [reset](https://github.com/ab77/netflix-proxy/wiki/Changing-Admin-Password-For-Auth-Version).

[![](https://raw.githubusercontent.com/ab77/netflix-proxy/master/static/admin.png)](https://raw.githubusercontent.com/ab77/netflix-proxy/master/static/admin.png)

The `admin` account does not restrict the entry or removal of IPs. If you want to restrict the entry of IPs to the current client IP using an automatically populated drop-down, create a standard user account using the `account-creator.sh` script located in the `auth` directory, which will prompt you for the input and create the user account.

#### Dynamic IPs
You can also use the `netflix-proxy` admin site to update your IP address, should your ISP assign you a new one (e.g. via DHCP). If your IP address does change, all HTTP/HTTPS requests will automatically be redirected to the admin site on port `8080`. All DNS requests will be redirected to `dnsmasq` instance running on port `5353`. You will most likely need to purge your browser and system DNS caches after this (e.g. `ipconfig /flushdns` and `chrome://net-internals/#dns`) and/or reboot the relevant devices. This mechanism should work on browsers, but will most likely cause errors on other devices, such as Apple TVs and smart TVs. If you Internet stops working all of a sudden, try loading a browser and going to `netflix.com`.

#### Automatic IP Authorization
**WARNING**: do not do enable this unless you know what you are doing.

To enable automatic authorization of every IP that hits your proxy, set `AUTO_AUTH = True` in `auth/settings.py` and run `service netflix-proxy-admin restart`. This setting will effectively authorize any IP hitting your proxy IP with a web browser for the first time, including bots, hackers, spammers, etc. Upon successful authorization, the browser will be redirected to [Google](http://google.com/).

The DNS service is configured with recursion turned on by [default](https://github.com/ab77/netflix-proxy#security), so after a successful authorization, anyone can use your VPS in DNS amplification attacks, which will probably put you in breach of contract with the VPS provider. You have been **WARNED**.

### Security
The build script automatically configures the system with **DNS recursion turned on**. This has security implications, since it potentially opens your DNS server to a DNS amplification attack, a kind of a [DDoS attack](https://en.wikipedia.org/wiki/Denial-of-service_attack). This should not be a concern however, as long as the `iptables` firewall rules configured automatically by the build script for you remain in place. However if you ever decide to turn the firewall off, please be aware of this.

If you want to turn DNS recursion off, please be aware that you will need a mechanism to selectively send DNS requests for domains your DNS server knows about (i.e. netflix.com) to your VPS and send all of the other DNS traffic to your local ISP's DNS server. Something like [Dnsmasq](http://www.thekelleys.org.uk/dnsmasq/doc.html) can be used for this and some Internet routers even have it built in. In order to switch DNS recursion off, you will need to build your system using the following command:

```
git clone https://github.com/ab77/netflix-proxy /opt/netflix-proxy && cd /opt/netflix-proxy && ./build.sh -r 0 -b 1
```

### Command Line Options
The following command line options can be optionaly passed to `build.sh` for additional control:

```
Usage: ./build.sh [-r 0|1] [-b 0|1] [-c <ip>] [-z 0|1] [-u <username>] [-p <password>] [-k <update-key>] [-n <1..N>] [-s <subnet>]
        -r      enable (1) or disable (0) DNS recursion (default: 1)
        -b      grab docker images from repository (0) or build locally (1) (default: 0)
        -c      specify client-ip instead of being taken from ssh_connection
        -s      specify IPv6 subnet for Docker (e.g. 2001:470:abcd:123::/64)
        -z      enable caching resolver (default: 0)
        -u      HE tunnel broker username
        -p      HE tunnel broker password
        -k      HE tunnel broker update key
        -n      HE tunnel index (default: 1)
```

## Other Cloud Providers

### Locale Issues

The build script has been designed to work on `Ubuntu 14.x` and `Debian 8.x`. It will most likely fail on all other distributions. Some pre-requisites require the locale to be set correctly and some provider OS images need extra help. If you get `locale` issues reported by `Python` and/or `pip` during the build, try running the following first:

```
export LANGUAGE=en_US.UTF-8 && \
  export LANG=en_US.UTF-8 && \
  export LC_ALL=en_US.UTF-8 && \
  export LC_CTYPE="en_US.UTF-8" && \
  locale-gen en_US.UTF-8 && \
  sudo apt-get -y install language-pack-en-base && \
  sudo dpkg-reconfigure locales
```

[![](https://raw.githubusercontent.com/ab77/netflix-proxy/master/static/vultr.png)](http://www.vultr.com/?ref=6871746)

The following is based on a Debian image provided by `Vultr`, but should in theory work on any Debian distribution. Do **not** enable native IPv6 on the host.

1. Head over to [Vultr](http://www.vultr.com/?ref=6871746) to create an account.
2. Create a compute instance in a location closest to you using `Debian 8 x64 (jessie)` image.
3. Create a free [tunnel broker](https://tunnelbroker.net/register.php) account.
4. Create a [regular tunnel](https://tunnelbroker.net/new_tunnel.php).
5. Set the `IPv4 Endpoint` to the IP address of your Vultr instance, pick a tunnel server closest to you and click `Create Tunnel`.
6. SSH to your server and run `ping6 netflix.com`; if you get `Network is unreachable` proceed to the next step, otherwise remove native IPv6 first.
7. Run: `apt-get update && apt-get -y install vim dnsutils curl sudo git && curl -sSL https://get.docker.com/ | sh && git clone https://github.com/ab77/netflix-proxy /opt/netflix-proxy && cd /opt/netflix-proxy && ./build.sh -u <tunnelbroker-username> -p <tunnelbroker-password>`, making sure to specify your HE tunnel username and password correctly.
8. Make sure to **record the credentials** for the `netflix-proxy` admin site.
9. Set your DNS server to the IP given at the end of the script, then go to [this](http://ipinfo.io/) site to make sure the same IP is displayed.
10. Finally, enjoy `Netflix` and others out of region.
11. Enjoy or raise a new [issue](https://github.com/ab77/netflix-proxy/issues/new) if something doesn't work quite right (also `#netflix-proxy` on [freenode](https://webchat.freenode.net/?channels=netflix-proxy)).

[![](http://www.ramnode.com/images/banners/affbannerdarknewlogo.png)](https://clientarea.ramnode.com/aff.php?aff=3079)

The following is based on a Debian or Ubuntu OS images provided by `RamNode`. Do **not** enable native IPv6 on the host.

1. Head over to [RamNode](https://clientarea.ramnode.com/aff.php?aff=3079) to create an account and buy a **KVM** VPS in a location closest to you (OpenVZ won't work).
2. Log into the `VPS Control Panel` and (re)install the OS using `Ubuntu 14.04 x86_64 Server Minimal` or `Debian 8.0 x86_64 Minimal` image.
3. Create a free [tunnel broker](https://tunnelbroker.net/register.php) account.
4. Create a [regular tunnel](https://tunnelbroker.net/new_tunnel.php).
5. Set the `IPv4 Endpoint` to the IP address of your RamNode VPS, pick a tunnel server closest to you and click `Create Tunnel`.
6. SSH to your server and run `ping6 netflix.com`; if you get `Network is unreachable` proceed to the next step, otherwise remove native IPv6 first.
7. Run: `apt-get update && apt-get -y install vim dnsutils curl sudo git && curl -sSL https://get.docker.com/ | sh && git clone https://github.com/ab77/netflix-proxy /opt/netflix-proxy && cd /opt/netflix-proxy && ./build.sh -u <tunnelbroker-username> -p <tunnelbroker-password>`, making sure to specify your HE tunnel username and password correctly.
8. Make sure to **record the credentials** for the `netflix-proxy` admin site.
9. Set your DNS server to the IP given at the end of the script, then go to [this](http://ipinfo.io/) site to make sure the same IP is displayed.
10. Finally, enjoy `Netflix` and others out of region.
11. Enjoy or raise a new [issue](https://github.com/ab77/netflix-proxy/issues/new) if something doesn't work quite right (also `#netflix-proxy` on [freenode](https://webchat.freenode.net/?channels=netflix-proxy)).

[![](https://www.linode.com/media/images/logos/standard/light/linode-logo_standard_light_small.png)](https://www.linode.com/?r=ceb35af7bad520f1e2f4232b3b4d49136dcfe9d9)

**(untested)** The following is based on a standard Ubuntu image provided by `Linode`, but should work on any Linux distribution **without** Docker installed. Do **not** enable native IPv6 on the host or disable it post-build and before moving onto step 7.

1. Head over to [Linode](https://www.linode.com/?r=ceb35af7bad520f1e2f4232b3b4d49136dcfe9d9) and sign-up for an account.
2. Create a new `Linode` in a location closest to you and deploy an `Ubuntu 14-04 LTS` image into it.
3. Create a free [tunnel broker](https://tunnelbroker.net/register.php) account.
4. Create a [regular tunnel](https://tunnelbroker.net/new_tunnel.php).
5. Set the `IPv4 Endpoint` to the IP address of your Linode, pick a tunnel server closest to you and click `Create Tunnel`.
6. SSH to your server and run `ping6 netflix.com`; if you get `Network is unreachable` proceed to the next step, otherwise remove native IPv6 first.
7. Run: `apt-get update && apt-get -y install vim dnsutils curl sudo git && curl -sSL https://get.docker.com/ | sh && git clone https://github.com/ab77/netflix-proxy /opt/netflix-proxy && cd /opt/netflix-proxy && ./build.sh -u <tunnelbroker-username> -p <tunnelbroker-password>`, making sure to specify your HE tunnel username and password correctly.
8. Make sure to **record the credentials** for the `netflix-proxy` admin site.
9. Set your DNS server to the IP given at the end of the script, then go to [this](http://ipinfo.io/) site to make sure the same IP is displayed.
10. Finally, enjoy `Netflix` and others out of region.
11. Enjoy or raise a new [issue](https://github.com/ab77/netflix-proxy/issues/new) if something doesn't work quite right (also `#netflix-proxy` on [freenode](https://webchat.freenode.net/?channels=netflix-proxy)).

[![](https://raw.githubusercontent.com/ab77/netflix-proxy/master/static/dreamhost.png)](http://www.dreamhost.com/r.cgi?2124700)

**(untested)** The following is based on a standard Ubuntu image provided by `DreamHost`, but should work on any Linux distribution **without** Docker installed and running under **non-root** user (e.g. `Amazon Web Services`[n13]). Do **not** enable native IPv6 on the host.

1. Head over to [DreamHost](http://www.dreamhost.com/r.cgi?2124700) and sign-up for an account.
2. Find the `DreamCompute` or `Public Cloud Computing` section and launch an `Ubuntu 14-04-Trusty` instance in a location closest to you.
3. Make sure to add an additional firewall rule to allow DNS: `Ingress	IPv4	UDP	53	0.0.0.0/0 (CIDR)`
4. Also add a `Floating IP` to your instance.
5. Create a free [tunnel broker](https://tunnelbroker.net/register.php) account.
6. Create a [regular tunnel](https://tunnelbroker.net/new_tunnel.php).
7. Set the `IPv4 Endpoint` to the IP address of your instance, pick a tunnel server closest to you and click `Create Tunnel`.
8. SSH to your server and run `ping6 netflix.com`; if you get `Network is unreachable` proceed to the next step, otherwise remove native IPv6 first.
9. Run: `sudo apt-get update && sudo apt-get -y install vim dnsutils curl git && curl -sSL https://get.docker.com/ | sh && sudo usermod -aG docker $(whoami | awk '{print $1}') && sudo git clone https://github.com/ab77/netflix-proxy /opt/netflix-proxy && cd /opt/netflix-proxy && ./build.sh -u <tunnelbroker-username> -p <tunnelbroker-password>`, making sure to specify your HE tunnel username and password correctly.
10. Make sure to **record the credentials** for the `netflix-proxy` admin site.
11. Set your DNS server to the IP given at the end of the script, then go to [this](http://ipinfo.io/) site to make sure the same IP is displayed.
12. Finally, enjoy `Netflix` and others out of region.
13. Enjoy or raise a new [issue](https://github.com/ab77/netflix-proxy/issues/new) if something doesn't work quite right (also `#netflix-proxy` on [freenode](https://webchat.freenode.net/?channels=netflix-proxy)).

[![](https://raw.githubusercontent.com/ab77/netflix-proxy/master/static/gandi.png)](https://www.gandi.net/hosting/iaas/buy)

The following is based on Ubuntu image provided by `Gandi` using` root` login with SSH key only (no password). For default non-root `admin` login, adjust step 6 to use `sudo` where nesessary. If using HE tunnel borker, you will definitely need to [disable](http://askubuntu.com/a/484487/412107) native IPv6, as it is enabled by default.

1. Head over to [Gandi](https://www.gandi.net/hosting/iaas/buy) to create a virtual server.
2. Create a free [tunnel broker](https://tunnelbroker.net/register.php) account.
3. Create a [regular tunnel](https://tunnelbroker.net/new_tunnel.php).
4. Set the `IPv4 Endpoint` to the IP address of your server, pick a tunnel server in the US and click `Create Tunnel`.
5. SSH to your server and run `ping6 netflix.com`; if you get `Network is unreachable` proceed to the next step, otherwise remove native IPv6 first.
6. Run: `apt-get update && apt-get -y install vim dnsutils curl sudo git && curl -sSL https://get.docker.com/ | sh && git clone https://github.com/ab77/netflix-proxy /opt/netflix-proxy && cd /opt/netflix-proxy && ./build.sh -u <tunnelbroker-username> -p <tunnelbroker-password>`, making sure to specify your HE tunnel username and password correctly.
7. Make sure to **record the credentials** for the `netflix-proxy` admin site.
8. Set your DNS server to the IP given at the end of the script, then go to [this](http://ipinfo.io/) site to make sure the same IP is displayed.
9. Finally, enjoy `Netflix` and others out of region.
10. Enjoy or raise a new [issue](https://github.com/ab77/netflix-proxy/issues/new) if something doesn't work quite right (also `#netflix-proxy` on [freenode](https://webchat.freenode.net/?channels=netflix-proxy)).

### Microsoft Azure (advanced)
The following **has not been tested** and is based on a standard `Ubuntu` image provided by `Microsoft Azure` using `cloud-harness` automation tool I wrote a while back and assumes an empty `Microsoft Azure` subscription. Also, because Azure [block ICMP](https://blogs.msdn.microsoft.com/mast/2014/06/22/use-port-pings-instead-of-icmp-to-test-azure-vm-connectivity/) thorough the load-balancer, IPv6 tunnelling through HE tunnel broker isn't going to work.

1. Head over to [Microsoft Azure](https://azure.microsoft.com/en-gb/) and sign-up for an account.
2. Get [Python](https://www.python.org/downloads/).
3. On your workstation, run `git clone https://github.com/ab77/cloud-harness.git /opt/cloud-harness`.
4. Follow `cloud-harness` [Installation and Configuration](https://github.com/ab77/cloud-harness#installation-and-configuration) section to set it up.
5. [Create](https://github.com/ab77/cloud-harness#create-storage-account-name-must-be-unique-as-it-forms-part-of-the-storage-url-check-with---action-check_storage_account_name_availability) a storage account.
6. [Create](https://github.com/ab77/cloud-harness#create-a-new-hosted-service-name-must-be-unique-within-cloudappnet-domain-check-with---action-check_storage_account_name_availability) a new hosted service.
7. [Add](https://github.com/ab77/cloud-harness#add-x509-certificate-containing-rsa-public-key-for-ssh-authentication-to-the-hosted-service) a hosted service certificate for SSH public key authentication
8. [Create](https://github.com/ab77/cloud-harness#create-a-reserved-ip-address-for-the-hosted-service) a reserved ip address.
9. [Create](https://github.com/ab77/cloud-harness#create-virtual-network) a virtual network.
10. [Create](https://github.com/ab77/cloud-harness#create-a-new-linux-virtual-machine-deployment-and-role-with-reserved-ip-ssh-authentication-and-customscript-resource-extensionn3) a `Ubuntu 14.04 LTS` virtual machine as follows:

```
    ./cloud-harness.py azure --action create_virtual_machine_deployment \
    --service <your hosted service name> \
    --deployment <your hosted service name> \
    --name <your virtual machine name> \
    --label 'Netflix proxy' \
    --account <your storage account name> \
    --blob b39f27a8b8c64d52b05eac6a62ebad85__Ubuntu-14_04-LTS-amd64-server-20140414-en-us-30GB \
    --os Linux \
    --network VNet1 \
    --subnet Subnet-1 \
    --ipaddr <your reserved ipaddr name> \
    --size Medium \
    --ssh_auth \
    --disable_pwd_auth \
    --verbose
```

11. Use the [Azure Management Portal](https://manage.windowsazure.com/) to add `DNS (UDP)`, `HTTP (TCP)` and `HTTPS (TCP)` endpoints and secure them to your home/work/whatever IPs using the Azure `ACL` feature.
12. SSH to your VM as `azureuser` using custom public TCP port (not `22`) and use any non-root user Ubuntu instructions to build/install `netflix-proxy`.

### Automated Tests

#### Test Build
This project is linked with `Travis CI` to deploy and test the project automatically. The Python script `testbuild.py` is used to deploy and test `netflix-proxy`. This script deploys a test `Droplet` and then runs a serious of tests to verify (a) that all `Docker` containers start; (b) the `built.sh` script outputs the correct message at the end; (c) all the relevant services survive a reboot; and (d) proxy is able to comunicate with Netflix over SSL.

The `testbuild.py` script can also be used to programatically deploy `Droplets` from the command line:
```
usage: testbuild.py digitalocean [-h] --api_token API_TOKEN
                                 [--client_ip CLIENT_IP]
                                 [--fingerprint FINGERPRINT [FINGERPRINT ...]]
                                 [--region REGION] [--branch BRANCH]
                                 [--tb_user TB_USER] [--tb_passwd TB_PASSWD]
                                 [--tb_key TB_KEY] [--tb_index TB_INDEX]
                                 [--create] [--destroy] [--list_regions]
                                 [--name NAME]

optional arguments:
  -h, --help            show this help message and exit
  --api_token API_TOKEN
                        DigitalOcean API v2 secret token
  --client_ip CLIENT_IP
                        client IP to secure Droplet
  --fingerprint FINGERPRINT [FINGERPRINT ...]
                        SSH key fingerprint
  --region REGION       region to deploy into; use --list_regions for a list
  --branch BRANCH       netflix-proxy branch to deploy (default: master)
  --tb_user TB_USER     HE tunnel broker username
  --tb_passwd TB_PASSWD
                        HE tunnel broker password
  --tb_key TB_KEY       HE tunnel broker update key
  --tb_index TB_INDEX   HE tunnel broker tunnel index (default: 1)
  --create              Create droplet
  --destroy             Destroy droplet
  --list_regions        list all available regions
  --name NAME           Droplet name
```

Note, you will need a working `Python 2.7` environment and the modules listed in `tests/requirements.txt` (run `pip install -r tests/requirements.txt`).

#### Test Video Playback
After a successfull build deployment, `testvideo.py` is executed to test Netflix video playback. This is done by playing back 60 seconds of a title known to only be available in the US region (e.g. [1,000 Times Good Night](https://www.netflix.com/title/80001898)).

```
usage: testvideo.py netflix [-h] --email EMAIL --password PASSWORD
                            [--seconds SECONDS] [--titleid TITLEID]
                            [--tries TRIES]

optional arguments:
  -h, --help           show this help message and exit
  --email EMAIL        Netflix username
  --password PASSWORD  Netflix password
  --seconds SECONDS    playback time per title in seconds (default: 60)
  --titleid TITLEID    Netflix title_id to play (default: 80001898)
  --tries TRIES        Playback restart attempts (default: 4)
```

Finally, a screenshot is saved at the end of the test, which is uploaded to the `gh-pages` branch.

![VideoPlaybackTest](https://raw.githubusercontent.com/ab77/netflix-proxy/gh-pages/artifacts/VideoPlaybackTest.png)

### IPv6 and Docker
This solution uses IPv6 downstream from the proxy to unblock IPv6 enabled providers, such as Netflix. No IPv6 support on the client is required for this to work, only the VPS must public IPv6 connectivity. You may also need to turn off IPv6 on your local network (and/or relevant devices).[n6] Having said that, the current iteration uses `HE Eectric's` free tunnel broker service to provide IPv6 connectivity, since `HE Electric` is geo-located in the US, Netflix geoblocking (or `geo-bollocking`, if you like), allows the traffic through.

```
+----------+                  +-----------+                 +-----------------+
|          |                  |           |                 |                 |
|  client  | +--------------> |   proxy   | +-------------> |  Netflix, etc.  |
|          |      (ipv4)      |           |      (ipv6)     |                 |
+----------+                  +-----------+                 +-----------------+
```

When IPv6 public address is present on the host, Docker is configured with public IPv6 support. This is done by assuming the smallest possible IPv6 allocation, dividing it further by two and assigning the second half to the Docker system. Network Discovery Protocol (NDP) proxying is required for this to work, since the second subnet can not be routed[n9]. Afterwards, Docker is running in dual-stack mode, with each container having a public IPv6 address. This approach seems to work in most cases where native IPv6 is used. If IPv6 is provided via a tunnel, Docker subnet can not be reliably calculated and must be specified using `-s` parameter to the `build.sh` script. If IPv6 is not enabled at all, the VPS is built with IPv4 support only.

#### RamNode
RamNode (and any other provider which uses SolusVM as its VPS provisioning system[n10]) assign a `/64` subnet to the VPS, but don't route it. Instead, individual addresses must be added in the portal if they are to be used on the host. After speaking with RamNode support, it appears this is a side-effect of MAC address filtering, which prevents IP address theft. This means that even though the subnet can be further divided on the host, only the main IPv6 address bound to `eth0` is ever accessible from the outside and none of the IPv6 addresses on the bridges below can communicate over IPv6 to the outside.

To demonstrate this behavour, follow these steps:
```
IPV6_SUBNET=<allocated-ipv6-subnet> (e.g. 2604:180:2:abc)
IPV6_ADDR=<allocated-ipv6-addr> (e.g. 2604:180:2:abc::abcd)

# re-configure eth0
ip -6 addr del ${IPV6_ADDR}/64 dev eth0
ip -6 addr add ${IPV6_ADDR}/80 dev eth0

# install Docker
apt-get update && apt-get -y install vim dnsutils curl sudo git && curl -sSL https://get.docker.com/ | sh

# update DOCKER_OPTS
# for upstart based systems (e.g. Ubuntu):
printf "DOCKER_OPTS='--ipv6 --fixed-cidr-v6=\"${IPV6_SUBNET}:1::/80\"'\n" > /etc/default/docker && \
  service docker restart

# -- OR --

# for systemd based systems (e.g. Debian):
# change "ExecStart" in /lib/systemd/system/docker.service to:
ExecStart=/usr/bin/docker daemon -H fd:// --ipv6 --fixed-cidr-v6="${IPV6_SUBNET}:1::/80"

systemctl daemon-reload && \
  systemctl docker restart


# verify IPv6 configuration inside Docker containers
docker run -it ubuntu bash -c "ip -6 addr show dev eth0; ip -6 route show"

# test (this will fail)
docker run -it ubuntu bash -c "ping6 google.com"
```

However, if we NAT all IPv6 traffic from this host using `eth0`, communication will be allowed:
```
# NAT all IPv6 traffic behind eth0
ip6tables -t nat -A POSTROUTING -o eth0  -j MASQUERADE

# test (this will succeed)
docker run -it ubuntu bash -c "ping6 google.com"
```


### Further Work
This solution is meant to be a quick and dirty (but functional) method of bypassing geo-restrictions for various services. While it is (at least in theory) called a `smart DNS proxy`, the only `smart` bit is in the `zones.override` file, which tells the system which domains to proxy and which to pass through. You could easilly turn this into a `dumb/transparent DNS proxy`, by replacing the contents of `zones.override` with a simple[n4] statement:

    zone "." {
        type master;
        file "/data/conf/db.override";
    };

This will in effect proxy every request that ends up on your VPS if you set your VPS IP as your main and only DNS server at home. This will unfortunately invalidate the original purpose of this project. Ideally, what you really want to do, is to have some form of DNS proxy at home, which selectively sends DNS requests to your VPS only for the domains you care about (i.e. netflix.com) and leaves everything else going out to your ISP DNS server(s). [Dnsmasq](https://en.wikipedia.org/wiki/Dnsmasq) could be used to achieve this, in combination, perhaps, with a small Linux device like Raspberry Pi or a router which can run OpenWRT.

There is a [similar](https://github.com/trick77/dockerflix) project to this, which automates the Dnsmasq configuration.

If your client is running OS X, you can skip dnsmasq and simply redirect all DNS requests for e.g. `netflix.com` to your VPS IP by creating a file at `/etc/resolver/netflix.com` with these contents:

    nameserver xxx.yyy.zzz.ttt

replacing `xxx.yyy.zzz.ttt` with your VPS IP, of course.

### Contributing
If you have any idea, feel free to fork it and submit your changes back to me.

### Donate
If you find this useful, please feel free to make a small donation with [PayPal](https://www.paypal.me/belodetech) or Bitcoin.

| Paypal | Bitcoin |
| ------ | ------- |
|<center>[![](https://www.paypalobjects.com/en_GB/i/btn/btn_donateCC_LG.gif)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=5UUCDR8YXWERQ)</center>|<center>![91c446adbd54ef84eef1c6c1c723586aa0ba85d7](https://raw.githubusercontent.com/ab77/netflix-proxy/master/static/bitcoin_qr.png)<br />91c446adbd54ef84eef1c6c1c723586aa0ba85d7</center>|

[![ab1](https://avatars2.githubusercontent.com/u/2033996?v=3&s=96)](http://ab77.github.io/)

#### Footnotes
[n1] https://github.com/dlundquist/sniproxy by Dustin Lundquist `dustin@null-ptr.net`

[n2] `Hulu` is heavily geo-restricted from most non-residential IP ranges and doesn't support IPv6.

[n3] You can now specify your home/office/etc. IP manually using `-c <ip>` option to `build.sh`.

[n4] See, serverfault [post](http://serverfault.com/questions/396958/configure-dns-server-to-return-same-ip-for-all-domains).

[n5] See, this [issue](https://github.com/ab77/netflix-proxy/issues/42#issuecomment-152128091).

[n6] If you have a working IPv6 stack, then your device may be preferring it over IPv4, see this [issue](https://forums.he.net/index.php?topic=3056).

[n7] See, https://en.wikipedia.org/wiki/Server_Name_Indication.

[n8] See, https://www.reddit.com/r/VPN/comments/48v03v/netflix_begins_geo_checks_on_cdn/.

[n9] See, [Using NDP proxying](https://docs.docker.com/engine/userguide/networking/default_network/ipv6/). Both the caching resolver and Docker dual-stack support are disabled by default due to differences in IPv6 configurations provided by various hosting providers (i.e. RamNode).

[n10] See, http://www.webhostingtalk.com/showthread.php?t=1262537&p=9157381#post9157381.

[n11] See, [https://www.facebook.com/GetflixAU/posts/650132888457824](https://www.facebook.com/GetflixAU/posts/650132888457824), [Netflix Geoblocking - Part 2](http://forums.whirlpool.net.au/forum-replies.cfm?t=2508180#r5) and read [How Netflix is blocking VPNs](http://www.techcentral.co.za/how-netflix-is-blocking-vpns/63882/) and [Wiki](https://github.com/ab77/netflix-proxy/wiki/On-how-Netflix-enforces-geographical-boundaries-in-the-Information-Age..).

[n12] [Bypass Netflix Geoblocks with IPv6](https://www.ubermotive.com/?p=344).

[n13] See, [IPv6 on Amazon AWS EC2](http://blog.iphoting.com/blog/2012/06/02/ipv6-on-amazon-aws-ec2/).

[n14] If Netflix still thinks you are in a wrong country, try a different tunnel server (e.g. in a US location).

```
-- v2.4
```
