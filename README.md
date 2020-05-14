[![Build Status](https://travis-ci.org/ab77/netflix-proxy.svg?branch=master)](https://travis-ci.org/ab77/netflix-proxy) [![Docker Pulls](https://img.shields.io/docker/pulls/ab77/sniproxy.svg?maxAge=2592000)](https://hub.docker.com/r/ab77/sniproxy/) [![Docker Stars](https://img.shields.io/docker/stars/ab77/sniproxy.svg?maxAge=2592000)](https://hub.docker.com/r/ab77/sniproxy/)

> `TL;DR`

find a (recent)[n19](https://github.com/ab77/netflix-proxy#footnotes) Debian or Ubuntu box with root on a clean public IP and run:

    apt-get update\
	  && apt-get -y install vim dnsutils curl sudo\
	  && curl -fsSL https://get.docker.com/ | sh || apt-get -y install docker.io\
	  && mkdir -p ~/netflix-proxy\
	  && cd ~/netflix-proxy\
	  && curl -fsSL https://github.com/ab77/netflix-proxy/archive/latest.tar.gz | gunzip - | tar x --strip-components=1\
	  && ./build.sh

See the [**Wiki**](https://github.com/ab77/netflix-proxy/wiki) page(s) for some common troubleshooting ideas.

... or subscribe to [Unzoner](http://unzoner.com) VPN service to un-block:

<a href="https://dashboard.unzoner.com/sub"><img align="left" src="https://api.unzoner.com/api/v1.0/countries/available/flags.png"></a><br><br>

# about
`netflix-proxy` is a smart DNS proxy to stream `Netflix`, `Hulu`[[n2]](#footnotes), `HBO Now` and others out of region. It is deployed using Docker containers and uses `dnsmasq`[[n18]](#footnotes) and `sniproxy`[[n1]](#footnotes) to provide SmartDNS services. It works for some blocked sites, such as [PornHub](http://www.pornhub.com/) and [YouTube](https://en.wikipedia.org/wiki/Blocking_of_YouTube_videos_in_Germany). [Subscribe](http://eepurl.com/cb4rUv) to the mailing list and be notified of new features, updates, etc.

# supported services
The following are supported out of the box, however adding additional services is trivial and is done by updating `dnsmasq.conf` file and running `docker restart dnsmasq`:
* Netflix
* Hulu[[n2]](#footnotes)
* HBO Now
* Amazon Instant Video
* Crackle
* Pandora
* Vudu
* blinkbox
* BBC iPlayer[[n5]](#footnotes)
* NBC Sports and potentially many [more](https://github.com/ab77/netflix-proxy/blob/master/proxy-domains.txt)

# license
This project is **free**, covered by the [MIT License](https://github.com/ab77/netflix-proxy/blob/master/LICENSE.md). It is provided without any warranty and can be used for any purpose, including private and commercial. However, if you are planning to use it for commercial purposes (i.e make money off it), please do not expect free support, as it would be unfair. A commercial support model can always be negotiated, if required. Please [contact](https://www.upwork.com/freelancers/~016da2a2dc195af5ec) me if this is something that interests you.

# instructions
The following paragraphs show how to get this solution up and running with a few different Cloud providers I've tried so far. If you prefer a video tutorial, [here](https://www.youtube.com/watch?v=8DrNgnq_cdM) is one prapared by one of the users. Note, OpenVZ **won't work**[[n15]](#footnotes), make sure to get a proper virtual machine using KVM or Xen.

[![](https://raw.githubusercontent.com/ab77/netflix-proxy/master/static/digitalocean.png)](https://m.do.co/c/937b01397c94)

(Netflix is **blocked**[[n16]](#footnotes)) The following is based on a standard Ubuntu Docker image provided by `DigitalOcean`, but should in theory work on any Linux distribution **with** Docker pre-installed.

1. Head over to [Digital Ocean](https://m.do.co/c/937b01397c94) to get **$10 USD credit**
2. Create a Droplet in a geographic location of interest using the latest Docker image (find in under `One-click Apps` tab).
3. SSH to your server and run:

```
mkdir -p ~/netflix-proxy\
  && cd ~/netflix-proxy\
  && curl -fsSL https://github.com/ab77/netflix-proxy/archive/latest.tar.gz | gunzip - | tar x --strip-components=1\
  && ./build.sh
```

4. Make sure to **record the URL and credentials** for the `netflix-proxy` admin site.
5. Set your DNS server to the IP given at the end of the script, then go to [this](http://ifconfig.co/) site to make sure the same IP is displayed.
6. Finally, enjoy `Netflix` and others out of region.
7. Enjoy or try `#netflix-proxy` on [freenode](https://webchat.freenode.net/?channels=netflix-proxy) for help.

### authorising additional IPs
If you want to share your system with friends and family, you can authorise their home IP address(s) using the `netflix-proxy` admin site, located at `http://<ipaddr>:8080/`, where `ipaddr` is the public IP address of your VPS. Login using `admin` account with the password you recorded during the build. If you've forgotten your admin credentials, [reset](https://github.com/ab77/netflix-proxy/wiki/Changing-Admin-Password-For-Auth-Version).

[![](https://raw.githubusercontent.com/ab77/netflix-proxy/master/static/admin.png)](https://raw.githubusercontent.com/ab77/netflix-proxy/master/static/admin.png)

The `admin` account does not restrict the entry or removal of IPs. If you want to restrict the entry of IPs to the current client IP using an automatically populated drop-down, create a standard user account using the `account-creator.sh` script located in the `auth` directory, which will prompt you for the input and create the user account.

#### dynamic IPs
You can also use the `netflix-proxy` admin site to update your IP address, should your ISP assign you a new one (e.g. via DHCP). If your IP address does change, all HTTP/HTTPS requests will automatically be redirected to the admin site on port `8080`. All DNS requests will be redirected to `dnsmasq` instance running on port `5353`. You will most likely need to purge your browser and system DNS caches after this. On Windows, run `ipconfig /flushdns`. On OS X, run:

```
sudo killall -HUP mDNSResponder\
 && sudo dscacheutil -flushcache`
```

Then restart the browser (e.g `chrome://restart`) and/or reboot the relevant devices. This mechanism should work on browsers, but will most likely cause errors on other devices, such as Apple TVs and smart TVs. If you Internet stops working all of a sudden, try loading a browser and going to `netflix.com`.

#### scripted authorization of IPs
* to automatically authorise client IP using a script (where `ipaddr` is the public IP address of your VPS), substitute admin credentials and run:

```
curl -L http://<ipaddr>:8080/autoadd?username=<admin-username>&password=<admin-password>
```

* to manually authorise a specific IP, substitute admin credentials and run:

```
curl -L http://<ipaddr>:8080/autoadd?ip=<your-public-ipaddr>&username=<admin-username>&password=<admin-password>
```

#### automatic IP authorization
**WARNING**: do not do enable this unless you know what you are doing.

To enable automatic authorization of every IP that hits your proxy, set `AUTO_AUTH = True` in `auth/settings.py` and run `service netflix-proxy-admin restart`. This setting will effectively authorize any IP hitting your proxy IP with a web browser for the first time, including bots, hackers, spammers, etc. Upon successful authorization, the browser will be redirected to [Google](http://google.com/).

The DNS service is configured with recursion turned on by [default](https://github.com/ab77/netflix-proxy#security), so after a successful authorization, anyone can use your VPS in DNS amplification attacks, which will probably put you in breach of contract with the VPS provider. You have been **WARNED**.

### security
The build script automatically configures the system with **DNS recursion turned on**. This has security implications, since it potentially opens your DNS server to a DNS amplification attack, a kind of a [DDoS attack](https://en.wikipedia.org/wiki/Denial-of-service_attack). This should not be a concern however, as long as the `iptables` firewall rules configured automatically by the build script for you remain in place. However if you ever decide to turn the firewall off, please be aware of this.

### command line options
The following command line options can be optionaly passed to `build.sh` for additional control:

```
Usage: ./build.sh [-b 0|1] [-c <ip>]
        -b      grab docker images from repository (0) or build locally (1) (default: 0)
        -c      specify client-ip instead of being taken from ssh_connection
```

### updates
In order to update your existing database schema, please run the provided `update.sh` script. Alternatively you can run the schema updates manually (e.g. if you skipped a version).

## other cloud providers

### locale issues

The build script has been designed to work on Ubuntu and Debian. It will most likely fail on all other distributions. Some pre-requisites require the locale to be set correctly and some provider OS images need extra help. If you get `locale` issues reported by `Python` and/or `pip` during the build, try running the following first:

```
export LANGUAGE=en_US.UTF-8\
  && export LANG=en_US.UTF-8\
  && export LC_ALL=en_US.UTF-8\
  && export LC_CTYPE="en_US.UTF-8"\
  && locale-gen en_US.UTF-8\
  && sudo apt-get -y install language-pack-en-base\
  && sudo dpkg-reconfigure locales
```

[![](https://raw.githubusercontent.com/ab77/netflix-proxy/master/static/vultr.png)](http://www.vultr.com/?ref=6871746)

(Netflix is **blocked**[[n16]](#footnotes)) The following is based on a Debian image provided by `Vultr`, but should in theory work on any Debian distribution.

1. For a limited time, head over to [Vultr](http://www.vultr.com/?ref=6962933-3B) to create and account and get **$20 USD credit**.
2. Create a compute instance in a geographic location of interest using Debian or Ubuntu image.
3. SSH to your server and run:

```
apt-get update\
  && apt-get -y install vim dnsutils curl sudo\
  && curl -fsSL https://get.docker.com/ | sh || apt-get -y install docker.io\
  && mkdir -p ~/netflix-proxy\
  && cd ~/netflix-proxy\
  && curl -fsSL https://github.com/ab77/netflix-proxy/archive/latest.tar.gz | gunzip - | tar x --strip-components=1\
  && ./build.sh
```

4. Make sure to **record the credentials** for the `netflix-proxy` admin site.
5. Set your DNS server to the IP given at the end of the script, then go to [this](http://ifconfig.co/) site to make sure the same IP is displayed.
6. Finally, enjoy `Netflix` and others out of region.
7. Enjoy or try `#netflix-proxy` on [freenode](https://webchat.freenode.net/?channels=netflix-proxy) for help.

[![](https://raw.githubusercontent.com/ab77/netflix-proxy/master/static/kamatera.png)](https://www.kamatera.com/express/compute/?tcampaign=antonbelodedenko&HT=17)

(Netflix is **blocked**[[n16]](#footnotes)) The following is based on a standard Ubuntu image provided by `Kamatera`.

1. Head over to [Kamatera](https://www.kamatera.com/express/compute/?tcampaign=antonbelodedenko&HT=17) to start your **30 Day Free Trial**.
2. Create a new server in a geographic location of interest using Ubuntu or Debian image.
3. SSH to your server and run:

```
apt-get update\
  && apt-get -y install vim dnsutils curl sudo\
  && curl -fsSL https://get.docker.com/ | sh || apt-get -y install docker.io\
  && mkdir -p ~/netflix-proxy\
  && cd ~/netflix-proxy\
  && curl -fsSL https://github.com/ab77/netflix-proxy/archive/latest.tar.gz | gunzip - | tar x --strip-components=1\
  | tar x --strip-components=1\
  && ./build.sh
```

4. Make sure to **record the URL and credentials** for the `netflix-proxy` admin site.
5. Set your DNS server to the IP given at the end of the script, then go to [this](http://ifconfig.co/) site to make sure the same IP is displayed.
6. Finally, enjoy `Netflix` and others out of region.
7. Enjoy or try `#netflix-proxy` on [freenode](https://webchat.freenode.net/?channels=netflix-proxy) for help.

[![](http://www.ramnode.com/images/banners/affbannerdarknewlogo.png)](https://clientarea.ramnode.com/aff.php?aff=3079)

(Netflix is blocked[[n16]](#footnotes)) The following is based on a Debian or Ubuntu images provided by `RamNode`.

1. Head over to [RamNode](https://clientarea.ramnode.com/aff.php?aff=3079) to create an account and buy a **KVM** VPS in a geographic location of interest (OpenVZ won't work).
2. Log into the `VPS Control Panel` and (re)install the OS using Ubuntu or Debian image.
3. SSH to your server and run:

```
apt-get update\
  && apt-get -y install vim dnsutils curl sudo\
  && curl -fsSL https://get.docker.com/ | sh || apt-get -y install docker.io\
  && mkdir -p ~/netflix-proxy\
  && cd ~/netflix-proxy\
  && curl -fsSL https://github.com/ab77/netflix-proxy/archive/latest.tar.gz | gunzip - | tar x --strip-components=1\
  && ./build.sh
```

4. Make sure to **record the credentials** for the `netflix-proxy` admin site.
5. Set your DNS server to the IP given at the end of the script, then go to [this](http://ifconfig.co/) site to make sure the same IP is displayed.
6. Finally, enjoy `Netflix` and others out of region.
7. Enjoy or try `#netflix-proxy` on [freenode](https://webchat.freenode.net/?channels=netflix-proxy) for help.

[![](https://www.linode.com/media/images/logos/standard/light/linode-logo_standard_light_small.png)](https://www.linode.com/?r=ceb35af7bad520f1e2f4232b3b4d49136dcfe9d9)

(Netflix is **blocked**[[n16]](#footnotes)) The following is based on a standard Ubuntu image provided by `Linode`, but should work on any Linux distribution **without** Docker installed.

1. Head over to [Linode](https://www.linode.com/?r=ceb35af7bad520f1e2f4232b3b4d49136dcfe9d9) and sign-up for an account.
2. Create a new `Linode` in a geographic location of interest and deploy an Ubuntu image into it.
3. SSH to your server and run:

```
apt-get update\
  && apt-get -y install vim dnsutils curl sudo\
  && curl -fsSL https://get.docker.com/ | sh || apt-get -y install docker.io\
  && mkdir -p ~/netflix-proxy\
  && cd ~/netflix-proxy\
  && curl -fsSL https://github.com/ab77/netflix-proxy/archive/latest.tar.gz | gunzip - | tar x --strip-components=1\
  && ./build.sh
```

4. Make sure to **record the credentials** for the `netflix-proxy` admin site.
5. Set your DNS server to the IP given at the end of the script, then go to [this](http://ifconfig.co/) site to make sure the same IP is displayed.
6. Finally, enjoy `Netflix` and others out of region.
7. Enjoy or try `#netflix-proxy` on [freenode](https://webchat.freenode.net/?channels=netflix-proxy) for help.

[![](https://raw.githubusercontent.com/ab77/netflix-proxy/master/static/dreamhost.png)](http://www.dreamhost.com/r.cgi?2124700)

**(untested)** The following is based on a standard Ubuntu image provided by `DreamHost`, but should work on any Linux distribution **without** Docker installed and running under **non-root** user (e.g. `Amazon Web Services`[[n13]](#footnotes)).

1. Head over to [DreamHost](http://www.dreamhost.com/r.cgi?2124700) and sign-up for an account.
2. Find the `DreamCompute` or `Public Cloud Computing` section and launch an Ubuntu instance in a geographic location of interest.
3. Make sure to add an additional firewall rule to allow DNS: `Ingress - IPv4 - UDP - 53 - 0.0.0.0/0 (CIDR)`
4. Also add a `Floating IP` to your instance.
5. SSH to your server and run:

```
sudo apt-get update\
  && sudo apt-get -y install vim dnsutils curl\
  && curl -fsSL https://get.docker.com/ | sh || apt-get -y install docker.io\
  && sudo usermod -aG docker $(whoami | awk '{print $1}')\
  && mkdir -p ~/netflix-proxy\
  && cd ~/netflix-proxy\
  && curl -fsSL https://github.com/ab77/netflix-proxy/archive/latest.tar.gz | gunzip - | tar x --strip-components=1\
  && ./build.sh
```

6. Make sure to **record the credentials** for the `netflix-proxy` admin site.
7. Set your DNS server to the IP given at the end of the script, then go to [this](http://ifconfig.co/) site to make sure the same IP is displayed.
8. Finally, enjoy `Netflix` and others out of region.
9. Enjoy or try `#netflix-proxy` on [freenode](https://webchat.freenode.net/?channels=netflix-proxy) for help.

[![](https://raw.githubusercontent.com/ab77/netflix-proxy/master/static/gandi.png)](https://www.gandi.net/hosting/iaas/buy)

The following is based on Ubuntu image provided by `Gandi` using` root` login with SSH key only (no password). For default non-root `admin` login, adjust step 6 to use `sudo` where nesessary.

1. Head over to [Gandi](https://www.gandi.net/hosting/iaas/buy) to create a virtual server in a geographic location of interest.
2. SSH to your server and run:

```
apt-get update\
  && apt-get -y install vim dnsutils curl sudo\
  && curl -fsSL https://get.docker.com/ | sh || apt-get -y install docker.io\
  && mkdir -p ~/netflix-proxy\
  && cd ~/netflix-proxy\
  && curl -fsSL https://github.com/ab77/netflix-proxy/archive/latest.tar.gz | gunzip - | tar x --strip-components=1\
  && ./build.sh
```

3. Make sure to **record the credentials** for the `netflix-proxy` admin site.
4. Set your DNS server to the IP given at the end of the script, then go to [this](http://ifconfig.co/) site to make sure the same IP is displayed.
5. Finally, enjoy `Netflix` and others out of region.
6. Enjoy or try `#netflix-proxy` on [freenode](https://webchat.freenode.net/?channels=netflix-proxy) for help.

### Microsoft Azure (advanced)
The following **has not been tested** and is based on a standard Ubuntu image provided by `Microsoft Azure` using `cloud-harness` automation tool I wrote a while back and assumes an empty `Microsoft Azure` subscription. Also, because Azure [block ICMP](https://blogs.msdn.microsoft.com/mast/2014/06/22/use-port-pings-instead-of-icmp-to-test-azure-vm-connectivity/) thorough the load-balancer and don't offer native IPv6 support, IPv6 isn't going to work.

1. Head over to [Microsoft Azure](https://azure.microsoft.com/en-gb/) and sign-up for an account.
2. Get [Python](https://www.python.org/downloads/).
3. On your workstation, run `git clone https://github.com/ab77/cloud-harness.git ~/cloud-harness`.
4. Follow `cloud-harness` [Installation and Configuration](https://github.com/ab77/cloud-harness#installation-and-configuration) section to set it up.
5. [Create](https://github.com/ab77/cloud-harness#create-storage-account-name-must-be-unique-as-it-forms-part-of-the-storage-url-check-with---action-check_storage_account_name_availability) a storage account.
6. [Create](https://github.com/ab77/cloud-harness#create-a-new-hosted-service-name-must-be-unique-within-cloudappnet-domain-check-with---action-check_storage_account_name_availability) a new hosted service.
7. [Add](https://github.com/ab77/cloud-harness#add-x509-certificate-containing-rsa-public-key-for-ssh-authentication-to-the-hosted-service) a hosted service certificate for SSH public key authentication
8. [Create](https://github.com/ab77/cloud-harness#create-a-reserved-ip-address-for-the-hosted-service) a reserved ip address.
9. [Create](https://github.com/ab77/cloud-harness#create-virtual-network) a virtual network.
10. [Create](https://github.com/ab77/cloud-harness#create-a-new-linux-virtual-machine-deployment-and-role-with-reserved-ip-ssh-authentication-and-customscript-resource-extensionn3) a Ubuntu virtual machine as follows:

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

### automated tests

#### test build
This project is linked with `Travis CI` to deploy and test the project automatically. The Python script `testbuild.py` is used to deploy and test `netflix-proxy`. This script deploys a test `Droplet` and then runs a serious of tests to verify (a) that all `Docker` containers start; (b) the `built.sh` script outputs the correct message at the end; (c) all the relevant services survive a reboot; and (d) proxy is able to comunicate with Netflix over SSL.

The `testbuild.py` script can also be used to programatically deploy `Droplets` from the command line:

```
usage: testbuild.py digitalocean [-h] --api_token API_TOKEN
                                 [--client_ip CLIENT_IP]
                                 [--fingerprint FINGERPRINT [FINGERPRINT ...]]
                                 [--region REGION] [--branch BRANCH]
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
  --create              Create droplet
  --destroy             Destroy droplet
  --list_regions        list all available regions
  --name NAME           Droplet name
```

Note, you will need a working `Python 2.7` environment and the modules listed in `tests/requirements.txt` (run `pip install -r tests/requirements.txt`).

#### test video playback
Video playback tests are **currently disabled** due to provider blocking.

##### Netflix
After a successful build deployment, `testvideo.py` is executed to test Netflix video playback. This is done by playing back 60 seconds of a title known to only be available in the US region (e.g. [1,000 Times Good Night](https://www.netflix.com/title/80001898)).

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

A screenshot is saved at the end of the test and uploaded to the `gh-pages` branch.

![Netflix VideoPlaybackTest screenshot](https://raw.githubusercontent.com/ab77/netflix-proxy/gh-pages/artifacts/VideoPlaybackTestNflx.png)

##### Hulu
Similarly, `testvideo.py` is executed to test Hulu video playback using one of the free titles (e.g. [South Park S01E01: Cartman Gets an Anal Probe](http://www.hulu.com/watch/249837)). The build is configured not to fail in the event of Hulu test failing. This is because Hulu is almost cetrtainly blocked from Digital Ocean.

![Hulu VideoPlaybackTest screenshot](https://raw.githubusercontent.com/ab77/netflix-proxy/gh-pages/artifacts/waitForPlayer.png)

### IPv6
This solution uses IPv6 downstream from the proxy to unblock IPv6 enabled providers, such as Netflix. No IPv6 support on the client is required for this to work, only the VPS must have public IPv6 connectivity. You may also need to turn off IPv6 on your local network (and/or relevant devices).[[n6]](#footnotes)

```
+----------+                  +-----------+                 +-----------------+
|          |                  |           |                 |                 |
|  client  | +--------------> |   proxy   | +-------------> |  Netflix, etc.  |
|          |      (ipv4)      |           |      (ipv6)     |                 |
+----------+                  +-----------+                 +-----------------+
```

### contributing
If you have any idea, feel free to fork it and submit your changes back to me.

### donate
If you find this useful, please feel free to make a small donation with [PayPal](https://www.paypal.me/belodetech) or Bitcoin.

| Paypal | Bitcoin |
| ------ | ------- |
|[![](https://www.paypalobjects.com/en_GB/i/btn/btn_donateCC_LG.gif)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=5UUCDR8YXWERQ)|![1GUrKgkaCkdsrCzb4pq3bJwkmjTVv9X7eG](https://raw.githubusercontent.com/ab77/netflix-proxy/master/static/bitcoin_qr.png)1GUrKgkaCkdsrCzb4pq3bJwkmjTVv9X7eG|

#### footnotes
1. [SNIProxy](https://github.com/dlundquist/sniproxy) by Dustin Lundquist `dustin@null-ptr.net`; this solution will only on devices supporting Server Name Indication (SNI)[[n7]](#footnotes) and only if they use DNS to resolve names.
2. `Hulu` is heavily geo-restricted from most non-residential IP ranges and doesn't support IPv6.
3. You can now specify your home/office/etc. IP manually using `-c <ip>` option to `build.sh`.
4. See, serverfault [post](http://serverfault.com/questions/396958/configure-dns-server-to-return-same-ip-for-all-domains).
5. See, [this](https://daniel.haxx.se/blog/2016/08/18/http2-connection-coalescing/) and [this](https://github.com/dlundquist/sniproxy/issues/178). The following [four](https://github.com/ab77/netflix-proxy/blob/master/proxy-domains.txt#L66-L69) hosts all need to resolve to different public IPs.
6. If you have a working IPv6 stack, then your device may be preferring it over IPv4, see this [issue](https://forums.he.net/index.php?topic=3056).
7. See, [article](https://en.wikipedia.org/wiki/Server_Name_Indication).
8. See, [post](https://www.reddit.com/r/VPN/comments/48v03v/netflix_begins_geo_checks_on_cdn/).
9. See, [Using NDP proxying](https://docs.docker.com/engine/userguide/networking/default_network/ipv6/). Both the caching resolver and Docker dual-stack support are disabled by default due to differences in IPv6 configurations provided by various hosting providers (i.e. RamNode).
10. See, [post](http://www.webhostingtalk.com/showthread.php?t=1262537&p=9157381#post9157381).
11. See, [https://www.facebook.com/GetflixAU/posts/650132888457824](https://www.facebook.com/GetflixAU/posts/650132888457824), [Netflix Geoblocking - Part 2](http://forums.whirlpool.net.au/forum-replies.cfm?t=2508180#r5) and read [How Netflix is blocking VPNs](http://www.techcentral.co.za/how-netflix-is-blocking-vpns/63882/) and [Wiki](https://github.com/ab77/netflix-proxy/wiki/On-how-Netflix-enforces-geographical-boundaries-in-the-Information-Age..).
12. [Bypass Netflix Geoblocks with IPv6](https://www.ubermotive.com/?p=344).
13. See, [IPv6 on Amazon AWS EC2](http://blog.iphoting.com/blog/2012/06/02/ipv6-on-amazon-aws-ec2/).
14. If Netflix still thinks you are in a wrong country, try a different tunnel server (e.g. in a US location).
15. See, [article](https://openvz.org/Docker_inside_CT).
16. Netflix have most definitely blocked this service provider network ranges, so following the process is unlikely to yield an unblocking solution. If you own a compatible device, you could try `black.box` [unzoner](http://unzoner.com).
17. GFW is probably re-writing DNS responses for certain very sensitive domains (i.e. facebook.com), so unfortunately a simple proxy solution like this won't work. VPN technology is required to bypass, try `black.box` [unzoner](http://unzoner.com).
18. [dnsmasq](http://www.thekelleys.org.uk/dnsmasq/doc.html) by `simon@thekelleys.org.uk`.
19. Python3 (latest) release won't work on Ubuntu16/Debian9, use Python2 release or (recommended) upgrade to a more recent distribution.

<hr>
<p align="center">&copy; 2016-2019 <a href="http://ab77.github.io/">ab1</a></p>
<p align="center"><a href="http://anton.belodedenko.me/"><img src="https://avatars2.githubusercontent.com/u/2033996?v=3&s=50"></a></p>
