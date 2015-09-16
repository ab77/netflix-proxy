# netflix-proxy [![Build Status](https://travis-ci.org/ab77/netflix-proxy.svg?branch=master)](https://travis-ci.org/ab77/netflix-proxy)
`Docker` packaged smart DNS proxy to watch `Netflix`, `Hulu`[n2], `HBO Now` and others out of region using `BIND` and `sniproxy`[n1].

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
* NBC Sports and potentially many more

# Instructions
The following paragraphs show how to get this solution up and running with a few different Cloud providers I've tried so far.

## DigitalOcean
The following is based on a standard Ubuntu Docker image provided by `DigitalOcean`, but should in theory work on any Linux distribution **with** Docker pre-installed.

1. Head over to [Digital Ocean](https://www.digitalocean.com/?refcode=937b01397c94) to get **$10 USD credit**
2. Create a `Droplet` using `Docker 1.x` on `Ubuntu 14.04` (find in under Applications images).
3. Make sure you create the `Droplet` in the right region, for example if you want to watch US content, create in the US.
4. SSH to your `Droplet` and run: `git clone https://github.com/ab77/netflix-proxy /opt/netflix-proxy && cd /opt/netflix-proxy && ./build.sh`
5. Point your DNS at the Droplet IP and watch `Netflix`, `Hulu` and `HBO Now` out of region.
6. Enjoy or raise a new [issue](https://github.com/ab77/netflix-proxy/issues/new) if something doesn't work quite right..

### Authorising Additional IPs
If you want to share your system with friends and family, you can authorise their home IP address(s) as follows (where `x.x.x.x` is the IP address) by running:

    sudo iptables -I FRIENDS -s x.x.x.x/32 -j ACCEPT
    iptables-save > /etc/iptables/rules.v4 || iptables-save > /etc/iptables.rules

To remove previous authorised IP address, run:

    sudo iptables -D FRIENDS -s x.x.x.x/32 -j ACCEPT
    iptables-save > /etc/iptables/rules.v4 || iptables-save > /etc/iptables.rules

### Security
The build script automatically configures the system with **DNS recursion turned on**. This has security implications, since it potentially opens your DNS server to a DNS amplification attack, a kind of a [DDoS attack](https://en.wikipedia.org/wiki/Denial-of-service_attack). This should not be a concern however, as long as the `iptables` firewall rules configured automatically by the build script for you remain in place. However if you ever decide to turn the firewall off, please be aware of this.

If you want to turn DNS recursion off, please be aware that you will need a mechanism to selectively send DNS requests for domains your DNS server knows about (i.e. netflix.com) to your VPS and send all of the other DNS traffic to your local ISP's DNS server. Something like [Dnsmasq](http://www.thekelleys.org.uk/dnsmasq/doc.html) can be used for this and some Internet routers even have it built in. In order to switch DNS recursion off, you will need to build your system using the following command:

`git clone https://github.com/ab77/netflix-proxy /opt/netflix-proxy && cd /opt/netflix-proxy && ./build.sh -r 0 -b 1`

### Command Line Options
The following command line options can be optionaly passed to `build.sh` for additional control:

    Usage: ./build.sh [-r 0|1] [-b 0|1] [-c <ip>]
        -r      enable (1) or disable (0) DNS recursion (default: 1)
        -b      grab docker images from repository (0) or build locally (1) (default: 0)
        -c      specify client-ip instead of being taken from ssh_connection[n3]

## Other Cloud Providers

### Linode
The following is based on a standard Ubuntu image provided by `Linode`, but should work on any Linux distribution **without** Docker installed.

1. Head over to [Linode](https://www.linode.com/?r=ceb35af7bad520f1e2f4232b3b4d49136dcfe9d9) and sign-up for an account.
2. Create a new `Linode` and deploy an `Ubuntu 14-04 LTS` image into it.
3. Make sure you create the Linode in the right location, as there a few to pick from.
4. SSH to your `Linode` and run the following command: `curl -sSL https://get.docker.com/ | sh && git clone https://github.com/ab77/netflix-proxy /opt/netflix-proxy && cd /opt/netflix-proxy && ./build.sh`
5. Point your DNS at the `Linode` IP and watch `Netflix`, `Hulu` and/or `HBO Now` out of region.
6. Binge. Not that there is anything wrong with that or raise a new [issue](https://github.com/ab77/netflix-proxy/issues/new) if something doesn't work quite right..

### DreamCompute by DreamHost
The following is based on a standard Ubuntu image provided by `DreamHost`, but should work on any Linux distribution **without** Docker installed and running under **non-root** user.

1. Head over to [DreamHost]( http://www.dreamhost.com/r.cgi?2124700) and sign-up for an account.
2. Find the `DreamCompute` or `Public Cloud Computing` section and launch an `Ubuntu 14-04-Trusty` instance.
3. Make sure to add an additional firewall rule to allow DNS: `Ingress	IPv4	UDP	53	0.0.0.0/0 (CIDR)`
4. Also add a `Floating IP` to your instance, otherwise it will only have an IPv6 IP.
5. SSH to your instance and run the following command: `curl -sSL https://get.docker.com/ | sh && sudo usermod -aG docker $(who am i | awk '{print $1}') && git clone https://github.com/ab77/netflix-proxy /opt/netflix-proxy && cd /opt/netflix-proxy && ./build.sh`
6. Point your DNS at the instance IP and watch `Netflix`, `Hulu` and/or `HBO Now` out of region.
7. Well done, enjoy or raise a new [issue](https://github.com/ab77/netflix-proxy/issues/new) if something doesn't work quite right..


### Continuous Integration (CI)

I've linked this project with `Travis CI` to automatically test the build. The helper Python script `__testbuild.py` now runs automatically after every commit. This script deploys a test `Droplet` and then runs a serious of tests to verify (a) that both `Docker` containers start; and (b) the `built.sh` script outputs the correct message at the end. The test `Droplet` is destroyed and the end of the run.

The `__testbuild.py` script can also be used to programatically deploy `Droplets` from the command line as follows:

	python ./__testbuild.py digitalocean --api_token abcdef0123456789... --fingerprint 'aa:bb:cc:dd:...' --region 'abc1'
	
* `--api_token abcdef0123456789...` is your `DigitalOCean` API v2 token, which you can generate [here](https://cloud.digitalocean.com/settings/applications).
* `--fingerprint aa:bb:cc:dd:...` are your personal SSH key fingerprint(s) quoted and separated by spaces. You can manage your SSH keys [here](https://cloud.digitalocean.com/settings/security). If you don't specify a fingerprint, it will default to my test one, which means you **won't** be able to SSH into your `Droplet`.
* `--region abc1` is the region where you want the `Droplet` deployed. The default is `nyc3`, but you can use `--list_regions` to see the available choices.
* `--help` parameter will also list all of the available command line options to pass to the script.

Note, you will need a working `Python 2.7` environment and the modules listed in `requirements.txt` (run `pip install -r requirements.txt`).


### Further Work
This solution is meant to be a quick and dirty (but functional) method of bypassing geo-restrictions for various services. While it is (at least in theory) called a `smart DNS proxy`, the only `smart` bit is in the `zones.override` file, which tells the system which domains to proxy and which to pass through. You could easilly turn this into a `dumb/transparrent DNS proxy`, by replacing the contents of `zones.override` with a simple[n4] statement:

    zone "." {
        type master;
        file "/data/db.override";
    };

This will in effect proxy every request that ends up on your VPS if you set your VPS IP as your main and only DNS server at home. This will unfortunately invalidate the original purpose of this project. Ideally, what you really want to do, is to have some form of DNS proxy at home, which selectively sends DNS requests to your VPS only for the domains you care about (i.e. netflix.com) and leaves everything else going out to your ISP DNS server(s). [Dnsmasq](https://en.wikipedia.org/wiki/Dnsmasq) could be used to achieve this, in combination, perhaps, with a small Linux device like Raspberry Pi or a router which can run OpenWRT.

There is a [similar](https://github.com/trick77/dockerflix) project to this, which automates the Dnsmasq configuration.

-- [ab1](https://plus.google.com/+AntonBelodedenko?rel=author)

[n1] https://github.com/dlundquist/sniproxy by Dustin Lundquist dustin@null-ptr.net

[n2] At the time of writing (May 2015), `Hulu` appears to be geo-restricted from `DigitalOcean` and `Linode` US IPs, but worked for a short time from a `DreamCompute` IAD DC IP. It also seems to be working from `Amazon EC2` IPs.

[n3] You can now specify your home/office/etc. IP manually using `-c <ip>` option to `build.sh`.

[n4] See, serverfault [post](http://serverfault.com/questions/396958/configure-dns-server-to-return-same-ip-for-all-domains).
