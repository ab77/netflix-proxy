# netflix-proxy [![Build Status](https://travis-ci.org/ab77/netflix-proxy.svg?branch=master)](https://travis-ci.org/ab77/netflix-proxy) [![](https://www.paypalobjects.com/en_GB/i/btn/btn_donate_SM.gif)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=5UUCDR8YXWERQ)
`Docker` packaged smart DNS proxy to watch `Netflix`, `Hulu`[n2], `HBO Now` and others out of region using `BIND` and `sniproxy`[n1]. Works for blocked sites too, such as [PornHub](http://www.pornhub.com/).

This is the [new-auth](https://github.com/ab77/netflix-proxy/tree/new-auth) version, which among other things, adds automatic IP address authorisation via dynamic DNS/HTTP redirect. This version also adds a caching `dnsmasq` DNS resolver behind `sniproxy`, to speed up DNS resolution and improve security[n9] as well as Docker IPv6 dual-stack support. The code will eventually be merged into the [master](https://github.com/ab77/netflix-proxy/tree/master) branch, once it is deemed stable enough.

This solution will only work with devices supporting Server Name Indication (SNI)[n7]. To test, open a web browser on the device you are planning to watch content and go to [this](https://sni.velox.ch/) site (`https://sni.velox.ch/`).

**Update March/2016**: Netflix seems to be testing geo-fencing on their media hosts[n8]. If this is affecting you, add the following block to `/opt/netflix-proxy/data/conf/zones.override` and run `docker restart bind`:

```
zone "nflxvideo.net." {
    type master;
    file "/data/conf/db.override";
};
```

BBC iPlayer seems to be geo-fencing on their CDN hosts. If this is affecting you, add the following block to `/opt/netflix-proxy/data/zones.override` and run `docker restart bind`:

```
zone "bbcfmt.vo.llnwd.net." {
    type master;
    file "/data/db.override";
};
```

Note, this will potentially land you with a large bandwidth bill from your VPS provider as all Netflix and/or BBC iPlayer video will now be running through your VPS. However, since most VPS providers offer 1TB per month inclusive with each server and most home ISPs don't offer anywhere near that amount, it should be a moot point in most situations.

Please see the [**Wiki**](https://github.com/ab77/netflix-proxy/wiki) page(s) for some common troubleshooting ideas.

**Unblocked Netflix?** Great success! [Vote](http://www.poll-maker.com/poll622505x596e406D-26) now and see the [results](http://www.poll-maker.com/results622505xfcC7F6aA-26).

[![](https://raw.githubusercontent.com/ab77/netflix-proxy/new-auth/static/poll_results.png)](http://www.poll-maker.com/results622505xfcC7F6aA-26)

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
* NBC Sports and potentially many [more](https://github.com/ab77/netflix-proxy/blob/new-auth/data/conf/zones.override)

# Instructions
The following paragraphs show how to get this solution up and running with a few different Cloud providers I've tried so far.

[![](https://raw.githubusercontent.com/ab77/netflix-proxy/master/static/digitalocean.png)](https://m.do.co/c/937b01397c94)

The following is based on a standard Ubuntu Docker image provided by `DigitalOcean`, but should in theory work on any Linux distribution **with** Docker pre-installed.

1. Head over to [Digital Ocean](https://m.do.co/c/937b01397c94) to get **$10 USD credit**
2. Create a `Droplet` using `Docker 1.x` on `Ubuntu 14.04` (find in under `One-click Apps` tab).
3. **Make sure to enable `IPv6` support**.
4. Make sure you create the `Droplet` in the right region, for example if you want to watch US content, create in the US.
5. SSH to your `Droplet` and run: `git clone -b new-auth https://github.com/ab77/netflix-proxy /opt/netflix-proxy && cd /opt/netflix-proxy && ./build.sh`
6. Make sure to record the credentials for the `netflix-proxy` admin site.
7. Point your DNS at the Droplet IP, then go to [this](http://ipinfo.io/) site to make sure your Droplet IP is displayed.
8. Finally, watch `Netflix` and others out of region.
9. Enjoy or raise a new [issue](https://github.com/ab77/netflix-proxy/issues/new) if something doesn't work quite right (also `#netflix-proxy` on [freenode](https://webchat.freenode.net/?channels=netflix-proxy)).

### Authorising Additional IPs
If you want to share your system with friends and family, you can authorise their home IP address(s) using the `netflix-proxy` admin site, located at `http://<ipaddr>:8080/`, where `ipaddr` is the public IP address of your VPS. Login using `admin` account with the password you recorded during the build, in step 6.

[![](https://raw.githubusercontent.com/ab77/netflix-proxy/new-auth/static/admin.png)](https://raw.githubusercontent.com/ab77/netflix-proxy/new-auth/static/admin.png)

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
git clone -b new-auth https://github.com/ab77/netflix-proxy /opt/netflix-proxy && cd /opt/netflix-proxy && ./build.sh -r 0 -b 1
```

### Command Line Options
The following command line options can be optionaly passed to `build.sh` for additional control:

    Usage: ./build.sh [-r 0|1] [-b 0|1] [-c <ip>]
        -r      enable (1) or disable (0) DNS recursion (default: 1)
        -b      grab docker images from repository (0) or build locally (1) (default: 0)
        -c      specify client-ip instead of being taken from ssh_connection[n3]

## Other Cloud Providers

[![](https://raw.githubusercontent.com/ab77/netflix-proxy/master/static/vultr.png)](http://www.vultr.com/?ref=6871746)

The following is based on a Debian image provided by `Vultr`, but should in theory work on any Debian distribution.

1. Head over to [Vultr](http://www.vultr.com/?ref=6871746) to create an account.
2. Create a compute instance using `Debian 8 x64 (jessie)` image.
3. **Make sure to enable `IPv6` support**. 
4. Make sure you deploy the server in the right region, for example if you want to watch US content, create in one of the US DCs.
5. SSH to your server and run: `apt-get update && apt-get -y install vim dnsutils curl sudo git && curl -sSL https://get.docker.com/ | sh && git clone -b new-auth https://github.com/ab77/netflix-proxy /opt/netflix-proxy && cd /opt/netflix-proxy && ./build.sh`
7. Make sure to record the credentials for the `netflix-proxy` admin site.
8. Point your DNS at the server IP, then go to [this](http://ipinfo.io/) site to make sure your server IP is displayed.
9. Finally, watch `Netflix` and others out of region.
10. Enjoy or raise a new [issue](https://github.com/ab77/netflix-proxy/issues/new) if something doesn't work quite right (also `#netflix-proxy` on [freenode](https://webchat.freenode.net/?channels=netflix-proxy)).

[![](http://www.ramnode.com/images/banners/affbannerdarknewlogo.png)](https://clientarea.ramnode.com/aff.php?aff=3079)

The following is based on a Debian or Ubuntu OS images provided by `RamNode`.

1. Head over to [RamNode](https://clientarea.ramnode.com/aff.php?aff=3079) to create an account and buy a **KVM** VPS (OpenVZ won't work).
2. Make sure you buy your KVM VPS in the right region, for example if you want to watch US content, select one of the US DCs.
3. Log into the `VPS Control Panel` and (re)install the OS using `Ubuntu 14.04 x86_64 Server Minimal` or `Debian 8.0 x86_64 Minimal` image.
4. SSH to your server and run: `apt-get update && apt-get -y install vim dnsutils curl sudo git && curl -sSL https://get.docker.com/ | sh && git clone -b new-auth https://github.com/ab77/netflix-proxy /opt/netflix-proxy && cd /opt/netflix-proxy && ./build.sh`
5. Make sure to record the credentials for the `netflix-proxy` admin site.
6. Point your DNS at the server IP, then go to [this](http://ipinfo.io/) site to make sure your server IP is displayed.
7. Finally, watch `Netflix` and others out of region.
8. Enjoy or raise a new [issue](https://github.com/ab77/netflix-proxy/issues/new) if something doesn't work quite right (also `#netflix-proxy` on [freenode](https://webchat.freenode.net/?channels=netflix-proxy)).

[![](https://www.linode.com/media/images/logos/standard/light/linode-logo_standard_light_small.png)](https://www.linode.com/?r=ceb35af7bad520f1e2f4232b3b4d49136dcfe9d9)

The following is based on a standard Ubuntu image provided by `Linode`, but should work on any Linux distribution **without** Docker installed.

1. Head over to [Linode](https://www.linode.com/?r=ceb35af7bad520f1e2f4232b3b4d49136dcfe9d9) and sign-up for an account.
2. Create a new `Linode` and deploy an `Ubuntu 14-04 LTS` image into it.
3. **Make sure to enable `IPv6` support (untested)**.
4. Make sure you create the Linode in the right location, as there a few to pick from.
5. SSH to your `Linode` and run the following command: `curl -sSL https://get.docker.com/ | sh && git clone -b new-auth https://github.com/ab77/netflix-proxy /opt/netflix-proxy && cd /opt/netflix-proxy && ./build.sh`
6. Make sure to record the credentials for the `netflix-proxy` admin site.
7. Point your DNS at your Linode IP, then go to [this](http://ipinfo.io/) site to make sure your Linode IP is displayed.
8. Finally, watch `Netflix` and others out of region.
9. Binge. Not that there is anything wrong with that or raise a new [issue](https://github.com/ab77/netflix-proxy/issues/new) if something doesn't work quite right (also `#netflix-proxy` on [freenode](https://webchat.freenode.net/?channels=netflix-proxy)).

[![](https://raw.githubusercontent.com/ab77/netflix-proxy/master/static/dreamhost.png)](http://www.dreamhost.com/r.cgi?2124700)

The following is based on a standard Ubuntu image provided by `DreamHost`, but should work on any Linux distribution **without** Docker installed and running under **non-root** user (e.g. `Amazon Web Services`).

1. Head over to [DreamHost](http://www.dreamhost.com/r.cgi?2124700) and sign-up for an account.
2. Find the `DreamCompute` or `Public Cloud Computing` section and launch an `Ubuntu 14-04-Trusty` instance.
3. **Make sure to enable `IPv6` support (untested)**.
4. Make sure to add an additional firewall rule to allow DNS: `Ingress	IPv4	UDP	53	0.0.0.0/0 (CIDR)`
5. Also add a `Floating IP` to your instance, otherwise it will only have an IPv6 IP.
6. SSH to your instance and run the following command: `curl -sSL https://get.docker.com/ | sh && sudo usermod -aG docker $(whoami | awk '{print $1}') && sudo git clone -b new-auth https://github.com/ab77/netflix-proxy /opt/netflix-proxy && cd /opt/netflix-proxy && ./build.sh`
7. Make sure to record the credentials for the `netflix-proxy` admin site.
8. Point your DNS at the instance IP, then go to [this](http://ipinfo.io/) site to make sure your instance IP is displayed.
9. Finally, watch `Netflix` and others out of region.
10. Well done, enjoy or raise a new [issue](https://github.com/ab77/netflix-proxy/issues/new) if something doesn't work quite right (also `#netflix-proxy` on [freenode](https://webchat.freenode.net/?channels=netflix-proxy)).

[![](https://raw.githubusercontent.com/ab77/netflix-proxy/master/static/gandi.png)](https://www.gandi.net/hosting/iaas/buy)

The following is based on a Debian or Ubuntu OS images provided by `Gandi`.

1. Head over to [Gandi](https://www.gandi.net/hosting/iaas/buy) to create a virtual server.
2. Make sure you buy your server in the right region, for example if you want to watch US content, select the Baltimore DC.
3. SSH to your server and run: `apt-get update && apt-get -y install vim dnsutils curl sudo git && curl -sSL https://get.docker.com/ | sh && git clone -b new-auth https://github.com/ab77/netflix-proxy /opt/netflix-proxy && cd /opt/netflix-proxy && ./build.sh`
4. Make sure to record the credentials for the `netflix-proxy` admin site.
5. Point your DNS at the server IP, then go to [this](http://ipinfo.io/) site to make sure your server IP is displayed.
6. Finally, watch `Netflix`, `Hulu` and others out of region.
7. Enjoy or raise a new [issue](https://github.com/ab77/netflix-proxy/issues/new) if something doesn't work quite right (also `#netflix-proxy` on [freenode](https://webchat.freenode.net/?channels=netflix-proxy)).

### Microsoft Azure
The following is based on a standard `Ubuntu` image provided by `Microsoft Azure` using `cloud-harness` automation tool I wrote a while back and assumes an empty `Microsoft Azure` subscription. Probably a bit more complicated than it should be, but whatever :)

0. First, please see note regarding [IPv6](https://azure.microsoft.com/en-us/pricing/faq/#) support.
1. Then, if you are still interested, head over to [Microsoft Azure](https://azure.microsoft.com/en-gb/) and sign-up for an account.
2. Get [Python](https://www.python.org/downloads/).
3. On your workstation, run `git clone -b new-auth https://github.com/ab77/cloud-harness.git /opt/cloud-harness`.
4. Follow `cloud-harness` [Installation and Configuration](https://github.com/ab77/cloud-harness#installation-and-configuration) section to set it up.
5. [Create](https://github.com/ab77/cloud-harness#create-storage-account-name-must-be-unique-as-it-forms-part-of-the-storage-url-check-with---action-check_storage_account_name_availability) a storage account.
6. [Create](https://github.com/ab77/cloud-harness#create-a-new-hosted-service-name-must-be-unique-within-cloudappnet-domain-check-with---action-check_storage_account_name_availability) a new hosted service.
7. [Add](https://github.com/ab77/cloud-harness#add-x509-certificate-containing-rsa-public-key-for-ssh-authentication-to-the-hosted-service) a hosted service certificate for SSH public key authentication
8. [Create](https://github.com/ab77/cloud-harness#create-a-reserved-ip-address-for-the-hosted-service) a reserved ip address.
9. [Create](https://github.com/ab77/cloud-harness#create-virtual-network) a virtual network.
10. [Create](http://docs.docker.com/engine/articles/https/) Docker certificates and update `[DockerExtension]` section in `cloud-harness.conf`.
11. In `cloud-harness.conf` under `[DockerExtension]` section, set `docker_compose = netflix-proxy.yaml`.

Then, [Create](https://github.com/ab77/cloud-harness#create-a-new-linux-virtual-machine-deployment-and-role-with-reserved-ip-ssh-authentication-and-customscript-resource-extensionn3) a `Ubuntu 14.04 LTS` virtual machine as follows:

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

Next, add the DockerExtension:

    ./cloud-harness.py azure --action add_resource_extension \
    --service <your hosted service name> \
    --deployment <your hosted service name> \
    --name <your virtual machine name> \
    --extension DockerExtension \
    --docker_compose netflix-proxy.yaml \
    --verbose  

Set `linux_customscript_name` under `[CustomScriptExtensionForLinux]` in `cloud-harness.conf` to `netflix-proxy.sh` and run:

    ./cloud-harness.py azure --action add_resource_extension \
    --service netflix-proxy \
    --deployment netflix-proxy \
    --name netflix-proxy \
    --extension CustomScript \
    --verbose  

Once this part finishes, you should be able to SSH to your VM as `azureuser` using custom public TCP port (not `22`) and test the configuration by running:

    dig netflix.com @localhost && echo "GET /" | openssl s_client -servername netflix.com -connect localhost:443

Lastly, use the [Azure Management Portal](https://manage.windowsazure.com/) to add `DNS (UDP)`, `HTTP (TCP)` and `HTTPS (TCP)` endpoints and secure them to your home/work/whatever IPs using the Azure `ACL` feature. This means you don't have to run `iptables` firewall on your VM.

Now you are all set, set DNS server on your device(s) to your Azure public IP and enjoy `Netflix` and don't forget to turn off IPv6.

### Automated Tests

I've linked this project with `Travis CI` to automatically test the build. The helper Python script `__testbuild.py` now runs automatically after every commit. This script deploys a test `Droplet` and then runs a serious of tests to verify (a) that both `Docker` containers start; and (b) the `built.sh` script outputs the correct message at the end. The test `Droplet` is destroyed and the end of the run.

The `__testbuild.py` script can also be used to programatically deploy `Droplets` from the command line as follows:

	python ./__testbuild.py digitalocean --api_token abcdef0123456789... --fingerprint 'aa:bb:cc:dd:...' --region 'abc1'
	
* `--api_token abcdef0123456789...` is your `DigitalOCean` API v2 token, which you can generate [here](https://cloud.digitalocean.com/settings/applications).
* `--fingerprint aa:bb:cc:dd:...` are your personal SSH key fingerprint(s) quoted and separated by spaces. You can manage your SSH keys [here](https://cloud.digitalocean.com/settings/security). If you don't specify a fingerprint, it will default to my test one, which means you **won't** be able to SSH into your `Droplet`.
* `--region abc1` is the region where you want the `Droplet` deployed. The default is `nyc3`, but you can use `--list_regions` to see the available choices.
* `--help` parameter will also list all of the available command line options to pass to the script.

Note, you will need a working `Python 2.7` environment and the modules listed in `requirements.txt` (run `pip install -r requirements.txt`).

### IPv6 and Docker
This solution uses IPv6 downstream from the proxy to unblock IPv6 enabled providers, such as Netflix. No IPv6 support on the client is required for this to work, only the VPS must have IPv6 support enabled, although you may need to turn off IPv6 on your local network (or relevant devices).[n6]

```
+----------+                  +-----------+                 +-----------------+
|          |                  |           |                 |                 |
|  client  | +--------------> |   proxy   | +-------------> |  Netflix, etc.  |
|          |      (ipv4)      |           |      (ipv6)     |                 |
+----------+                  +-----------+                 +-----------------+
```

When IPv6 public address is present on the host, Docker is configured with public IPv6 support. This is done by dividing the small public IPv6 range allocated to the VPS by two and assigning the second half to the Docker system. Network Discovery Protocol (NDP) proxying is required for this to work, since the VPS allocation is usually too small to be properly routed[n]. Afterwards, Docker is running in dual-stack mode, with each container having a public IPv6 address.

If IPv6 is not enabled, the VPS is built with IPv4 support only.

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
[n1] https://github.com/dlundquist/sniproxy by Dustin Lundquist dustin@null-ptr.net

[n2] At the time of writing (May 2015), `Hulu` appears to be geo-restricted from `DigitalOcean` and `Linode` US IPs, but worked for a short time from a `DreamCompute` IAD DC IP. It also seems to be working from `Amazon EC2` IPs.

[n3] You can now specify your home/office/etc. IP manually using `-c <ip>` option to `build.sh`.

[n4] See, serverfault [post](http://serverfault.com/questions/396958/configure-dns-server-to-return-same-ip-for-all-domains).

[n5] See, this [issue](https://github.com/ab77/netflix-proxy/issues/42#issuecomment-152128091).

[n6] If you have a working IPv6 stack, then your device may be preferring it over IPv4, see this [issue](https://forums.he.net/index.php?topic=3056).

[n7] See, https://en.wikipedia.org/wiki/Server_Name_Indication.

[n8] See, https://www.reddit.com/r/VPN/comments/48v03v/netflix_begins_geo_checks_on_cdn/.

[n9] See, [Using NDP proxying](https://docs.docker.com/engine/userguide/networking/default_network/ipv6/).

[n10] See notes in https://github.com/dlundquist/sniproxy/blob/master/sniproxy.conf.
