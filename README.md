# netflix-proxy
`Docker` packaged smart DNS proxy to watch `Netflix`, `Hulu`[n2] and/or `HBO Now`, out of region using `BIND` and `sniproxy`[n1].

# Instructions
The following paragraphs show how to get this solution up and running with a few different Cloud providers I've tried so far.

## DigitalOcean
The following is based on a standard Ubuntu Docker image provided by `DigitalOcean`, but should in theory work on any Linux distribution with Docker pre-installed.

1. Head over to [Digital Ocean](https://www.digitalocean.com/?refcode=937b01397c94) to get $10 USD credit to create a Docker VM
2. Create a `Droplet` using `Docker 1.6.2` on `Ubuntu 14.04` (find in under Applications images).
3. Make sure you create the `Droplet` in the right location, for example if you want to watch US content, create in the US.
3. SSH to your `Droplet` and run the following command..
4. `cd /opt && git clone https://github.com/ab77/netflix-proxy.git && cd netflix-proxy && ./build.sh`
5. Point your DNS at the Droplet IP and watch `Netflix`, `Hulu` and `HBO Now` out of region.
6. Enjoy!

## Linode
The following is based on a standard Ubuntu image provided by `Linode`, but should work on any Linux distribution **without** Docker installed.

1. Head over to [Linode](https://www.linode.com/?r=ceb35af7bad520f1e2f4232b3b4d49136dcfe9d9) and sign-up for an account.
2. Create a new `Linode` and deploy an `Ubuntu 14-04 LTS` image into it.
3. Make sure you create the Linode in the right location, as there a few to pick from.
3. SSH to your `Linode` and run the following command..
4. `curl -sSL https://get.docker.com/ | sh && cd /opt && git clone https://github.com/ab77/netflix-proxy.git && cd netflix-proxy && ./build.sh`
5. Point your DNS at the `Linode` IP and watch `Netflix`, `Hulu` and/or `HBO Now` out of region.
6. Binge. Not that there is anything wrong with that..

## DreamCompute by DreamHost
The following is based on a standard Ubuntu image provided by `DreamHost`, but should work on any Linux distribution **without** Docker installed and running under **non-root** user.

1. Head over to [DreamHost]( http://www.dreamhost.com/r.cgi?2124700) and sign-up for an account.
2. Find the `DreamCompute` or `Public Cloud Computing` section and launch an `Ubuntu 14-04-Trusty` instance.
3. Make sure to add an additional firewall rule to allow DNS: `Ingress	IPv4	UDP	53	0.0.0.0/0 (CIDR)`
4. Also add a `Floating IP` to your instance, otherwise it will only have an IPv6 IP.
3. SSH to your instance and run the following command..
4. `curl -sSL https://get.docker.com/ | sh && sudo usermod -aG docker dhc-user && cd /opt && sudo git clone https://github.com/ab77/netflix-proxy.git && cd netflix-proxy && ./build.sh`
5. Point your DNS at the instance IP and watch `Netflix`, `Hulu` and/or `HBO Now` out of region.
6. Well done, enjoy!

-- ab1

[n1] https://github.com/dlundquist/sniproxy by Dustin Lundquist dustin@null-ptr.net

[n2] At the time of writing (May 2015), Hulu appears to be geo-restricted from DigitalOcean and Linode US IPs, but working from DreamCompute IAD DC IPs (at least the ones I've tried).
