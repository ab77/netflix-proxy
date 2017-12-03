FROM phusion/baseimage

MAINTAINER anton@belodedenko.me

RUN apt-get update && apt-get -y install --no-install-recommends\
      vim dnsutils curl git sipcalc iptables autotools-dev\
      cdbs debhelper dh-autoreconf dpkg-dev gettext libev-dev\
      libpcre3-dev libudns-dev pkg-config fakeroot\
      inetutils-traceroute net-tools iputils-ping

WORKDIR /root

RUN git clone https://github.com/dlundquist/sniproxy.git\
      && cd sniproxy\
      && ./autogen.sh\
      && dpkg-buildpackage\
      && dpkg -i ../sniproxy_*.deb

ADD functions ./functions

ADD sniproxy.sh ./sniproxy.sh

CMD ./sniproxy.sh
