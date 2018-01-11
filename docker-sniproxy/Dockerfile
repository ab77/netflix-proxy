FROM phusion/baseimage

MAINTAINER anton@belodedenko.me

RUN apt-get update\
      && apt-get upgrade -y -o Dpkg::Options::="--force-confold"

RUN apt-get -y install --no-install-recommends\
      build-essential vim dnsutils curl git iptables\
      autotools-dev cdbs debhelper dh-autoreconf dpkg-dev gettext\
      libev-dev libpcre3-dev libudns-dev pkg-config fakeroot\
      inetutils-traceroute net-tools iputils-ping libssl-dev

WORKDIR /root

RUN git clone https://github.com/dlundquist/sniproxy.git\
      && cd sniproxy\
      && ./autogen.sh\
      && dpkg-buildpackage\
      && dpkg -i ../sniproxy_*.deb

ADD functions ./

ADD run.sh ./

CMD ./run.sh
