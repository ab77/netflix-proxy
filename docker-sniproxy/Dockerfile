FROM phusion/baseimage

MAINTAINER anton@belodedenko.me

RUN apt-get update && \
    apt-get -y install vim dnsutils curl git sipcalc iptables autotools-dev \
    cdbs debhelper dh-autoreconf dpkg-dev gettext libev-dev libpcre3-dev \
    libudns-dev pkg-config fakeroot

RUN git clone https://github.com/dlundquist/sniproxy.git ${HOME}/sniproxy && \
    cd ${HOME}/sniproxy && \
    ./autogen.sh && dpkg-buildpackage && \
    dpkg -i ../sniproxy_*.deb

ADD functions /opt/functions

ADD sniproxy.sh /opt/sniproxy.sh

CMD /opt/sniproxy.sh
