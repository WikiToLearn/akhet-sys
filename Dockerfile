FROM debian:stretch

MAINTAINER wikitolearn sysadmin@wikitolearn.org
ENV DEBIAN_FRONTEND noninteractive
ENV DEBCONF_NONINTERACTIVE_SEEN true

RUN apt-get update && apt-get -y install zip unzip nano apt-utils curl rsync git && rm -f /var/cache/apt/archives/*deb && find /var/lib/apt/lists/ -type f -delete

RUN apt-get update && apt-get -y install python && rm -f /var/cache/apt/archives/*deb && find /var/lib/apt/lists/ -type f -delete
RUN apt-get update && apt-get -y install python-pip && rm -f /var/cache/apt/archives/*deb && find /var/lib/apt/lists/ -type f -delete
RUN apt-get update && apt-get -y install nginx && rm -f /var/cache/apt/archives/*deb && find /var/lib/apt/lists/ -type f -delete
RUN apt-get update && apt-get -y install python-dev && rm -f /var/cache/apt/archives/*deb && find /var/lib/apt/lists/ -type f -delete
RUN apt-get update && apt-get -y install dnsmasq && rm -f /var/cache/apt/archives/*deb && find /var/lib/apt/lists/ -type f -delete
RUN apt-get update && apt-get -y install cron && rm -f /var/cache/apt/archives/*deb && find /var/lib/apt/lists/ -type f -delete
RUN apt-get update && apt-get -y install wget && rm -f /var/cache/apt/archives/*deb && find /var/lib/apt/lists/ -type f -delete
RUN pip install docker-py flask

WORKDIR /var/www/html
RUN rm /var/www/html/* -Rfv

ADD ./akhetcron /etc/cron.d/

RUN rm -f /etc/nginx/sites-available/default
ADD ./default /etc/nginx/sites-available/default
ADD ./nginx-auth-type /etc/nginx/common/auth-type

ADD ./run.sh /run.sh
RUN chmod +x /run.sh

EXPOSE 80 443

CMD ["/run.sh"]

ADD ./index.html /var/www/html/index.html
ADD ./akhet.py /akhet.py
ADD ./akhet.ini /akhet.ini

WORKDIR /root

VOLUME ["/var/log/", "/tmp/"]
