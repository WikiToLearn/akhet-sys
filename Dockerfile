FROM debian:stretch

EXPOSE 80 443

MAINTAINER wikitolearn sysadmin@wikitolearn.org
ENV DEBIAN_FRONTEND noninteractive
ENV DEBCONF_NONINTERACTIVE_SEEN true

RUN apt-get update && apt-get -y install zip unzip nano apt-utils curl rsync git && rm -f /var/cache/apt/archives/*deb

RUN apt-get -y install python && rm -f /var/cache/apt/archives/*deb
RUN apt-get -y install python-pip && rm -f /var/cache/apt/archives/*deb
RUN apt-get -y install nginx && rm -f /var/cache/apt/archives/*deb
RUN apt-get -y install python-dev && rm -f /var/cache/apt/archives/*deb
RUN apt-get -y install dnsmasq && rm -f /var/cache/apt/archives/*deb
RUN apt-get -y install cron && rm -f /var/cache/apt/archives/*deb
RUN apt-get -y install wget && rm -f /var/cache/apt/archives/*deb
RUN pip install docker-py flask

WORKDIR /var/www/html
RUN rm * -Rfv

ADD ./dockerservercron /etc/cron.d/

RUN rm -f /etc/nginx/sites-available/default
ADD ./default /etc/nginx/sites-available/default

ADD ./run.sh /run.sh
ADD ./akhet.py /akhet.py

CMD ["/run.sh"]
