FROM debian:stretch

EXPOSE 80 443

MAINTAINER wikitolearn sysadmin@wikitolearn.org
ENV DEBIAN_FRONTEND noninteractive
ENV DEBCONF_NONINTERACTIVE_SEEN true

CMD ["/run.sh"]

RUN apt-get update && apt-get -y install zip unzip nano apt-utils curl rsync git && rm -f /var/cache/apt/archives/*deb

RUN apt-get -y install python && rm -f /var/cache/apt/archives/*deb
RUN apt-get -y install python-pip && rm -f /var/cache/apt/archives/*deb
RUN apt-get -y install nginx && rm -f /var/cache/apt/archives/*deb
RUN apt-get -y install git && rm -f /var/cache/apt/archives/*deb
RUN apt-get -y install python-dev && rm -f /var/cache/apt/archives/*deb
RUN apt-get -y install dnsmasq && rm -f /var/cache/apt/archives/*deb
RUN pip install docker-py flask

WORKDIR /var/www/html
RUN rm * -Rfv
ADD ./index.html /var/www/html/index.html

RUN apt-get -y install cron && rm -f /var/cache/apt/archives/*deb
RUN apt-get -y install wget && rm -f /var/cache/apt/archives/*deb

RUN git clone git://github.com/kanaka/noVNC viewer

ADD ./dockerservercron /etc/cron.d/

RUN rm -f /etc/nginx/sites-available/default
ADD ./default /etc/nginx/sites-available/default

ADD ./run.sh /run.sh
ADD flask /flask

# Custom Branding
ADD favicon.ico /var/www/html/viewer/images/favicon.ico