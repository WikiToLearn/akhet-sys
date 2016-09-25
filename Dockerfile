FROM debian:8

MAINTAINER wikitolearn sysadmin@wikitolearn.org
ENV DEBIAN_FRONTEND noninteractive
ENV DEBCONF_NONINTERACTIVE_SEEN true

ADD ./sources.list /etc/apt/sources.list

RUN apt-get update && apt-get -y install zip && rm -f /var/cache/apt/archives/*deb && find /var/lib/apt/lists/ -type f -delete && find /var/log/ -type f -delete
RUN apt-get update && apt-get -y install unzip && rm -f /var/cache/apt/archives/*deb && find /var/lib/apt/lists/ -type f -delete && find /var/log/ -type f -delete
RUN apt-get update && apt-get -y install nano && rm -f /var/cache/apt/archives/*deb && find /var/lib/apt/lists/ -type f -delete && find /var/log/ -type f -delete
RUN apt-get update && apt-get -y install apt-utils && rm -f /var/cache/apt/archives/*deb && find /var/lib/apt/lists/ -type f -delete && find /var/log/ -type f -delete
RUN apt-get update && apt-get -y install curl && rm -f /var/cache/apt/archives/*deb && find /var/lib/apt/lists/ -type f -delete && find /var/log/ -type f -delete
RUN apt-get update && apt-get -y install rsync && rm -f /var/cache/apt/archives/*deb && find /var/lib/apt/lists/ -type f -delete && find /var/log/ -type f -delete
RUN apt-get update && apt-get -y install git && rm -f /var/cache/apt/archives/*deb && find /var/lib/apt/lists/ -type f -delete && find /var/log/ -type f -delete

RUN apt-get update && apt-get -y install python3 && rm -f /var/cache/apt/archives/*deb && find /var/lib/apt/lists/ -type f -delete && find /var/log/ -type f -delete
RUN apt-get update && apt-get -y install python3-pip && rm -f /var/cache/apt/archives/*deb && find /var/lib/apt/lists/ -type f -delete && find /var/log/ -type f -delete
RUN apt-get update && apt-get -y install python3-dev && rm -f /var/cache/apt/archives/*deb && find /var/lib/apt/lists/ -type f -delete && find /var/log/ -type f -delete
RUN apt-get update && apt-get -y install python3-dateutil && rm -f /var/cache/apt/archives/*deb && find /var/lib/apt/lists/ -type f -delete && find /var/log/ -type f -delete
RUN apt-get update && apt-get -y install nginx-extras && rm -f /var/cache/apt/archives/*deb && find /var/lib/apt/lists/ -type f -delete && find /var/log/ -type f -delete
RUN apt-get update && apt-get -y install cron && rm -f /var/cache/apt/archives/*deb && find /var/lib/apt/lists/ -type f -delete && find /var/log/ -type f -delete
RUN apt-get update && apt-get -y install wget && rm -f /var/cache/apt/archives/*deb && find /var/lib/apt/lists/ -type f -delete && find /var/log/ -type f -delete

RUN pip3 install docker-py==1.9.0
RUN pip3 install flask==0.10.1
RUN pip3 install htpasswd==2.3

RUN rm /var/www/html/* -Rfv

ADD ./akhetcron /etc/cron.d/

RUN rm -f /etc/nginx/sites-available/default
ADD ./default /etc/nginx/sites-available/default

ADD ./index.html /var/www/html/index.html
ADD ./favicon.ico /var/www/html/favicon.ico
ADD ./akhet.py /opt/akhet.py
ADD ./auth.lua /opt/auth.lua
ADD ./akhet-libs /opt/akhet-libs

ADD ./run.sh /run.sh
RUN chmod +x /run.sh

RUN mkdir /var/log/akhet/

CMD ["/run.sh"]

EXPOSE 80 443
