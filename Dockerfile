FROM debian
MAINTAINER wikitolearn sysadmin@wikitolearn.org
ENV DEBIAN_FRONTEND noninteractive
ENV DEBCONF_NONINTERACTIVE_SEEN true
RUN apt-get update
RUN apt-get -y install zip unzip nano apt-utils curl rsync git && rm -f /var/cache/apt/archives/*deb

RUN apt-get update
RUN apt-get -y install python && rm -f /var/cache/apt/archives/*deb
RUN apt-get -y install python-pip && rm -f /var/cache/apt/archives/*deb
RUN apt-get -y install nginx && rm -f /var/cache/apt/archives/*deb
RUN apt-get -y install git && rm -f /var/cache/apt/archives/*deb
RUN apt-get -y install python-dev && rm -f /var/cache/apt/archives/*deb
RUN apt-get -y install dnsmasq && rm -f /var/cache/apt/archives/*deb
RUN pip install docker-py flask

RUN rm -f /etc/nginx/sites-available/default
ADD ./default /etc/nginx/sites-available/default

ADD ./dockerserver.py /dockerserver.py
ADD ./run.sh /run.sh

WORKDIR /var/www/html
RUN rm * -Rfv
RUN git clone git://github.com/kanaka/noVNC .

EXPOSE 80 443

CMD ["/run.sh"]
