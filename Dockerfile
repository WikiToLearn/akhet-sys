FROM debian

RUN apt-get update
RUN apt-get install -y python python-pip nginx git python-dev
RUN pip install docker-py flask
RUN apt-get clean

ADD ./dockerserver.py /dockerserver.py
ADD ./run.sh /run.sh

WORKDIR /var/www/html
RUN rm * -Rfv
RUN git clone git://github.com/kanaka/noVNC .

EXPOSE 80 443

CMD ["/run.sh"]
