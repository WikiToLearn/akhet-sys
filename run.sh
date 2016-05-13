#!/bin/bash

touch /var/www/htpasswd

if [ -f /certs/akhet.crt ] ; then
 echo "Copy /certs/akhet.crt"
 cp /certs/akhet.crt /etc/ssl/certs/nginx.crt
fi
if [ -f /certs/akhet.key ] ; then
 echo "Copy /certs/akhet.key"
 cp /certs/akhet.key /etc/ssl/private/nginx.key
fi


if [ ! -f /etc/ssl/private/nginx.key ] ; then
 cd /tmp/
 openssl genrsa -des3 -passout pass:x -out server.pass.key 2048
 openssl rsa -passin pass:x -in server.pass.key -out /etc/ssl/private/nginx.key
 rm server.pass.key
 openssl req -new -key /etc/ssl/private/nginx.key -out server.csr -subj "/C=IT/ST=Italia/L=Milano/O=WikiToLearn/OU=IT Department/CN=www.wikitolearn.org"
 openssl x509 -req -days 365000 -in server.csr -signkey /etc/ssl/private/nginx.key -out /etc/ssl/certs/nginx.crt
 rm server.csr
fi

rm -Rf /var/www/wsvnc/
mkdir /var/www/wsvnc/
mkdir /var/www/wsvnc/allowedports/
mkdir /var/www/wsvnc/allowedhosts/

rm -Rf /var/www/ws/
mkdir /var/www/ws/
mkdir /var/www/ws/allowedports/
mkdir /var/www/ws/allowedhosts/

rm -Rf /var/www/http/
mkdir /var/www/http/
mkdir /var/www/http/allowedports/
mkdir /var/www/http/allowedhosts/

echo resolver $(awk 'BEGIN{ORS=" "} $1=="nameserver" {print $2}' /etc/resolv.conf) ";" > /etc/nginx/resolvers.conf
/etc/init.d/nginx start

cron

exec python3 /opt/akhet.py
