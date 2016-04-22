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
 openssl genrsa -des3 -passout pass:x -out server.pass.key 2048
 openssl rsa -passin pass:x -in server.pass.key -out /etc/ssl/private/nginx.key
 rm server.pass.key
 openssl req -new -key /etc/ssl/private/nginx.key -out server.csr -subj "/C=IT/ST=Italia/L=Milano/O=WikiToLearn/OU=IT Department/CN=www.wikitolearn.org"
 openssl x509 -req -days 365000 -in server.csr -signkey /etc/ssl/private/nginx.key -out /etc/ssl/certs/nginx.crt
 rm server.csr
fi

rm -Rf /var/www/allowedports/
rm -Rf /var/www/allowedhosts/

mkdir /var/www/allowedports/
mkdir /var/www/allowedhosts/

/etc/init.d/dnsmasq start
/etc/init.d/nginx start

cron

exec python3 /akhet.py
