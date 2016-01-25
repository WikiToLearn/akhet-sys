#!/bin/bash

[[ "$AKHET_START_PORT" != "" ]] || export AKHET_START_PORT=1000
[[ "$AKHET_END_PORT" != "" ]] || export AKHET_END_PORT=2000
[[ "$AKHET_HOSTNAME" != "" ]] || export AKHET_HOSTNAME="dockers.wikitolearn.org"

[[ "$AKHET_HOSTS" != "" ]] || export AKHET_HOSTS="172.17.0.1"

[[ "$AKHET_USER" != "" ]] || export AKHET_USER="admin"
[[ "$AKHET_PASS" != "" ]] || export AKHET_PASS="admin"


echo $AKHET_USER:$(perl -le 'print crypt("'$AKHET_PASS'", "Salt-hash")') > /var/www/htpasswd

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

rm -Rf /var/www/socket_allowedports/
rm -Rf /var/www/allowedhosts/

mkdir /var/www/socket_allowedports/
P=$AKHET_START_PORT
while [[ $P -le $AKHET_END_PORT ]] ; do
 touch /var/www/socket_allowedports/$P
 P=$(($P+1))
done

mkdir /var/www/allowedhosts/
for allow_host in $AKHET_HOSTS ; do
 touch /var/www/allowedhosts/$allow_host
done

/etc/init.d/dnsmasq start
/etc/init.d/nginx start

cron

python /akhet.py
