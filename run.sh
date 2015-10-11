#!/bin/bash

[[ "$DOCKERAPI_START_PORT" != "" ]] || export DOCKERAPI_START_PORT=1000
[[ "$DOCKERAPI_END_PORT" != "" ]] || export DOCKERAPI_END_PORT=2000
[[ "$DOCKERAPI_HOSTNAME" != "" ]] || export DOCKERAPI_HOSTNAME="dockers.wikitolearn.org"

[[ "$DOCKERAPI_HOSTS" != "" ]] || DOCKERAPI_HOSTS="172.17.42.1"

[[ "$DOCKERAPI_USER" != "" ]] || DOCKERAPI_USER="admin"
[[ "$DOCKERAPI_PASS" != "" ]] || DOCKERAPI_PASS="admin"

echo $DOCKERAPI_USER:$(perl -le 'print crypt("'$DOCKERAPI_PASS'", "Salt-hash")') > /var/www/htpasswd

if [ -f /certs/virtualfactory.crt ] ; then
 echo "Copy /certs/virtualfactory.crt"
 cp /certs/virtualfactory.crt /etc/ssl/certs/nginx.crt
fi
if [ -f /certs/virtualfactory.key ] ; then
 echo "Copy /certs/virtualfactory.key"
 cp /certs/virtualfactory.key /etc/ssl/private/nginx.key
fi


if [ ! -f /etc/ssl/private/nginx.key ] ; then
 openssl genrsa -des3 -passout pass:x -out server.pass.key 2048
 openssl rsa -passin pass:x -in server.pass.key -out /etc/ssl/private/nginx.key
 rm server.pass.key
 openssl req -new -key /etc/ssl/private/nginx.key -out server.csr -subj "/C=IT/ST=Italia/L=Milano/O=WikiFM/OU=IT Department/CN=www.wikifm.org"
 openssl x509 -req -days 365000 -in server.csr -signkey /etc/ssl/private/nginx.key -out /etc/ssl/certs/nginx.crt
 rm server.csr
fi

if [ -d /var/www/allowedports/ ] ; then
 rm -Rf /var/www/allowedports/
fi
mkdir /var/www/allowedports/
P=$DOCKERAPI_START_PORT
while [[ $P -le $DOCKERAPI_END_PORT ]] ; do
 touch /var/www/allowedports/$P
 P=$(($P+1))
done

if [ -d /var/www/allowedhosts/ ] ; then
 rm -Rf /var/www/allowedhosts/
fi
mkdir /var/www/allowedhosts/
for allow_host in $DOCKERAPI_HOSTS ; do
 touch /var/www/allowedhosts/$allow_host
done

/etc/init.d/dnsmasq start
/etc/init.d/nginx start

python /dockerserver.py
