#!/bin/bash

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

if test -e /var/run/docker.sock ; then # if there is the socket file for docker the user must have the right permissoion
  GROUP_ID=$(stat -c %g /var/run/docker.sock)
else
  GROUP_ID=1000
fi

if ! getent group $GROUP_ID &> /dev/null ; then
  groupadd -g $GROUP_ID dockergroup
fi
useradd -d /bin -r -s /bin/bash -u $GROUP_ID -g $GROUP_ID -G www-data -o akhetuser

mkdir /var/run/akhet/

touch /var/run/akhet/htpasswd

mkdir /var/run/akhet/{wsvnc,ws,http}/
mkdir /var/run/akhet/{wsvnc,ws,http}/{allowedports,allowedhosts}/

chmod 750 /var/run/akhet/ -R
chown akhetuser:www-data /var/run/akhet/ -R

chown akhetuser:www-data /var/log/akhet/ -R

echo resolver $(awk 'BEGIN{ORS=" "} $1=="nameserver" {print $2}' /etc/resolv.conf) ";" > /etc/nginx/resolvers.conf
/etc/init.d/nginx start

cron
chmod 755 /etc/akhet.ini
exec su akhetuser -c /opt/akhet.py
