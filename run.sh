#!/bin/bash
set -e
set -x
if [ ! -f /etc/akhet.ini ] ; then
  echo "Missing /etc/akhet.ini file"
  exit 1
fi
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
 openssl req \
      -subj '/CN=localhost' \
      -new -newkey rsa:1024 \
      -days 365 \
      -nodes -x509 \
      -keyout /etc/ssl/private/nginx.key \
      -out /etc/ssl/certs/nginx.crt
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
