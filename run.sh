#!/bin/bash

export DOCKERAPI_START_PORT=1000
export DOCKERAPI_END_PORT=2000
export DOCKERAPI_HOSTNAME="dockers.wikifm.org"

{
P=$DOCKERAPI_START_PORT
while [[ $P -le $DOCKERAPI_END_PORT ]] ; do
 echo 'upstream port'$P' { server 172.17.42.1:'$P'; }'
 P=$(($P+1))
done
echo 'server {'
echo ' listen 80;'
echo ' location / {'
echo '  root /var/www/html;'
echo '  index vnc.html;'
echo ' }'
P=$DOCKERAPI_START_PORT
while [[ $P -le $DOCKERAPI_END_PORT ]] ; do
 echo ' location /'$P' { proxy_pass http://port'$P'; proxy_http_version 1.1; proxy_set_header Upgrade $http_upgrade; proxy_set_header Connection "upgrade"; }'
 P=$(($P+1))
done
echo '}'
} > /etc/nginx/sites-available/default

/etc/init.d/nginx start

python /dockerserver.py
