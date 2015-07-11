#!/bin/bash

[[ "$DOCKERAPI_START_PORT" != "" ]] || export DOCKERAPI_START_PORT=1000
[[ "$DOCKERAPI_END_PORT" != "" ]] || export DOCKERAPI_END_PORT=2000
[[ "$DOCKERAPI_HOSTNAME" != "" ]] || export DOCKERAPI_HOSTNAME="dockers.wikifm.org"

[[ "$DOCKERAPI_USER" != "" ]] || DOCKERAPI_USER="admin"
[[ "$DOCKERAPI_PASS" != "" ]] || DOCKERAPI_PASS="admin"

echo $DOCKERAPI_USER:$(perl -le 'print crypt("'$DOCKERAPI_PASS'", "Salt-hash")') > /var/www/htpasswd

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
echo 'location /create {'
echo ' auth_basic "Administrator Login";'
echo ' auth_basic_user_file /var/www/htpasswd;'
echo ' proxy_pass http://127.0.0.1:5000;'
echo ' proxy_set_header Host $host;'
echo ' proxy_set_header X-Real-IP $remote_addr;'
echo ' proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;'
echo ' proxy_set_header X-Forwarded-Proto $scheme;'
echo '}'
P=$DOCKERAPI_START_PORT
while [[ $P -le $DOCKERAPI_END_PORT ]] ; do
 echo ' location /'$P' { proxy_pass http://port'$P'; proxy_http_version 1.1; proxy_set_header Upgrade $http_upgrade; proxy_set_header Connection "upgrade"; }'
 P=$(($P+1))
done
echo '}'
} > /etc/nginx/sites-available/default

/etc/init.d/nginx start

python /dockerserver.py
