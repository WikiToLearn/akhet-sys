#!/bin/bash
DOCKERAPI_HOSTNAME="192.168.93.30"
DOCKERAPI_HOMEDIRS="/var/homedirs/"

docker stop virtualfactory
docker rm virtualfactory

docker run -v /var/run/docker.sock:/var/run/docker.sock \
 --name virtualfactory \
 --privileged -p 80:80 -p 443:443 -dti --restart=always \
 -e DOCKERAPI_HOSTNAME=$DOCKERAPI_HOSTNAME \
 -e DOCKERAPI_HOMEDIRS=$DOCKERAPI_HOMEDIRS \
 wikitolearndockeraccess/virtualfactory:0.4
