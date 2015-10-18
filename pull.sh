#!/bin/bash
docker pull wikitolearndockeraccess/access-base:0.1
for img in $(docker search wikitolearndockeracces | awk '{ print $1 }' | grep -v virtualfactory | grep -v NAME) ; do
 docker pull $img
done
