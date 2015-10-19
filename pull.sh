#!/bin/bash
docker pull wikitolearndockeraccess/access-base
for img in $(docker search wikitolearndockeracces | awk '{ print $1 }' | grep -v virtualfactory | grep -v NAME) ; do
 docker pull $img
done
