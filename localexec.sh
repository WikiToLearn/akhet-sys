#!/bin/bash
docker run -ti --rm -p 80:80 -p 443:443 --privileged -v /var/run/docker.sock:/var/run/docker.sock  akhetbase/akhet
