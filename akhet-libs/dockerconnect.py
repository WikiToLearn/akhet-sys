#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from docker import Client
from docker.client import Client
from docker.tls import TLSConfig
import sys
from akhet_logger import akhet_logger

def docker_connect(config):
    c = None
    if (config['docker']['connection_type'] == "socket"):
        akhet_logger("Connecting through socket...")
        c = Client(base_url="unix:/{}".format(config['docker']['socket_file']))
    elif (config['docker']['connection_type'] == "tcp"):
        akhet_logger("Connecting through TCP...")
        c = Client(base_url='tcp://{}:{}'.format(config['docker']['remote']['host'], config['docker']['remote']['port']))
    else:
        akhet_logger("Connecting through HTTPS...")
        # tls auth
        tls_config = TLSConfig(client_cert=(config['docker']['remote']['ssl_cert_file'], config['docker']['remote']['ssl_key_file']), verify=config['docker']['remote']['ssl_ca'], ca_cert=config['docker']['remote']['ssl_ca'])
        c = Client(base_url='https://{}:{}'.format(config['docker']['remote']['host'], config['docker']['remote']['port']), tls=tls_config)
    try:
        c.info()
    except:
        akhet_logger("Error during the connection to docker")
        sys.exit(1)

    volumes_info = c.volumes()
    volumes=volumes_info['Volumes']
    volumes_cuda = []
    if volumes != None:
        for volume in volumes:
            if volume['Driver'] == "nvidia-docker":
                volumes_cuda.append(volume)

    if config['cuda']['available']:
        if len(volumes_cuda) == 1:
            akhet_logger("CUDA volume found")
        else:
            akhet_logger("CUDA volume not found")
            sys.exit(1)

    akhet_logger("...connected!")
    # load finished
    return c
