# -*- coding: utf-8 -*-
#!/usr/bin/env python3
from docker import Client
from docker.client import Client
from docker.tls import TLSConfig

def docker_connect(config):
    c = None
    if (config['docker']['connection_type'] == "socket"):
        print("Connecting through socket...")
        c = Client(base_url="unix:/{}".format(config['docker']['socket_file']))
    elif (config['docker']['connection_type'] == "tcp"):
        print("Connecting through TCP...")
        c = Client(base_url='tcp://{}:{}'.format(config['docker']['remote']['host'], config['docker']['remote']['port']))
    else:
        print("Connecting through HTTPS...")
        # tls auth
        tls_config = TLSConfig(client_cert=(config['docker']['remote']['ssl_cert_file'], config['docker']['remote']['ssl_key_file']), verify=config['docker']['remote']['ssl_ca'], ca_cert=config['docker']['remote']['ssl_ca'])
        c = Client(base_url='https://{}:{}'.format(config['docker']['remote']['host'], config['docker']['remote']['port']), tls=tls_config)
    try:
        c.info()
    except:
        print("Error during the connection to docker")
        sys.exit(1)

    print("...connected!")
    # load finished
    return c
