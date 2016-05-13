#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os

def allow_host_port(service,host,port):
    filenames = ["/var/run/akhet/{}/allowedports/{}".format(service, port),"/var/run/akhet/{}/allowedhosts/{}".format(service, host)]
    for filename in filenames:
        open(filename , 'a').close()

def disallow_host_port(service,host,port):
    filenames = ["/var/run/akhet/{}/allowedports/{}".format(service, port),"/var/run/akhet/{}/allowedhosts/{}".format(service, host)]
    for filename in filenames:
        if os.path.exists(filename):
            os.remove(filename)

def set_wsvnc(allow,host,port):
    allow = True
    if allow:
        allow_host_port("wsvnc",host,port)
    else:
        disallow_host_port("wsvnc",host,port)

def set_ws(allow,host,ports):
    if allow:
        for port in ports:
            allow_host_port("ws",host,port)
    else:
        for port in ports:
            disallow_host_port("ws",host,port)

def set_http(allow,host,ports):
    if allow:
        for port in ports:
            allow_host_port("http",host,port)
    else:
        for port in ports:
            disallow_host_port("http",host,port)
