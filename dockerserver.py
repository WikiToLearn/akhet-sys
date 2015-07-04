#!/usr/bin/python
from flask import Flask, jsonify, abort, request
import os
#from docker import Client
import re
import random
import string
from docker.utils import create_host_config
from functools import cmp_to_key

from docker.client import Client as DockerClient
from docker.utils import compare_version


MINIMUM_API_VERSION = '1.14'
machines = 0

def get_api_version(*versions):
    # compare_version is backwards
    def cmp(a, b):
        return -1 * compare_version(a, b)
    return min(versions, key=cmp_to_key(cmp))


version_client = DockerClient(base_url='unix://var/run/docker.sock', version=MINIMUM_API_VERSION)
version = get_api_version('1.18', version_client.version()['ApiVersion'])

c = DockerClient(base_url='unix://var/run/docker.sock', version=version)


hostn="dockers.wikifm.org"

app = Flask(__name__)

def get_pass(n):
    return ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(n))

def validate(test_str):
    p = re.compile(u'[a-zA-Z0-9\-]*')
    p = re.compile(u'.*')
    return re.search(p, test_str).group(0)

@app.route('/')
def index():
 return "WikiFM Docker Init"

@app.route('/create', methods=['GET'])
def get_task():
    machines = 0
    if machines < 30:
        port = 6080+machines
        usr = validate(request.args.get('user'))
        img = validate(request.args.get('image'))
        
        if (len(usr) == 0):
            return "User not valid"
        if (len(img) == 0):
            return "Image not valid"

        #img = "wikifm/%s" % img # only support official images

        confdict = {}
        confdict['UBUNTUPASS'] = get_pass(16)
        confdict['VNCPASS'] = get_pass(16)
        confdict['USER'] = usr
        
        hostcfg = create_host_config(port_bindings={port: ('127.0.0.1', port)})
        
        #sudo docker run -i -t -p 6081:6080 -e UBUNTUPASS=supersecret -e VNCPASS=secret -h localhost mccahill/eclipse-novnc
        container = c.create_container(detach=True, image=img, hostname=hostn, environment=confdict, host_config=hostcfg, ports=[port])
        resp = c.start(container=container.get('Id'))
        print(resp)
        
        machines = machines + 1
        url = "https://%s/%s/vnc.html?&encrypt=1&autoconnect=1&password=%s" % (hostn, port, confdict['VNCPASS'])
        return url
    
    return "Too many virtual machines"

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')