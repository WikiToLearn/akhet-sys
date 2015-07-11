#!/usr/bin/python
from flask import Flask, jsonify, abort, request
import os
import re
import random
import string
from docker.utils import create_host_config
from functools import cmp_to_key

from docker.client import Client as DockerClient
from docker.utils import compare_version

start_port=int(os.getenv('DOCKERAPI_START_PORT', 1000))
end_port=int(os.getenv('DOCKERAPI_END_PORT', 1050))
hostn=os.getenv('DOCKERAPI_HOSTNAME', "dockers.wikifm.org")

MINIMUM_API_VERSION = '1.14'

def get_api_version(*versions):
    # compare_version is backwards
    def cmp(a, b):
        return -1 * compare_version(a, b)
    return min(versions, key=cmp_to_key(cmp))


version_client = DockerClient(base_url='unix://var/run/docker.sock', version=MINIMUM_API_VERSION)
version = get_api_version('1.18', version_client.version()['ApiVersion'])

c = DockerClient(base_url='unix://var/run/docker.sock', version=version)

app = Flask(__name__)

def get_pass(n):
    return ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(n))

def validate(test_str):
    p = re.compile(u'[a-zA-Z0-9\-]*')
    p = re.compile(u'.*')
    return re.search(p, test_str).group(0)

def first_ok_port():
    l = c.containers(all=True)#, quiet=True)
    ports_list = []
    for i in l:
        #if (len(i['Ports'])):
        ports = i['Ports']
        for port in ports:
            try:
                ports_list.append(port['PublicPort'])
            except:
                continue;
    try_port = start_port
    while True:
        if try_port in ports_list:
            try_port += 1
        else:
            return try_port
        
        if try_port > end_port:
            return None
            
@app.route('/')
def index():
 return "WikiFM Docker Init"

@app.route('/create', methods=['GET'])
def get_task():
    
    port = first_ok_port()
    if port == None:
        return "No machines available. Please try again later." # estimated time
    
    usr = validate(request.args.get('user'))
    img = validate(request.args.get('image'))
    
    if (len(usr) == 0):
        return "User not valid"
    if (len(img) == 0):
        return "Image not valid"

    img = "wikifm/%s" % img # only support official images

    confdict = {}
    confdict['UBUNTUPASS'] = get_pass(16)
    confdict['VNCPASS'] = get_pass(16)
    confdict['USER'] = usr
    
    #hostcfg = create_host_config(port_bindings={6080: ('127.0.0.1', port)})
    hostcfg = create_host_config(port_bindings={6080: port})
    
    container = c.create_container(detach=True, tty=True, image=img, hostname=hostn, environment=confdict, host_config=hostcfg, ports=[port])
    resp = c.start(container=container.get('Id'))
    
    url = "http://%s/vnc.html?resize=scale&path=%s&autoconnect=1&password=%s" % (hostn, port, confdict['VNCPASS'])
    return url
    
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
