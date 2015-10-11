#!/usr/bin/python
from flask import Flask, jsonify, abort, request
import os
import re
import random
import string
import ssl

from functools import cmp_to_key

from docker.utils import create_host_config
from docker import Client
from docker.tls import TLSConfig
from docker.client import Client
from docker.utils import compare_version

start_port=int(os.getenv('DOCKERAPI_START_PORT', 1000))
end_port=int(os.getenv('DOCKERAPI_END_PORT', 1050))
external_port=int(os.getenv('DOCKERAPI_EXTERNAL_PORT', 80))
hostn=os.getenv('DOCKERAPI_HOSTNAME', "dockers.wikifm.org")
homedir_folder=os.getenv('DOCKERAPI_HOMEDIRS', "/var/homedirs/")

# tls auth for swarm cluster
tls_config = TLSConfig(
 client_cert=('/certs/virtualfactory.crt', '/certs/virtualfactory.key'),
 verify='/certs/ca.crt',
 ca_cert='/certs/ca.crt'
)

c = Client(base_url='https://swarm-manager:2375', tls=tls_config) #, version=version)

app = Flask(__name__)

def get_pass(n):
    return ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(n))

def validate(test_str):
    p = re.compile(u'[a-zA-Z0-9\-]*')
    p = re.compile(u'.*')
    return re.search(p, test_str).group(0)

def first_ok_port():
    # Garbage collect
    for d in c.containers(all=True,filters={"status":"exited"}):
        c.remove_container(d)
        
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
 return "WikiToLearn Docker Init"

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
    confdict['VNCPASS'] = get_pass(8)
    confdict['USER'] = usr
    
    #hostcfg = create_host_config(port_bindings={6080: ('127.0.0.1', port)})
    hostcfg = c.create_host_config(port_bindings={6080: port}, binds=['%s/%s:/home/user' % (homedir_folder, usr) ])
    
    container = c.create_container(detach=True, tty=True, image=img, hostname=str(port), environment=confdict,
                                   volumes=['%s/%s' % (homedir_folder, usr)], host_config=hostcfg, ports=[port])
    resp = c.start(container=container.get('Id'))

    # get node address
    nodeaddr = c.inspect_container(container=container.get('Id'))["Node"]["Addr"].split(':')[0]

    url = "/vnc.html?resize=scale&path=/socket/%s/%s&autoconnect=1&password=%s" % (nodeaddr, port, confdict['VNCPASS'])
    return url
    
if __name__ == '__main__':
    app.run(debug=True)
