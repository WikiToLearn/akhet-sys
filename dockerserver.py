#!/usr/bin/python
from flask import Flask, jsonify, abort, request, current_app
import os
import re
import random
import string
import ssl
import docker
import sys

from functools import cmp_to_key

from docker.utils import create_host_config
from docker import Client
from docker.tls import TLSConfig
from docker.client import Client
from docker.utils import compare_version

start_port=int(os.getenv('DOCKERAPI_START_PORT', 1000))
end_port=int(os.getenv('DOCKERAPI_END_PORT', 1050))
external_port=int(os.getenv('DOCKERAPI_EXTERNAL_PORT', 80))
external_ssl_port=int(os.getenv('DOCKERAPI_EXTERNAL_SSL_PORT', 443))
hostn=os.getenv('DOCKERAPI_HOSTNAME', "dockers.wikitolearn.org")
homedir_folder=os.getenv('DOCKERAPI_HOMEDIRS', "/var/homedirs/")
direct_access_to_nodes=os.getenv('DOCKERAPI_DIRECT_NODES', "no")

swarm_cluster=os.path.exists("/var/run/docker.sock")==False

if swarm_cluster:
    print "Using swarm cluster"
    # tls auth for swarm cluster
    tls_config = TLSConfig( client_cert=('/certs/virtualfactory.crt', '/certs/virtualfactory.key'), verify='/certs/ca.crt', ca_cert='/certs/ca.crt')
    c = Client(base_url='https://swarm-manager:2375', tls=tls_config) # connect to swarm manager node
else:
    print "Using single node"
    c = Client(base_url='unix:///var/run/docker.sock') # socket connection for single host

app = Flask(__name__)

def get_pass(n):
    return ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(n))

def validate(test_str):
    p = re.compile(u'[a-zA-Z0-9\-]*')
    p = re.compile(u'.*')
    return re.search(p, test_str).group(0)

@app.route('/gc')
def garbage_collector():
    count=0
    # Garbage collect
    for d in c.containers(all=True,filters={"status":"exited","label":"virtualfactory=yes"}):
        print "Removing " + str(d["Image"]) + " " + str(d["Labels"]["UsedPort"])
        c.remove_container(d)
        count=count+1
    return str(count)

def first_ok_port():
    l = c.containers(all=True,filters={"label":"virtualfactory=yes"})#, quiet=True)
    ports_list = []
    for i in l:
        #if (len(i['Ports'])):
        ports = i['Ports']
        try:
            p = int(i["Labels"]["UsedPort"])
            if p not in ports_list:
                ports_list.append(p)
        except:
            print "Missing UsedPort"
        for port in ports:
            try:
                if port['PublicPort'] not in ports_list:
                    ports_list.append(port['PublicPort'])
                if port['PrivatePort'] not in ports_list: 
                    ports_list.append(port['PrivatePort'])
            except:
                continue;
    print "Porte impegnate: " ,
    print ports_list
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

@app.route("/download", methods=['GET'])
def get_download():
    for line in c.pull("wikitolearndockeraccess/virtualfactory-firewall", stream=True):
        print " "
        print line
    for line in c.pull("wikitolearndockeraccess/access-base", stream=True):
        print " "
        print line
    return "OK"

@app.route('/create', methods=['GET'])
def get_task():
    port = first_ok_port()
    if port == None:
        return "No machines available. Please try again later." # estimated time
    
    usr = validate(request.args.get('user'))
    img = validate(request.args.get('image'))
    notimeout = request.args.get('notimeout') == "yes"

    if (len(usr) == 0):
        return "User not valid"
    if (len(img) == 0):
        return "Image not valid"

    img = "wikitolearndockeraccess/%s" % img # only support official images

    try:
        c.inspect_image(img)
    except:
        return "Missing image %s" % img

    confdict = {}
    confdict['NETWORK_TYPE'] = "limit"

    # create firewall docker to limit network
    hostcfg = c.create_host_config(port_bindings={6080:port},privileged=True)
    container = c.create_container(name="virtualfactory-fw-"+str(port),host_config=hostcfg,
                                   labels={"virtualfactory":"yes","UsedPort":str(port)},
                                   detach=True, tty=True, image="wikitolearndockeraccess/virtualfactory-firewall",
                                   hostname="dockeraccess"+str(port), ports=[6080],
                                   environment=confdict)
    c.start(container=container.get('Id'))
    firewallname = c.inspect_container(container=container.get('Id'))["Name"][1:]

    confdict = {}
    confdict['VNCPASS'] = get_pass(8)
    confdict['USER'] = usr
    if notimeout:
        confdict['NOTIMEOUT'] = '1'

    hostcfg = c.create_host_config(network_mode="container:" + firewallname,
                                   binds=['%s/%s:/home/user' % (homedir_folder, usr) ])
    container = c.create_container(name="virtualfactory-"+str(port),host_config=hostcfg,
                                   labels={"virtualfactory":"yes","UsedPort":str(port)},
                                   detach=True, tty=True, image=img,
                                   hostname="dockeraccess"+str(port), # ports=[port],
                                   environment=confdict, volumes=['%s/%s' % (homedir_folder, usr)])
    c.start(container=container.get('Id'))

    # get node address
    if swarm_cluster:
        nodeaddr = c.inspect_container(container=container.get('Id'))["Node"]["Addr"].split(':')[0]
    else:
        nodeaddr = "172.17.42.1"

    data = {"version":"0.3"}
    data["instance_path"] = "/socket/%s/%s" % (nodeaddr,port)
    data["instance_password"] = confdict['VNCPASS']
    data["host_port"] = external_port
    data["host_ssl_port"] = external_ssl_port
    data["host_name"] = hostn
    data["node_direct"] = direct_access_to_nodes == "yes"

    callback = request.args.get('callback', False)
    if callback:
       content = str(callback) + '(' + str(jsonify(data).data) + ')'
       resp = current_app.response_class(content, mimetype='application/json')
    else:
       resp = jsonify(data)

    return resp

if __name__ == '__main__':
    app.run(debug=True)
