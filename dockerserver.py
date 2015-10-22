# -*- coding: utf-8 -*-
#!/usr/bin/python
from flask import Flask, jsonify, abort, request, current_app, \
                  session, g, redirect, url_for, abort, render_template, flash

import os
import re
import random
import string
import ssl
import docker
import sys
import json

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

@app.route('/pull_images')
def pull_images():
    #print "Local images:"
    #for image in c.images(filters={"label":"virtualfactoryimage=true"}):
    #    print image['RepoTags']
    #for image in c.images():
    #    if len(image['RepoTags'])==1:
    #        print image['RepoTags'][0]=='<none>:<none>'
    print "Remote images:"
    for image in c.search('wikitolearndockeraccess'):
        if image['name'] != "wikitolearndockeraccess/virtualfactory":
           print "Pulling " + image['name']
           c.pull(image['name'], tag="latest")
    return "OK"

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


def do_instanciate(usr, img):
    if (len(usr) == 0):
        return "User not valid"
    if (len(img) == 0):
        return "Image not valid"

    img = "wikitolearndockeraccess/%s" % img # only support official images

    try:
        c.inspect_image(img)
    except:
        return "Missing image %s" % img

    user_home_dir = '%s/%s' % (homedir_folder, usr)

    confdict = {}
    confdict['NETWORK_TYPE'] = "limit"

    # create firewall docker to limit network
    hostcfg = c.create_host_config(port_bindings={6080:port},privileged=True)
    try:
        container = c.create_container(name="virtualfactory-fw-"+str(port),host_config=hostcfg,
                                       labels={"virtualfactory":"yes","UsedPort":str(port)},
                                       detach=True, tty=True, image="wikitolearndockeraccess/virtualfactory-firewall",
                                       hostname="dockeraccess"+str(port), ports=[6080],
                                       environment=confdict)
    except:
        return "Missing firewall image"
    c.start(container=container.get('Id'))
    firewallname = c.inspect_container(container=container.get('Id'))["Name"][1:]

    confdict = {}
    confdict['VNCPASS'] = get_pass(8)
    confdict['USER'] = usr
    if notimeout:
        confdict['NOTIMEOUT'] = '1'
    if shared:
        confdict['SHARED'] = '1'

    for var in user_env_vars:
        var_split=var.split('=')
        if len(var_split) == 2:
            var_name=var_split[0]
            var_value=var_split[1]
            print var_name, " => ", var_value
            if not confdict.has_key(var_name):
                confdict[var_name] = var_value

    hostcfg = c.create_host_config(network_mode="container:" + firewallname,
                                   binds=['%s/%s:/home/user' % (homedir_folder, usr) ])
    container = c.create_container(name="virtualfactory-"+str(port),host_config=hostcfg,
                                   labels={"virtualfactory":"yes","UsedPort":str(port)},
                                   detach=True, tty=True, image=img,
                                   hostname="dockeraccess"+str(port), # ports=[port],
                                   environment=confdict, volumes=[user_home_dir])
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

@app.route('/create', methods=['GET'])
def get_task():
    port = first_ok_port()
    if port == None:
        return "No machines available. Please try again later." # estimated time
    

    user_env_vars =  request.args.getlist('env')
    usr = validate(request.args.get('user'))
    img = validate(request.args.get('image'))
    notimeout = request.args.get('notimeout') == "yes"
    shared = request.args.get('shared') == "yes"
    
    return do_instanciate(usr, img)

#=======================
### WEB INTERFACE
#=======================


@app.route('/web/')
def show_entries():
    #cur = g.db.execute('select title, text from entries order by id desc')
    #entries = [dict(title=row[0], text=row[1]) for row in cur.fetchall()]
    return render_template('marketplace.html')
# login data -> env 

@app.route('/web/get_url')
def get_url():
    url = "//%s/" % hostn
    
    # Demo data
    usr = "User"
    img = "access-base"
    
    data = json.loads(do_instanciate(usr, img))
    vncopens = "%svnc.html?resize=scale&autoconnect=1&host=%s&port=%s&password=%s&path=%s"% (url, data['host_name'], data['host_port'], data['instance_password'], data['instance_path'])

    #cur = g.db.execute('select title, text from entries order by id desc')
    ##entries = [dict(title=row[0], text=row[1]) for row in cur.fetchall()]
    return render_template('url.html', url=vncopens)


if __name__ == '__main__':
    app.run()
