# -*- coding: utf-8 -*-
#!/usr/bin/python
import ConfigParser
from docker import Client
from docker.client import Client
from docker.tls import TLSConfig
from flask import Flask
from flask import current_app
from flask import jsonify
from flask import request
import os
import random
import re
import string
import thread
import threading

akhetconfig = ConfigParser.ConfigParser()
akhetconfig.read("/akhet.ini")

profile_options = {}
profile_options['network'] = ['defaultrule', 'allowddest', 'allowdport', 'blacklistdest', 'blacklistport']
profile_options['resource'] = ['ram']

profiles = {}
for p in profile_options.keys():
    profiles[p] = {}
    options = profile_options[p]
    if akhetconfig.has_option("Akhet", p + "profiles"):
        for profilename in akhetconfig.get("Akhet", p + "profiles").split(','):
            try:
                if akhetconfig.has_section(p + ":" + profilename):
                    profiles[p][profilename] = {}
                    for o in options:
                        if akhetconfig.has_option(p + ":" + profilename, o):
                            profiles[p][profilename][o] = akhetconfig.get(p + ":" + profilename, o)
                        else:
                            profiles[p][profilename][o] = None
                else:
                    print "Missing ", profilename, " profile for ", p
            except:
                print "Error loading ", p, ":", profilename, " profile"

    if 'default' not in profiles[p]:
        print "Missing ", p, " default profile"
        profiles[p]['default'] = {}
        for o in options:
            profiles[p]['default'][o] = None


start_port = int(os.getenv('AKHET_START_PORT', 1000))
end_port = int(os.getenv('AKHET_END_PORT', 1050))
external_port = int(os.getenv('AKHET_EXTERNAL_PORT', 80))
external_ssl_port = int(os.getenv('AKHET_EXTERNAL_SSL_PORT', 443))
hostn = os.getenv('AKHET_HOSTNAME', "dockers.wikitolearn.org")
homedir_folder = os.getenv('AKHET_HOMEDIRS', "/var/homedirs/")

swarm_cluster = os.path.exists("/var/run/docker.sock") == False

if swarm_cluster:
    print "Using swarm cluster"
    # tls auth for swarm cluster
    tls_config = TLSConfig(client_cert=('/certs/akhet.crt', '/certs/akhet.key'), verify='/certs/ca.crt', ca_cert='/certs/ca.crt')
    c = Client(base_url='https://swarm-manager:2375', tls=tls_config) # connect to swarm manager node
else:
    print "Using single node"
    c = Client(base_url='unix:///var/run/docker.sock') # socket connection for single host

app = Flask(__name__)

def resp_json(data):
    replaydata = {"data":data, "version":"0.7"}
    callback = request.args.get('callback', False)
    if callback:
        content = str(callback) + '(' + str(jsonify(replaydata).data) + ')'
        resp = current_app.response_class(content, mimetype='application/json')
    else:
        resp = jsonify(replaydata)
    return resp

def get_pass(n):
    return ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(n))

def validate(test_str):
    try:
        p = re.compile(u'[a-zA-Z0-9\-:]*')
        p = re.compile(u'.*')
        return re.search(p, test_str).group(0)
    except:
        return ""

def first_ok_port():
    l = c.containers(all=True, filters={"label":"akhetinstance=yes"})#, quiet=True)
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
                #if port['PrivatePort'] not in ports_list: 
                #    ports_list.append(port['PrivatePort'])
            except:
                continue;
    print "Porte impegnate: ",
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
    return resp_json("Akhet")

@app.route('/gc')
@app.route('/0.1/gc')
def do_0_1_gc():
    count = 0
    # Garbage collect
    for d in c.containers(all=True, filters={"status":"exited", "label":"akhetinstance=yes"}):
        print "Removing " + str(d["Image"]) + " " + str(d["Labels"]["UsedPort"])
        c.remove_container(d)
        count = count + 1
    return resp_json({"deletedcount":count})

@app.route('/0.1/create', methods=['GET'])
def do_0_1_create():
    usr = validate(request.args.get('user', False))
    img = validate(request.args.get('image', False))
    network = validate(request.args.get('network', ""))
    resource = validate(request.args.get('resource', ""))
    
    if (len(network) == 0):
        network = "default"
    if (len(resource) == 0):
        resource = "default"
        
    user_env_vars = request.args.getlist('env')
    notimeout = request.args.get('notimeout') == "yes"
    shared = request.args.get('shared') == "yes"
    port = first_ok_port()
    if port == None:
        return resp_json({"errorno":2, "error":"No machines available. Please try again later."}) # estimated time
    
    if (len(usr) == 0):
        return resp_json({"errorno":3, "error":"User not valid"})
    if (len(img) == 0):
        return resp_json({"errorno":4, "error":"Image not valid"})

    img = "akhet/%s" % img # only support official images

    try:
        c.inspect_image(img)
    except:
        return resp_json({"errorno":1, "error":"Missing image %s" % img})

    user_home_dir = '%s/%s' % (homedir_folder, usr)

    confdict = {}
    confdict['blacklistdest'] = None
    confdict['blacklistport'] = None
    confdict['allowddest'] = None
    confdict['allowdport'] = None
    confdict['defaultrule'] = None

    for k in confdict.keys():
        if network in profiles["network"].keys():
            if profiles["network"][network][k] != None:
                confdict[k] = ' '.join(profiles["network"][network][k].split(","))

    # create firewall docker to limit network
    hostcfg = c.create_host_config(port_bindings={6080:port}, privileged=True)
    try:
        container_fw_data = {}
        container_fw_data["name"] = "akhetinstance-fw-" + str(port)
        container_fw_data["host_config"] = hostcfg
        container_fw_data["labels"] = {"akhetinstance":"yes", "UsedPort":str(port)}
        container_fw_data["detach"] = True
        container_fw_data["tty"] = True
        container_fw_data["image"] = "akhetbase/akhet-firewall"
        container_fw_data["hostname"] = "akhetinstance" + str(port)
        container_fw_data["ports"] = [6080]
        container_fw_data["environment"] = confdict
        container = c.create_container( **container_fw_data)
    except:
        return resp_json({"errorno":5, "error":"Missing firewall image"})
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
        var_split = var.split('=')
        if len(var_split) == 2:
            var_name = var_split[0]
            var_value = var_split[1]
            print var_name, " => ", var_value
            if not confdict.has_key(var_name):
                confdict[var_name] = var_value
    hostcfg_data={}
    container_data = {}
    if resource in profiles["resource"].keys():
        if profiles["resource"][resource]['ram'] != None:
            hostcfg_data["mem_limit"] = profiles["resource"][resource]['ram']
    
    hostcfg_data["network_mode"]="container:" + firewallname
    hostcfg_data["binds"]=['%s/%s:/home/user' % (homedir_folder, usr)]
    hostcfg = c.create_host_config(**hostcfg_data)
    
    
    container_data["name"] = "akhetinstance-" + str(port)
    container_data["host_config"] = hostcfg
    container_data["labels"] = {"akhetinstance":"yes", "UsedPort":str(port)}
    container_data["detach"] = True
    container_data["tty"] = True
    container_data["image"] = img
    container_data["environment"] = confdict
    container_data["volumes"] = [user_home_dir]
    container = c.create_container( **container_data)
    c.start(container=container.get('Id'))

    # get node address
    if swarm_cluster:
        nodeaddr = c.inspect_container(container=container.get('Id'))["Node"]["Addr"].split(':')[0]
    else:
        nodeaddr = os.getenv('AKHET_SINGLE_NODE_BR_IP', "172.17.42.1")

    data = {}
    data["instance_node"] = nodeaddr # return node where akhet instance is running
    data["instance_port"] = port # return node port where akhet instance is running
    data["instance_path"] = "/socket/%s/%s" % (nodeaddr, port) #  return socket port if ahket as proxy
    data["instance_password"] = confdict['VNCPASS']  # return password for vnc instance
    data["host_port"] = external_port # return akhet unssl port
    data["host_ssl_port"] = external_ssl_port # return akhet ssl port
    data["host_name"] = hostn # return akhet hostn
   
    return resp_json(data)

@app.route('/0.1/hostinfo')
def do_0_1_hostinfo():
    data = {}
    data["host_port"] = external_port # return akhet unssl port
    data["host_ssl_port"] = external_ssl_port # return akhet ssl port
    data["host_name"] = hostn # return akhet hostn

    return resp_json(data)

@app.route('/0.1/imagesonline')
def do_0_1_imagesonline():
    data = []
    for image in c.search('akhet'):
        if image['name'].startswith("akhet/"):
            data.append(image['name'][6:])
            #c.pull(image['name'], tag="latest")
    return resp_json(data)

@app.route('/0.1/imageslocal')
def do_0_1_imageslocal():
    data = {}
    for image in c.images():
        for image_tag in image['RepoTags']:
            if image_tag.startswith("akhet/"):
                image_info = image_tag[6:].split(':')
                if image_info[1] == "latest":
                    if not image_info[0] in data:
                        data[image_info[0]] = c.inspect_image(image_tag)
    return resp_json(data)

@app.route('/0.1/pullimage')
def do_0_1_pullimage():
    img = validate(request.args.get('image', False))
    
    if (len(img) == 0):
        return resp_json({"errorno":4, "error":"Image not valid"})

    for t in threading.enumerate():
        if t.getName() == "pull-" + img:
            return resp_json({"statusno":2, "message":"Pulling running..."})

    thread.start_new_thread(thread_pull_image, (img, c,))
    return resp_json({"statusno":1, "message":"Pulling started..."})

@app.route('/0.1/pullimagesystem')
def do_0_1_pullimagesystem():
    img = "akhetbase/akhet-firewall"
    thread.start_new_thread(thread_pull_image, (img, c,))
    return resp_json({"statusno":1, "message":"Pulling started..."})

def thread_pull_image(img, c):
    threading.currentThread().setName("pull-" + img)
    print threading.currentThread().getName()
    for line in c.pull("akhet/" + img, tag="latest", stream=True):
        print line
    threading.currentThread().setName("finished")
    print "End pulling " + img

if __name__ == '__main__':
    app.run(debug=True)
