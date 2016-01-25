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

class Bunch(object):
  def __init__(self, adict):
    self.__dict__.update(adict)
    
def try_read_config(section, option, default_argument=None):
    if akhetconfig.has_option(section, option):
        return akhetconfig.get(section, option)
    else:
        return default_argument
    
def read_group_config(profile_list, section_prefix):
    for profile in profile_list:
        profile_section = "{}:{}".format(section_prefix, profile)
        try:
            if akhetconfig.has_section(profile_section):
                profiles[section_prefix][profile] = {}
                for option in profile_options[section_prefix]:
                    profiles[section_prefix][profile][option] = try_read_config(profile_section, option)
            else:
                print "Missing ", profile, " profile for ", section_prefix
        except:
            print "Error loading ", section_prefix, ":", profile, " profile"
            
    if 'default' not in profile_list:
        print "Missing ", section_prefix, " default profile"
        profiles[section_prefix]['default'] = {}
        for option in profile_options[section_prefix]:
            profiles[section_prefix]['default'][option] = None
        
akhetconfig = ConfigParser.ConfigParser()
akhetconfig.read("/akhet.ini")

profile_options = {}
profile_options['network'] = ['defaultrule', 'allowddest', 'allowdport', 'blacklistdest', 'blacklistport']
profile_options['resource'] = ['ram']

profiles = {}
profiles['network'] = {}
profiles['resource'] = {}
            
network_profiles = try_read_config("Akhet", "network_profiles")
if network_profiles:
    read_group_config(network_profiles.split(','), "network")

resource_profiles = try_read_config("Akhet", "resource_profiles")
if resource_profiles:
    read_group_config(resource_profiles.split(','), "resource")

start_port = int(try_read_config("Akhet", "start_port", 1000))
end_port = int(try_read_config("Akhet", "end_port", 1050))
external_port = int(try_read_config("Akhet", "external_port", 80))
external_ssl_port = int(try_read_config("Akhet", "external_ssl_port", 443))

connection_method = try_read_config("Akhet", "connection_method", "socket")
remote_host = try_read_config("Akhet", "remote_host", "swarm-manager")
remote_port = int(try_read_config("Akhet", "remote_port", 2375))
ssl_key_file = try_read_config("Akhet", "ssl_key_file", "/akhet.key")
ssl_cert_file = try_read_config("Akhet", "ssl_cert_file", "/akhet.crt")
ssl_ca = try_read_config("Akhet", "ssl_ca", "/ca.crt")
socket_file = try_read_config("Akhet", "socket_file", "/var/run/docker.sock")

homedir_folder = try_read_config("Akhet", "homes_basepath", "/var/homedirs")

public_hostname = try_read_config("Akhet", "public_hostname", "localhost")

swarm_cluster = os.environ.get('USING_SWARM')
https_socket = os.environ.get('HTTPS_SOCKET')

if (connection_method == "socket"):  
    print "Connecting through socket..." 
    c = Client(base_url="unix:/{}".format(socket_file))
else:
    print "Connecting through TCP..."
    # tls auth for swarm cluster
    tls_config = TLSConfig(client_cert=(ssl_cert_file, ssl_key_file), verify=ssl_ca, ca_cert=ssl_ca)
    c = Client(base_url='https://{}:{}'.format(remote_host, remote_port), tls=tls_config)

print "...connected!"

app = Flask(__name__)
instanceRegistry = {}

def resp_json(data):
    replaydata = {"data":data, "version":"0.7"}
    callback = request.values.get('callback', False)
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
    print "Used ports: ",
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
    return resp_json({"deletedcount": count})

@app.route('/0.1/query', methods=['POST'])
def do_poll():
    token = validate(request.values.get('token', False))
    if (token):
        return resp_json(instanceRegistry[token])
        
###
# Short API doc
#
# Arguments to "create" (mandatory)
# * user
#     a string uniquely identifying the user. Max 32 char
# * image
#     the name of the docker image to start. must come from a trusted vendor
#
# Arguments to "create" (optional):
# * network TODO FIXME
#     the network profile to associate to the session instanciated (default: default)
# * resource TODO FIXME
#     the physical resources profile to associate to the session instanciated (default: default)
# * uid TODO
#     numerical id to assign as UID to the user created (default: 1000)
# * gid TODO
#     list of numerical ids to assign to the user in these fashions
#   # TODO: we have to accept either [1, 2, 3, ...]
#   # TODO: or [{"name": "group1", "id": 1}, {"name": "group2", "id": 2} ...]
# * storage TODO FIXME (quasi)
#     volatile or persistent (i.e. the home directory is mounted, default)
# * mountables TODO
#      list of mountables to mount in host
# * env FIXME
#      list of environmental variables to set to the guest
# * enable_cuda TODO 
#      if you want to enable cuda, pass anything to this parameter
###

@app.route('/0.1/create', methods=['GET', 'POST'])
def do_0_1_create():
    usr = validate(request.values.get('user', False))
    img = validate(request.values.get('image', False))
    network = validate(request.values.get('network', "default"))
    resource = validate(request.values.get('resource', "default"))
    uid = validate(request.values.get('uid', "1000")) # FIXME missing GIDs
    storage = validate(request.values.get('storage', False))
    enable_cuda = validate(request.values.get('enable_cuda', False))
    user_env_vars = request.values.getlist('env')
    
    notimeout = request.values.get('notimeout') == "yes"
    shared = request.values.get('shared') == "yes"

    if (len(usr) == 0):
        return resp_json({"errorno": 3, "error": "Invalid user"})
    if (len(img) == 0):
        return resp_json({"errorno":4, "error":"Image not valid"})

    threadId = get_pass(32)
    instanceRegistry[threadId] = {"status": 0}
    
    thread.start_new_thread(do_create, (Bunch(locals()),) )
    return resp_json({"token": threadId})

locker = threading.Lock()
##### threaded stuff
def do_create(confbunch):
    
    locker.acquire()
    
    port = first_ok_port()
    if port == None:
        return resp_json({"errorno": 2, "error": "No machines available. Please try again later."}) # estimated time
    
    completeImg = "akhet/%s" % confbunch.img # only support official images

    try:
        c.inspect_image(completeImg)
    except:
        return resp_json({"errorno":1, "error":"Missing image %s" % confbunch.img})


    user_home_dir = '%s/%s' % (homedir_folder, confbunch.usr)

    confdict = {}
    confdict['blacklistdest'] = None
    confdict['blacklistport'] = None
    confdict['allowddest'] = None
    confdict['allowdport'] = None
    confdict['defaultrule'] = None

    for k in confdict.keys():
        if confbunch.network in profiles["network"].keys():
            if profiles["network"][confbunch.network][k] != None:
                confdict[k] = ' '.join(profiles["network"][confbunch.network][k].split(","))

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
        containerFirewall = c.create_container( **container_fw_data)
    except:
        return resp_json({"errorno":5, "error":"Missing firewall image"})
    c.start(container=containerFirewall.get('Id'))
    firewallname = c.inspect_container(container=containerFirewall.get('Id'))["Name"][1:]

    confdict = {}
    confdict['VNCPASS'] = get_pass(8)
    confdict['USER'] = confbunch.usr
    confdict['UID'] = confbunch.uid
    if confbunch.notimeout:
        confdict['NOTIMEOUT'] = '1'
    if confbunch.shared:
        confdict['SHARED'] = '1'

    for var in confbunch.user_env_vars:
        var_split = var.split('=')
        if len(var_split) == 2:
            var_name = var_split[0]
            var_value = var_split[1]
            print var_name, " => ", var_value
            if not confdict.has_key(var_name):
                confdict[var_name] = var_value
    hostcfg_data={}
    container_data = {}

    if confbunch.resource in profiles["resource"].keys():
        if profiles["resource"][resource]['ram'] != None:
            hostcfg_data["mem_limit"] = profiles["resource"][resource]['ram']
    
    hostcfg_data["network_mode"]="container:" + firewallname
    hostcfg_data["binds"]=['%s/%s:/home/user' % (homedir_folder, confbunch.usr)]
    hostcfg = c.create_host_config(**hostcfg_data)
    
    
    container_data["name"] = "akhetinstance-" + str(port)
    container_data["host_config"] = hostcfg
    container_data["labels"] = {"akhetinstance":"yes", "UsedPort":str(port)}
    container_data["detach"] = True
    container_data["tty"] = True
    container_data["image"] = completeImg
    container_data["environment"] = confdict
    container_data["volumes"] = [user_home_dir]
    container = c.create_container( **container_data)
    c.start(container=container.get('Id'))

    # get node address
    # FIXME: check if we're really in a docker swarm
    if swarm_cluster:
        nodeaddr = c.inspect_container(container=containerFirewall.get('Id'))["Node"]["Addr"].split(':')[0]
    else:
        nodeaddr = c.inspect_container(container=containerFirewall.get('Id'))['NetworkSettings']['Networks']['bridge']['Gateway']
        
    data = {}
    data["instance_node"] = nodeaddr # return node where akhet instance is running
    data["instance_port"] = port # return node port where akhet instance is running
    data["instance_path"] = "/socket/%s/%s" % (nodeaddr, port) #  return socket port if ahket as proxy
    data["instance_password"] = confdict['VNCPASS']  # return password for vnc instance
    data["host_port"] = external_port # return akhet unssl port
    data["host_ssl_port"] = external_ssl_port # return akhet ssl port
    data["host_name"] = public_hostname # return akhet hostn
    data["status"] = 1
   
    instanceRegistry[confbunch.threadId] = data
    locker.release()
    
    #print "Waiting for the death of", container.get('Id')
    c.wait(container.get('Id'))
    del instanceRegistry[confbunch.threadId]

@app.route('/0.1/hostinfo')
def do_0_1_hostinfo():
    data = {}
    data["host_port"] = external_port # return akhet unssl port
    data["host_ssl_port"] = external_ssl_port # return akhet ssl port
    data["host_name"] = public_hostname # return akhet hostn

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

if __name__ == '__main__':
    app.run(debug=True)
