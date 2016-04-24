# -*- coding: utf-8 -*-
#!/usr/bin/python
import configparser
import htpasswd
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
import _thread
import threading
import sys

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
                print("Missing ", profile, " profile for ", section_prefix)
        except:
            print("Error loading ", section_prefix, ":", profile, " profile")

    if 'default' not in profile_list:
        print("Missing ", section_prefix, " default profile")
        profiles[section_prefix]['default'] = {}
        for option in profile_options[section_prefix]:
            profiles[section_prefix]['default'][option] = None

profiles = {}
profile_options = {}
        
akhetconfig = configparser.ConfigParser()
akhetconfig.read("/akhet.ini")

profile_options['network'] = ['defaultrule', 'allowddest', 'allowdport', 'blacklistdest', 'blacklistport']
profile_options['resource'] = ['ram']
profile_options['mountable'] = ['hostpath','guestpath']

profiles['network'] = {}
profiles['resource'] = {}
profiles['mountable'] = {}

network_profiles = try_read_config("Akhet", "network_profiles")
if network_profiles:
    read_group_config(network_profiles.split(','), "network")

resource_profiles = try_read_config("Akhet", "resource_profiles")
if resource_profiles:
    read_group_config(resource_profiles.split(','), "resource")

mountables = try_read_config("Akhet", "mountables")
if mountables:
    read_group_config(mountables.split(','), "mountable")

wsvnc_port_start = int(try_read_config("Akhet", "wsvnc_port_start", 1000))
wsvnc_port_end = int(try_read_config("Akhet", "wsvnc_port_end", 1005))

ws_port_start = int(try_read_config("Akhet", "ws_port_start", 2000))
ws_port_end = int(try_read_config("Akhet", "ws_port_end", 2005))

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

swarm_cluster = (try_read_config("Akhet", "swarm_cluster", "off") == "on")

http_username = try_read_config("Akhet", "username", "akhetuser")
http_password = try_read_config("Akhet", "password", "akhetpass")

cuda =  try_read_config("Akhet", "cuda", "on") == "on"
cuda_devices_raw = try_read_config("Akhet", "cuda_devices", "")
cuda_devices = []
if len(cuda_devices_raw)>0:
    cuda_devices = cuda_devices_raw.split(',')

with htpasswd.Basic("/var/www/htpasswd") as userdb:
    try:
        userdb.add(http_username,http_password)
    except htpasswd.basic.UserExists as e:
        print(e)

if (connection_method == "socket"):  
    print("Connecting through socket...")
    c = Client(base_url="unix:/{}".format(socket_file))
else:
    print("Connecting through TCP...")
    # tls auth for swarm cluster
    tls_config = TLSConfig(client_cert=(ssl_cert_file, ssl_key_file), verify=ssl_ca, ca_cert=ssl_ca)
    c = Client(base_url='https://{}:{}'.format(remote_host, remote_port), tls=tls_config)

try:
    c.info()
except:
    print("Error during the connection to docker")
    sys.exit(1)

print("...connected!")
# load finished

app = Flask(__name__)
instanceRegistry = {}

def resp_json(data):
    replaydata = {"data":data, "version":"0.8"}
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

def port_used():
    list_containers = c.containers(all=True, filters={"label":"akhetinstance=yes"})#, quiet=True)
    ports_list = []
    for container in list_containers:
        try:
            my_port = int(container["Labels"]["UsedVNCPort"]) # this is to avoid name collision
            if my_port not in ports_list:
                ports_list.append(my_port)
        except:
            pass
        try:
            my_ports = container["Labels"]["UsedPorts"].split(',')
            for my_port_str in my_ports:
                my_port_int = int(my_port_str)
                if my_port_int not in ports_list:
                    ports_list.append(my_port_int)
        except:
            pass
        if 'Ports' in container:
            ports = container['Ports']
            for port in ports:
                try:
                    if port['PublicPort'] not in ports_list:
                        ports_list.append(port['PublicPort'])
                except:
                    continue;
    return ports_list

def wsvnc_port_first_free():
    ports_list = port_used()
    try_port = wsvnc_port_start
    port_found = False
    while try_port <= (wsvnc_port_end+1) and not port_found:
        if try_port in ports_list:
            try_port += 1
        else:
            port_found = True
        
    if try_port <= wsvnc_port_end:
        return try_port
    else:
        return None

def ws_port_first_free():
    ports_list = port_used()
    try_port = ws_port_start
    port_found = False
    while try_port <= (ws_port_end+1) and not port_found:
        if try_port in ports_list:
            try_port += 1
        else:
            port_found = True

    if try_port <= ws_port_end:
        return try_port
    else:
        return None
            
@app.route('/')
def index():
    return resp_json("Akhet")

@app.route('/gc')
@app.route('/0.8/gc')
def do_0_1_gc():
    count = 0
    # Garbage collect
    for d in c.containers(all=True, filters={"status":"exited", "label":"akhetinstance=yes"}):
        print("Removing " + str(d["Image"]) + " " + str(d["Labels"]["UsedVNCPort"]))
        c.remove_container(d)
        count = count + 1
    return resp_json({"deletedcount": count})

@app.route('/0.8/instance', methods=['GET'])
def do_poll():
    if request.headers['Content-Type'] != 'application/json':
        return({"errorno": 7, "error": "You have to send application/json"})

    if 'token' not in request.json:
        return resp_json({"errorno": 11, "error": "Invalid token '{}'".format(token)})

    token = validate(request.json['token'])
    if (token):
        if token in instanceRegistry:
            return resp_json(instanceRegistry[token])
        else:
            return resp_json({"errorno": 10, "error": "Token not found '{}'".format(token)})
    else:
        return resp_json({"errorno": 11, "error": "Invalid token '{}'".format(token)})

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

@app.route('/0.8/instance', methods=['POST'])
def do_0_1_create():
    if request.headers['Content-Type'] != 'application/json':
        return({"errorno": 7, "error": "You have to send application/json"})

    if 'user' not in request.json:
        return resp_json({"errorno": 8, "error": "Missing user"})
    usr = validate(request.json['user'])

    if 'image' not in request.json:
        return resp_json({"errorno": 9, "error": "Missing image"})
    img = validate(request.json['image'])

    if 'network' in request.json:
        network = validate(request.json['network'])
    else:
        network = "default"

    if 'resource' in request.json:
        resource = validate(request.json['resource'])
    else:
        resource = "default"

    if 'uid' in request.json:
        uid = request.json['uid']
    else:
        uid = "1000"

    if 'gids' in request.json:
        gids = request.json['gids']
    else:
        gids = ["1000"]

    if 'storage' in request.json:
        storage = validate(request.json['storage'])
    else:
        storage = "persistent"

    if 'mountables' in request.json:
        mountables = request.json['mountables']
    else:
        mountables = []

    if 'enable_cuda' in request.json:
        enable_cuda = validate(request.json['enable_cuda'])
    else:
        enable_cuda = False

    if 'env' in request.json:
        user_env_vars = request.json['env']
    else:
        user_env_vars = {}

    if 'notimeout' in request.json:
        notimeout = validate(request.json['notimeout'])
    else:
        notimeout = False

    if 'shared' in request.json:
        shared = validate(request.json['shared'])
    else:
        shared = False

    if 'additional_ws' in request.json:
        additional_ws = request.json['additional_ws']
    else:
        additional_ws = []

    if not img[0:6] == "akhet/":
       return resp_json({"errorno": 6, "error": "Image %s not allowed" % img})

    completeImg = "%s" % img # only support official images
    
    try:
        c.inspect_image(completeImg)
    except:
        return resp_json({"errorno": 1, "error": "Missing image %s" % img})

    if (len(usr) == 0):
        return resp_json({"errorno": 3, "error": "Invalid user"})
    if (len(img) == 0):
        return resp_json({"errorno": 4, "error":"Image not valid"})

    threadId = get_pass(32)
    instanceRegistry[threadId] = {"status": 0}
    
    _thread.start_new_thread(do_create, (Bunch(locals()),) )
    return resp_json({"token": threadId})

locker = threading.Lock()

##### threaded stuff
def do_create(confbunch):
    additional_ws_binding = {}

    locker.acquire()
    port = wsvnc_port_first_free()

    missing_additional_ws_port = False
    for additional_ws_port in confbunch.additional_ws:
        additional_ws_binding[additional_ws_port] = ws_port_first_free()
        if additional_ws_binding[additional_ws_port] == None:
            missing_additional_ws_port = True

    if port == None:
        instanceRegistry[confbunch.threadId] = {"errorno": 2, "error": "No machines available. Please try again later."} # estimated time
        locker.release()
    elif missing_additional_ws_port:
        instanceRegistry[confbunch.threadId] = {"errorno": 12, "error": "No ports available. Please try again later."} # estimated time
        locker.release()
    else:
        user_home_dir = '%s/%s' % (homedir_folder, confbunch.usr)
        volumes = []
        volumes_bind = []
        if confbunch.storage == "persistent":
            volumes.append(user_home_dir)
            volumes_bind.append('%s:/home/user' % user_home_dir)

        for mountable in confbunch.mountables:
            hostpath  = profiles["mountable"][mountable]['hostpath']
            guestpath = profiles["mountable"][mountable]['guestpath']
            volumes.append(hostpath)
            volumes_bind.append('%s:%s' % (hostpath, guestpath))

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
        try:
            fw_port_bindings = {6080:port}
            fw_ports = [6080]
            for binding in additional_ws_binding:
                fw_port_bindings[binding] = additional_ws_binding[binding]
                fw_ports.append(binding)
            hostcfg = c.create_host_config(port_bindings=fw_port_bindings, privileged=True)

            container_fw_data = {}
            container_fw_data["name"] = "akhetinstance-fw-" + str(port)
            container_fw_data["host_config"] = hostcfg
            container_fw_data["labels"] = {"akhetinstance":"yes", "UsedVNCPort":str(port), "UsedPorts":",".join(str(additional_ws_binding[x]) for x in additional_ws_binding)}
            container_fw_data["detach"] = True
            container_fw_data["tty"] = True
            container_fw_data["image"] = "akhetbase/akhet-firewall"
            container_fw_data["hostname"] = "akhetinstance" + str(port)
            container_fw_data["ports"] = fw_ports
            container_fw_data["environment"] = confdict
            containerFirewall = c.create_container( **container_fw_data)
        except:
            print("ERROR: Missing firewall image")
            instanceRegistry[confbunch.threadId] = {"errorno":5, "error":"Missing firewall image"}
        c.start(container=containerFirewall.get('Id'))
        firewallname = c.inspect_container(container=containerFirewall.get('Id'))["Name"][1:]

        confdict = {}
        confdict['AKHETBASE_VNCPASS'] = get_pass(8)
        confdict['AKHETBASE_USER'] = confbunch.usr
        confdict['AKHETBASE_USER_LABEL'] = "Akhet User"
        confdict['AKHETBASE_UID'] = confbunch.uid
        confdict['AKHETBASE_GIDs'] = " ".join(str(x) for x in confbunch.gids)
        if confbunch.notimeout:
            confdict['AKHETBASE_NOTIMEOUT'] = '1'
        if confbunch.shared:
            confdict['AKHETBASE_SHARED'] = '1'

        for var in confbunch.user_env_vars:
            var_name = "AKHET_{}".format(var)
            var_value = confbunch.user_env_vars[var]
            if var_name not in confdict:
                confdict[var_name] = var_value
        hostcfg_data={}
        container_data = {}

        if confbunch.resource in profiles["resource"].keys():
            if profiles["resource"][confbunch.resource]['ram'] != None:
                hostcfg_data["mem_limit"] = profiles["resource"][confbunch.resource]['ram']
    
        hostcfg_data["network_mode"]="container:" + firewallname
        hostcfg_data["binds"] = volumes_bind
    
        if(cuda):
            if(confbunch.enable_cuda):
                cuda_devs=[]
                cuda_devs.append("/dev/nvidiactl")
                cuda_devs.append("/dev/nvidia-uvm")
                for d in cuda_devices:
                    cuda_devs.append(d)
                hostcfg_data["devices"] = cuda_devs
        
        hostcfg = c.create_host_config(**hostcfg_data)
    
    
        container_data["name"] = "akhetinstance-" + str(port)
        container_data["host_config"] = hostcfg
        container_data["labels"] = {"akhetinstance":"yes", "UsedVNCPort":str(port), "UsedPorts":",".join(str(additional_ws_binding[x]) for x in additional_ws_binding)}
        container_data["detach"] = True
        container_data["tty"] = True
        container_data["image"] = confbunch.completeImg
        container_data["environment"] = confdict
        container_data["volumes"] = volumes
    
        container = c.create_container( **container_data)
        c.start(container=container.get('Id'))

        # get node address
        # FIXME: check if we're really in a docker swarm
        if swarm_cluster:
            nodeaddr = c.inspect_container(container=containerFirewall.get('Id'))["Node"]["Addr"].split(':')[0]
        else:
            nodeaddr = c.inspect_container(container=containerFirewall.get('Id'))['NetworkSettings']['Networks']['bridge']['Gateway']

        open("/var/www/wsvnc/allowedports/"+str(port) , 'a').close()
        open("/var/www/wsvnc/allowedhosts/"+nodeaddr  , 'a').close()


        for binding in additional_ws_binding:
            open("/var/www/ws/allowedports/"+str(additional_ws_binding[binding]) , 'a').close()
            open("/var/www/ws/allowedhosts/"+nodeaddr  , 'a').close()

        additional_ws_binding_paths = {}
        for binding in additional_ws_binding:
            additional_ws_binding_paths[binding] = "/ws/%s/%s" % (nodeaddr, additional_ws_binding[binding])

        data = {}
        data["instance_node"] = nodeaddr # return node where akhet instance is running
        data["instance_port"] = port # return node port where akhet instance is running
        data["instance_path"] = "/wsvnc/%s/%s" % (nodeaddr, port) #  return wsvnc port if ahket as proxy
        data["instance_ws_paths"] = additional_ws_binding_paths
        data["instance_password"] = confdict['AKHETBASE_VNCPASS']  # return password for vnc instance
        data["host_port"] = external_port # return akhet unssl port
        data["host_ssl_port"] = external_ssl_port # return akhet ssl port
        data["host_name"] = public_hostname # return akhet hostn
        data["status"] = 1
   
        instanceRegistry[confbunch.threadId] = data
        locker.release()
    
        print("Waiting for the death of", container.get('Id'))
        c.wait(container.get('Id'))
        del instanceRegistry[confbunch.threadId]

@app.route('/0.8/hostinfo')
def do_0_1_hostinfo():
    data = {}
    data["host_port"] = external_port # return akhet unssl port
    data["host_ssl_port"] = external_ssl_port # return akhet ssl port
    data["host_name"] = public_hostname # return akhet hostn

    return resp_json(data)

@app.route('/0.8/imagesonline')
def do_0_1_imagesonline():
    data = []
    for image in c.search('akhet'):
        if image['name'].startswith("akhet/"):
            data.append(image['name'])
    return resp_json(data)

@app.route('/0.8/imageslocal')
def do_0_1_imageslocal():
    data = {}
    for image in c.images():
        for image_tag in image['RepoTags']:
            if image_tag.startswith("akhet/"):
                image_info = image_tag.split(':')
                if image_info[1] == "latest":
                    if not image_info[0] in data:
                        inspect = c.inspect_image(image_tag)
                        data[image_info[0]] = {"Versions":inspect['RepoTags'],"Author":inspect['Author']}
    return resp_json(data)

if __name__ == '__main__':
    app.run(debug=False)
