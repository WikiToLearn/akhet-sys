# -*- coding: utf-8 -*-
#!/usr/bin/python
import tarfile
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
import json
from time import sleep

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
profile_options['storage'] = ['hostpath','guestpath']

profiles['network'] = {}
profiles['resource'] = {}
profiles['storage'] = {}

network_profiles = try_read_config("Akhet", "network_profiles")
if network_profiles:
    read_group_config(network_profiles.split(','), "network")

resource_profiles = try_read_config("Akhet", "resource_profiles")
if resource_profiles:
    read_group_config(resource_profiles.split(','), "resource")

storages = try_read_config("Akhet", "storages")
if storages:
    read_group_config(storages.split(','), "storage")

wsvnc_port_start = int(try_read_config("Akhet", "wsvnc_port_start", 1000))
wsvnc_port_end = int(try_read_config("Akhet", "wsvnc_port_end", 1005))

ws_port_start = int(try_read_config("Akhet", "ws_port_start", 2000))
ws_port_end = int(try_read_config("Akhet", "ws_port_end", 2010))

http_port_start = int(try_read_config("Akhet", "http_port_start", 3000))
http_port_end = int(try_read_config("Akhet", "http_port_end", 3010))


external_port = int(try_read_config("Akhet", "external_port", 80))
external_ssl_port = int(try_read_config("Akhet", "external_ssl_port", 443))

connection_method = try_read_config("Akhet", "connection_method", "socket")
remote_host = try_read_config("Akhet", "remote_host", "swarm-manager")
remote_port = int(try_read_config("Akhet", "remote_port", 2375))
ssl_key_file = try_read_config("Akhet", "ssl_key_file", "/akhet.key")
ssl_cert_file = try_read_config("Akhet", "ssl_cert_file", "/akhet.crt")
ssl_ca = try_read_config("Akhet", "ssl_ca", "/ca.crt")
socket_file = try_read_config("Akhet", "socket_file", "/var/run/docker.sock")


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

def get_random_string(n):
    return ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(n))

def image_validate(image,alsobase=True):
    status = False
    allowed_namespaces = ["akhet"]
    if alsobase:
        allowed_namespaces.append("akhetbase")
    for allowed_namespace in allowed_namespaces:
        if image.startswith("{}/".format(allowed_namespace)):
            status = True
    return status

def validate(test_str):
    try:
        p = re.compile(u'[a-zA-Z0-9\-:]*')
        p = re.compile(u'.*')
        return re.search(p, test_str).group(0)
    except:
        return ""

def port_used(ports_list = []):
    print("Used ports: ",)
    print(ports_list)
    list_containers = c.containers(all=True, filters={"label":"akhetinstance=yes"})#, quiet=True)
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

def wsvnc_port_first_free(used_ports_list=[]):
    ports_list = port_used(used_ports_list)
    try_port = wsvnc_port_start
    port_found = False
    while try_port <= (wsvnc_port_end+1) and not port_found:
        if try_port in ports_list:
            try_port += 1
        else:
            port_found = True

    if try_port <= wsvnc_port_end:
        print("Port selected {}".format(try_port))
        return try_port
    else:
        return None

def ws_port_first_free(used_ports_list=[]):
    ports_list = port_used(used_ports_list)
    try_port = ws_port_start
    port_found = False
    while try_port <= (ws_port_end+1) and not port_found:
        if try_port in ports_list:
            try_port += 1
        else:
            port_found = True

    if try_port <= ws_port_end:
        print("Port selected {}".format(try_port))
        return try_port
    else:
        return None

def http_port_first_free(used_ports_list=[]):
    ports_list = port_used(used_ports_list)
    try_port = http_port_start
    port_found = False
    while try_port <= (http_port_end+1) and not port_found:
        if try_port in ports_list:
            try_port += 1
        else:
            port_found = True

    if try_port <= http_port_end:
        print("Port selected {}".format(try_port))
        return try_port
    else:
        return None

@app.route('/')
def index():
    return resp_json("Akhet")

@app.route('/gc')
@app.route('/0.8/gc')
def do_0_8_gc():
    count = 0
    # Garbage collect
    for d in c.containers(all=True, filters={"status":"exited", "label":"akhetinstance=yes"}):
        print("Removing " + str(d["Image"]) + " " + str(d["Labels"]["UsedVNCPort"]))
        try:
            c.remove_container(d)
        except Exception as e:
            pass
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
# * user_label
#     User display name
# * network
#     the network profile to associate to the session instanciated (default: default)
# * resource
#     the physical resources profile to associate to the session instanciated (default: default)
# * uid
#     numerical id to assign as UID to the user created (default: 1000)
# * gid
#     list of numerical ids to assign to the user in these fashions
#     we have to accept [1, 2, 3, ...]
# * storages
#      list of storages to mount in host
# * env
#      list of environmental variables to set to the guest
# * notimeout
#      true/false to allow/disallow forever connections
# * shared
#      true/false to allow/disallow instance to be shared
# * additional_ws
#      list [80,443] of port for additional websockets
# * additional_http
#      list [80,443] of port for additional http
# * enable_cuda
#      if you want to enable cuda, pass anything to this parameter
###

@app.route('/0.8/instance', methods=['POST'])
def do_0_8_create():
    instance_data={}
    if request.headers['Content-Type'] != 'application/json':
        return({"errorno": 7, "error": "You have to send application/json"})

    if 'user' not in request.json:
        return resp_json({"errorno": 8, "error": "Missing user"})
    instance_data['request_user'] = validate(request.json['user'])

    if 'image' not in request.json:
        return resp_json({"errorno": 9, "error": "Missing image"})
    instance_data['request_img'] = validate(request.json['image'])

    if 'network' in request.json:
        instance_data['request_network'] = validate(request.json['network'])
    else:
        instance_data['request_network'] = "default"

    if 'user_label' in request.json:
        instance_data['request_user_label'] = validate(request.json['user_label'])
    else:
        instance_data['request_user_label'] = "Akhet User"

    if 'resource' in request.json:
        instance_data['request_resource'] = validate(request.json['resource'])
    else:
        instance_data['request_resource'] = "default"

    if 'uid' in request.json:
        instance_data['request_uid'] = request.json['uid']
    else:
        instance_data['request_uid'] = "1000"

    if 'gids' in request.json:
        instance_data['request_gids'] = request.json['gids']
    else:
        instance_data['request_gids'] = ["1000"]

    if 'storages' in request.json:
        instance_data['request_storages'] = request.json['storages']
    else:
        instance_data['request_storages'] = ["default"]

    if 'enable_cuda' in request.json:
        instance_data['request_enable_cuda'] = validate(request.json['enable_cuda'])
    else:
        instance_data['request_enable_cuda'] = False

    if 'env' in request.json:
        instance_data['request_env'] = request.json['env']
    else:
        instance_data['request_env'] = {}

    if 'notimeout' in request.json:
        instance_data['request_notimeout'] = validate(request.json['notimeout'])
    else:
        instance_data['request_notimeout'] = False

    if 'shared' in request.json:
        instance_data['request_shared'] = validate(request.json['shared'])
    else:
        instance_data['request_shared'] = False

    if 'additional_ws' in request.json:
        instance_data['request_additional_ws'] = request.json['additional_ws']
    else:
        instance_data['request_additional_ws'] = []

    if 'additional_http' in request.json:
        instance_data['request_additional_http'] = request.json['additional_http']
    else:
        instance_data['request_additional_http'] = []

    if (len(instance_data['request_user']) == 0):
        return resp_json({"errorno": 3, "error": "Invalid user"})
    if (len(instance_data['request_img']) == 0):
        return resp_json({"errorno": 4, "error":"Image not valid"})

    try:
        c.inspect_image(instance_data['request_img'])
    except:
        return resp_json({"errorno": 1, "error": "Missing image %s" % img})

    if not image_validate(instance_data['request_img']):
       return resp_json({"errorno": 6, "error": "Image %s not allowed" % img})

    instance_data['status']  = 0

    locker.acquire()
    token = get_random_string(32)
    instance_data['token']  = token
    instanceRegistry[token] = instance_data
    locker.release()

    _thread.start_new_thread(do_create, (token,) )
    return resp_json(instanceRegistry[token])

locker = threading.Lock()

##### threaded stuff
def do_create(token):
    confbunch = Bunch(instanceRegistry[token])
    additional_ws_binding = {}
    additional_http_binding = {}
    additional_used_ports=[]

    locker.acquire()
    port = wsvnc_port_first_free(additional_used_ports)

    missing_additional_ws_port = False
    for additional_ws_port in confbunch.request_additional_ws:
        additional_ws_binding[additional_ws_port] = ws_port_first_free(additional_used_ports)
        if additional_ws_binding[additional_ws_port] == None:
            missing_additional_ws_port = True
        else:
            additional_used_ports.append(additional_ws_binding[additional_ws_port])

    missing_additional_http_port = False
    for additional_http_port in confbunch.request_additional_http:
        additional_http_binding[additional_http_port] = http_port_first_free(additional_used_ports)
        if additional_http_binding[additional_http_port] == None:
            missing_additional_http_port = True
        else:
            additional_used_ports.append(additional_http_binding[additional_http_port])

    if port == None:
        instanceRegistry[token] = {"errorno": 2, "error": "No machines available. Please try again later."} # estimated time
        locker.release()
    elif missing_additional_ws_port:
        instanceRegistry[token] = {"errorno": 12, "error": "No ports available for additional ws. Please try again later."} # estimated time
        locker.release()
    elif missing_additional_http_port:
        instanceRegistry[token] = {"errorno": 13, "error": "No ports available for additional http. Please try again later."} # estimated time
        locker.release()
    else:
        # create the volumes mountpoints
        volumes = []
        volumes_bind = []
        for storage in confbunch.request_storages:
            string_placeholders = {}
            string_placeholders["username"] = confbunch.request_user

            hostpath  = profiles["storage"][storage]['hostpath'].format(**string_placeholders)
            guestpath = profiles["storage"][storage]['guestpath'].format(**string_placeholders)

            volumes.append(hostpath)
            volumes_bind.append('%s:%s' % (hostpath, guestpath))

        environment_fw = {}
        environment_fw['blacklistdest'] = None
        environment_fw['blacklistport'] = None
        environment_fw['allowddest'] = None
        environment_fw['allowdport'] = None
        environment_fw['defaultrule'] = None

        for k in environment_fw.keys():
            if confbunch.request_network in profiles["network"].keys():
                if profiles["network"][confbunch.request_network][k] != None:
                    environment_fw[k] = ' '.join(profiles["network"][confbunch.request_network][k].split(","))

        # create firewall docker to limit network
        try:

            fw_port_bindings = {6080:port}
            fw_ports = [6080]
            for binding in additional_ws_binding:
                fw_port_bindings[binding] = additional_ws_binding[binding]
                fw_ports.append(binding)
            for binding in additional_http_binding:
                fw_port_bindings[binding] = additional_http_binding[binding]
                fw_ports.append(binding)

            hostcfg_fw_data={}
            hostcfg_fw_data['port_bindings']=fw_port_bindings
            hostcfg_fw_data['privileged'] = True
            hostcfg_fw = c.create_host_config(**hostcfg_fw_data)

            container_fw_data = {}
            container_fw_data["name"] = "akhetinstance-fw-" + str(port)
            container_fw_data["host_config"] = hostcfg_fw
            container_fw_data["labels"] = {"akhetinstance":"yes", "UsedVNCPort":str(port), "UsedPorts":",".join(str(x) for x in additional_used_ports)}
            container_fw_data["detach"] = True
            container_fw_data["tty"] = True
            container_fw_data["image"] = "akhetbase/akhet-firewall"
            container_fw_data["hostname"] = "akhetinstance" + str(port)
            container_fw_data["ports"] = fw_ports
            container_fw_data["environment"] = environment_fw
            containerFirewall = c.create_container( **container_fw_data)
        except:
            print("ERROR: Missing firewall image")
            instanceRegistry[token] = {"errorno":5, "error":"Missing firewall image"}

        c.start(container=containerFirewall.get('Id'))
        firewallname = c.inspect_container(container=containerFirewall.get('Id'))["Name"][1:]

        environment = {}
        environment['AKHETBASE_VNCPASS'] = get_random_string(8)
        environment['AKHETBASE_USER'] = confbunch.request_user
        environment['AKHETBASE_USER_LABEL'] = confbunch.request_user_label
        environment['AKHETBASE_UID'] = confbunch.request_uid
        environment['AKHETBASE_GIDs'] = " ".join(str(x) for x in confbunch.request_gids)
        if confbunch.request_notimeout:
            environment['AKHETBASE_NOTIMEOUT'] = '1'
        if confbunch.request_shared:
            environment['AKHETBASE_SHARED'] = '1'

        for var in confbunch.request_env:
            var_name = "AKHET_{}".format(var)
            var_value = confbunch.request_env[var]
            if var_name not in environment:
                environment[var_name] = var_value
        hostcfg_data={}
        container_data = {}

        if confbunch.request_resource in profiles["resource"].keys():
            if profiles["resource"][confbunch.request_resource]['ram'] != None:
                hostcfg_data["mem_limit"] = profiles["resource"][confbunch.request_resource]['ram']

        hostcfg_data["network_mode"]="container:" + firewallname
        hostcfg_data["binds"] = volumes_bind

        if(cuda):
            if(confbunch.request_enable_cuda):
                cuda_devs=[]
                cuda_devs.append("/dev/nvidiactl")
                cuda_devs.append("/dev/nvidia-uvm")
                for d in cuda_devices:
                    cuda_devs.append(d)
                hostcfg_data["devices"] = cuda_devs

        hostcfg = c.create_host_config(**hostcfg_data)


        container_data["name"] = "akhetinstance-" + str(port)
        container_data["host_config"] = hostcfg
        container_data["labels"] = {"akhetinstance":"yes", "UsedVNCPort":str(port), "UsedPorts":",".join(str(x) for x in additional_used_ports)}
        container_data["detach"] = True
        container_data["tty"] = True
        container_data["image"] = confbunch.request_img
        container_data["environment"] = environment
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

        for binding in additional_http_binding:
            open("/var/www/http/allowedports/"+str(additional_http_binding[binding]) , 'a').close()
            open("/var/www/http/allowedhosts/"+nodeaddr  , 'a').close()

        additional_ws_binding_paths = {}
        for binding in additional_ws_binding:
            additional_ws_binding_paths[binding] = "/ws/%s/%s" % (nodeaddr, additional_ws_binding[binding])

        additional_http_binding_paths = {}
        for binding in additional_http_binding:
            additional_http_binding_paths[binding] = "/http/%s/%s" % (nodeaddr, additional_http_binding[binding])

        data = {}
        data["instance_node"] = nodeaddr # return node where akhet instance is running
        data["instance_port"] = port # return node port where akhet instance is running
        data["instance_path"] = "/wsvnc/%s/%s" % (nodeaddr, port) #  return wsvnc port if ahket as proxy
        data["instance_ws_paths"] = additional_ws_binding_paths
        data["instance_http_paths"] = additional_http_binding_paths
        data["instance_password"] = environment['AKHETBASE_VNCPASS']  # return password for vnc instance
        data["host_port"] = external_port # return akhet unssl port
        data["host_ssl_port"] = external_ssl_port # return akhet ssl port
        data["host_name"] = public_hostname # return akhet hostn
        data["status"] = 1
        data["docker_id"] = container.get('Id')


        print("Wait for VNC server")
        wait_for_vnc_server = True
        while wait_for_vnc_server:
            wait_vnc_server_exec = c.exec_create(container=container.get('Id'),cmd="cat /var/run/akhet/vnc-server")
            wait_vnc_server_exec_output = c.exec_start(exec_id=wait_vnc_server_exec).decode('utf-8')
            wait_vnc_server_exec_output_split = wait_vnc_server_exec_output.split('=')
            wait_for_vnc_server = (wait_vnc_server_exec_output_split[0] != "PORT")
            sleep(0.01)

        instanceRegistry[token] = data
        locker.release()

        # create a json file inside the docker to pass the akhet instance info inside the docker itself
        tmp_dir_name="/tmp/{}".format(token)
        tar_name="{}/akhet.tar".format(tmp_dir_name);
        info_file_name="{}/akhet.json".format(tmp_dir_name)
        os.mkdir(tmp_dir_name)
        text_file = open(info_file_name, "w")
        text_file.write(json.dumps(data))
        text_file.close()
        with tarfile.open(tar_name, "w") as tar:
            tar.add(info_file_name, filter=tarfile_info_akhet_json)
        c.put_archive(container=container.get('Id'),path="/",data=open(tar_name, "rb").read())
        os.remove(info_file_name)
        os.remove(tar_name)
        os.rmdir(tmp_dir_name)

        print("Waiting for the d)eath of ", container.get('Id'))

        c.wait(container.get('Id'))
        print("Death of ", container.get('Id'))

        locker.acquire()
        del instanceRegistry[token]
        locker.release()

def tarfile_info_akhet_json(tarinfo):
    tarinfo.uid = tarinfo.gid = 0
    tarinfo.uname = tarinfo.gname = "root"
    tarinfo.name = "/akhet.json"
    tarinfo.mode = 0o400
    return tarinfo

@app.route('/0.8/hostinfo')
def do_0_8_hostinfo():
    data = {}
    data["host_port"] = external_port # return akhet unssl port
    data["host_ssl_port"] = external_ssl_port # return akhet ssl port
    data["host_name"] = public_hostname # return akhet hostn

    return resp_json(data)

@app.route('/0.8/imagesonline')
def do_0_8_imagesonline():
    data = []
    for image in c.search('akhet'):
        if image_validate(image['name'],False):
            data.append(image['name'])
    return resp_json(data)

@app.route('/0.8/imageslocal')
def do_0_8_imageslocal():
    data = {}
    for image in c.images():
        for image_tag in image['RepoTags']:
            if image_validate(image_tag):
                image_info = image_tag.split(':')
                if image_info[1] == "latest":
                    if not image_info[0] in data:
                        inspect = c.inspect_image(image_tag)
                        versions=[]
                        for repo_tag in inspect['RepoTags']:
                            versions.append(repo_tag[len(image_info[0])+1:])
                        data[image_info[0]] = {"versions":versions}
    return resp_json(data)

if __name__ == '__main__':
    app.run(debug=True)
