#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys, os
sys.path.append(os.path.join(os.path.dirname(__file__), "akhet-libs"))

# our own modules
from loadconfig import load_config
from dockerconnect import docker_connect
import proxysecurity

from akhet_instance_registry import AkhetInstanceRegistry

#usefull stuff
from flask import Flask, current_app, jsonify, request
from werkzeug.contrib.fixers import ProxyFix

import tarfile
import random
import re
import string
import _thread
import threading
import json
from time import sleep
import datetime
import dateutil.parser
import logging
from logging.handlers import RotatingFileHandler

from akhet_logger import akhet_logger

config = load_config()
docker_client = docker_connect(config)

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app)

instance_registry = AkhetInstanceRegistry()

def resp_json(data):
    replaydata = {"data":data, "version":"0.8","version_minor":"2"}
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
    akhet_logger("Used ports: {}".format(ports_list))
    list_containers = docker_client.containers(all=True, filters={"label":"akhetinstance=yes"})#, quiet=True)
    for container in list_containers:
        try:
            my_port = int(container["Labels"]["akhetUsedVNCPort"]) # this is to avoid name collision
            if my_port not in ports_list:
                ports_list.append(my_port)
        except:
            pass
        try:
            my_ports = container["Labels"]["akhetUsedPorts"].split(',')
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
    try_port = config['ports']['wsvnc']['start']
    port_found = False
    while try_port <= (config['ports']['wsvnc']['end']+1) and not port_found:
        if try_port in ports_list:
            try_port += 1
        else:
            port_found = True

    if try_port <= config['ports']['wsvnc']['end']:
        akhet_logger("Port selected {}".format(try_port))
        return try_port
    else:
        return None

def ws_port_first_free(used_ports_list=[]):
    ports_list = port_used(used_ports_list)
    try_port = config['ports']['ws']['start']
    port_found = False
    while try_port <= (config['ports']['ws']['end']+1) and not port_found:
        if try_port in ports_list:
            try_port += 1
        else:
            port_found = True

    if try_port <= config['ports']['ws']['end']:
        akhet_logger("Port selected {}".format(try_port))
        return try_port
    else:
        return None

def http_port_first_free(used_ports_list=[]):
    ports_list = port_used(used_ports_list)
    try_port = config['ports']['http']['start']
    port_found = False
    while try_port <= (config['ports']['http']['end']+1) and not port_found:
        if try_port in ports_list:
            try_port += 1
        else:
            port_found = True

    if try_port <= config['ports']['http']['end']:
        akhet_logger("Port selected {}".format(try_port))
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
    for d in docker_client.containers(all=True, filters={"status":"running", "label":"akhetinstance=yes"}):
        cinfo=docker_client.inspect_container(container=d['Id'])
        started_time = dateutil.parser.parse( cinfo['State']['StartedAt'] )
        if 'akhetTTL' in cinfo['Config']['Labels']:
            instance_ttl = int(cinfo['Config']['Labels']['akhetTTL'])
            if instance_ttl != 0:
                if( (datetime.datetime.now().replace(tzinfo=None) - started_time.replace(tzinfo=None) ).total_seconds() > instance_ttl ):
                    docker_client.kill(container=d['Id'])

    for d in docker_client.containers(all=True, filters={"status":"exited", "label":"akhetinstance=yes"}):
        akhet_logger("Removing " + str(d["Image"]) + " " + str(d["Labels"]["akhetUsedVNCPort"]))
        try:
            docker_client.remove_container(d)
        except Exception as e:
            pass
        count = count + 1
    return resp_json({"deletedcount": count})

@app.route('/0.8/instance', methods=['GET'])
def do_poll():
    if request.args.get('token') == None:
        return resp_json({"errorno": 18, "error": "Missing token"})

    token = request.args.get('token')

    if (token):
        data = instance_registry.get(token)
        if data != None:
            return resp_json(data)
        else:
            return resp_json({"errorno": 10, "error": "Token not found '{}'".format(token)})
    else:
        return resp_json({"errorno": 11, "error": "Invalid token '{}'".format(token)})

@app.route('/0.8/instance', methods=['POST'])
def do_0_8_create():
    akhet_logger("New request")
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

    if 'env' in request.json:
        instance_data['request_env'] = request.json['env']
    else:
        instance_data['request_env'] = {}

    if 'notimeout' in request.json:
        instance_data['request_notimeout'] = request.json['notimeout']
    else:
        instance_data['request_notimeout'] = False

    if 'shared' in request.json:
        instance_data['request_shared'] = request.json['shared']
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

    if 'instance_ttl' in request.json:
        instance_data['request_instance_ttl'] = request.json['instance_ttl']
    else:
        instance_data['request_instance_ttl'] = 0

    if (len(instance_data['request_user']) == 0):
        return resp_json({"errorno": 3, "error": "Invalid user"})
    if (len(instance_data['request_img']) == 0):
        return resp_json({"errorno": 4, "error":"Image not valid"})

    if not image_validate(instance_data['request_img']):
       return resp_json({"errorno": 6, "error": "Image %s not allowed" % instance_data['request_img']})

    akhet_logger("Data valid")

    instance_data['status']  = 0

    token = instance_registry.get_token()
    akhet_logger("New token: {}".format(token))
    instance_data['token']  = token
    instance_registry.add_data(token,instance_data)

    _thread.start_new_thread(do_create, (token,) )
    return resp_json(instance_registry.get(token))

##### threaded stuff
def do_create(token):
    docker_inspect_image = None
    try:
        docker_inspect_image = docker_client.inspect_image(instance_registry.get(token)['request_img'])
    except:
        instance_registry.update_data(token, {"errorno": 1, "error": "Missing image %s" % instance_data['request_img']})

    if docker_inspect_image != None:
        additional_ws_binding = {}
        additional_http_binding = {}
        global_additional_used_ports=[]
        additional_used_ports=[]

        instance_registry.lock()
        wsvnc_port = wsvnc_port_first_free(global_additional_used_ports)

        missing_additional_ws_port = False
        for additional_ws_port in instance_registry.get(token)['request_additional_ws']:
            additional_ws_binding[additional_ws_port] = ws_port_first_free(global_additional_used_ports)
            if additional_ws_binding[additional_ws_port] == None:
                missing_additional_ws_port = True
            else:
                global_additional_used_ports.append(additional_ws_binding[additional_ws_port])

        missing_additional_http_port = False
        for additional_http_port in instance_registry.get(token)['request_additional_http']:
            additional_http_binding[additional_http_port] = http_port_first_free(global_additional_used_ports)
            if additional_http_binding[additional_http_port] == None:
                missing_additional_http_port = True
            else:
                global_additional_used_ports.append(additional_http_binding[additional_http_port])


        if wsvnc_port == None:
            instance_registry.update_data(token, {"errorno": 2, "error": "No machines available. Please try again later."},False) # estimated time
        elif missing_additional_ws_port:
            instance_registry.update_data(token, {"errorno": 12, "error": "No ports available for additional ws. Please try again later."},False) # estimated time
        elif missing_additional_http_port:
            instance_registry.update_data(token, {"errorno": 13, "error": "No ports available for additional http. Please try again later."},False) # estimated time
        else:
            for port in additional_ws_binding:
                additional_used_ports.append(port)
            for port in additional_http_binding:
                additional_used_ports.append(port)

            # create the volumes mountpoints
            volumes = []
            volumes_bind = []
            for storage in instance_registry.get(token)['request_storages']:
                string_placeholders = {}
                string_placeholders["username"] = instance_registry.get(token)['request_user']

                hostpath  = config['profiles']["storage"][storage]['hostpath'].format(**string_placeholders)
                guestpath = config['profiles']["storage"][storage]['guestpath'].format(**string_placeholders)

                volumes.append(guestpath)
                volumes_bind.append('%s:%s' % (hostpath,guestpath))

            environment_fw = {}
            environment_fw['blacklistdest'] = None
            environment_fw['blacklistport'] = None
            environment_fw['allowddest'] = None
            environment_fw['allowdport'] = None
            environment_fw['defaultrule'] = None

            for k in environment_fw.keys():
                if instance_registry.get(token)['request_network'] in config['profiles']["network"].keys():
                    if config['profiles']["network"][instance_registry.get(token)['request_network']][k] != None:
                        environment_fw[k] = ' '.join(config['profiles']["network"][instance_registry.get(token)['request_network']][k].split(","))

            containerFirewall = None
            # create firewall docker to limit network
            try:
                fw_port_bindings = {6080:wsvnc_port}
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
                hostcfg_fw = docker_client.create_host_config(**hostcfg_fw_data)

                container_fw_data = {}
                container_fw_data["name"] = "akhetinstance-fw-" + str(wsvnc_port)
                container_fw_data["host_config"] = hostcfg_fw
                container_fw_data["labels"] = {"akhetinstance":"yes", "akhetUsedVNCPort":str(wsvnc_port), "akhetUsedPorts":",".join(str(x) for x in additional_used_ports)}
                container_fw_data["detach"] = True
                container_fw_data["tty"] = True
                container_fw_data["image"] = "akhetbase/akhet-firewall"
                container_fw_data["hostname"] = "akhetinstance" + str(wsvnc_port)
                container_fw_data["ports"] = fw_ports
                container_fw_data["environment"] = environment_fw
                containerFirewall = docker_client.create_container( **container_fw_data)
            except:
                akhet_logger("ERROR: Missing firewall image ({})".format(token))
                instance_registry.update_data(token, {"errorno":5, "error":"Missing firewall image"},False)

            if containerFirewall != None:
                docker_client.start(container=containerFirewall.get('Id'))
                firewallname = docker_client.inspect_container(container=containerFirewall.get('Id'))["Name"][1:]

                environment = {}
                environment['AKHETBASE_VNCPASS'] = get_random_string(8)
                environment['AKHETBASE_USER'] = instance_registry.get(token)['request_user']
                environment['AKHETBASE_USER_LABEL'] = instance_registry.get(token)['request_user_label']
                environment['AKHETBASE_UID'] = instance_registry.get(token)['request_uid']
                environment['AKHETBASE_GIDs'] = " ".join(str(x) for x in instance_registry.get(token)['request_gids'])
                if instance_registry.get(token)['request_notimeout']:
                    environment['AKHETBASE_NOTIMEOUT'] = '1'
                if instance_registry.get(token)['request_shared']:
                    environment['AKHETBASE_SHARED'] = '1'

                for var in instance_registry.get(token)['request_env']:
                    var_name = "AKHET_{}".format(var)
                    var_value = instance_registry.get(token)['request_env'][var]
                    if var_name not in environment:
                        environment[var_name] = var_value
                hostcfg_data={}
                container_data = {}

                if instance_registry.get(token)['request_resource'] in config['profiles']["resource"].keys():
                    if config['profiles']["resource"][instance_registry.get(token)['request_resource']]['ram'] != None:
                        hostcfg_data["mem_limit"] = config['profiles']["resource"][instance_registry.get(token)['request_resource']]['ram']

                hostcfg_data["network_mode"]="container:" + firewallname


                if "akhetimagecuda" in docker_inspect_image["Config"]["Labels"]:
                    if(config['cuda']['available']):
                        cuda_devs=[]
                        cuda_devs.append("/dev/nvidiactl")
                        cuda_devs.append("/dev/nvidia-uvm")
                        for d in config['cuda']['devices']:
                            cuda_devs.append(d)
                        hostcfg_data["devices"] = cuda_devs

                        volumes_info = docker_client.volumes()
                        volumes_cuda_search=volumes_info['Volumes']
                        cuda_volume = None
                        for volume in volumes_cuda_search:
                            if volume['Driver'] == "nvidia-docker":
                                cuda_volume = volume['Name']

                        volumes_bind.append('%s:/usr/local/nvidia' % cuda_volume)
                    else:
                        instance_registry.update_data(token, {"errorno":20, "error":"This host has not CUDA support"},False)

                if "errorno" not in instance_registry.get(token):
                    hostcfg_data["binds"] = volumes_bind

                    hostcfg = docker_client.create_host_config(**hostcfg_data)

                    container_data["name"] = "akhetinstance-" + str(wsvnc_port)
                    container_data["host_config"] = hostcfg
                    container_data["labels"] = {"akhetinstance":"yes", "akhetTTL": str(instance_registry.get(token)['request_instance_ttl']), "akhetUsedVNCPort":str(wsvnc_port), "akhetUsedPorts":",".join(str(x) for x in additional_used_ports)}
                    container_data["detach"] = True
                    container_data["tty"] = True
                    container_data["image"] = instance_registry.get(token)['request_img']
                    container_data["environment"] = environment
                    container_data["volumes"] = volumes

                    container = docker_client.create_container( **container_data)
                    docker_client.start(container=container.get('Id'))

                    # get node address
                    if config['docker']['swarm']:
                        nodeaddr = docker_client.inspect_container(container=containerFirewall.get('Id'))["Node"]["Addr"].split(':')[0]
                    else:
                        nodeaddr = docker_client.inspect_container(container=containerFirewall.get('Id'))['NetworkSettings']['Networks']['bridge']['Gateway']

                    proxysecurity.set_wsvnc(True,nodeaddr,wsvnc_port)
                    proxysecurity.set_ws(True,nodeaddr,additional_ws_binding.keys())
                    proxysecurity.set_http(True,nodeaddr,additional_http_binding.keys())

                    additional_ws_binding_paths = {}
                    for binding in additional_ws_binding:
                        additional_ws_binding_paths[binding] = "/ws/%s/%s" % (nodeaddr, additional_ws_binding[binding])

                    additional_http_binding_paths = {}
                    for binding in additional_http_binding:
                        additional_http_binding_paths[binding] = "/http/%s/%s" % (nodeaddr, additional_http_binding[binding])

                    data = {}
                    data["instance_node"] = nodeaddr # return node where akhet instance is running
                    data["instance_port"] = wsvnc_port # return node port where akhet instance is running
                    data["instance_path"] = "/wsvnc/%s/%s" % (nodeaddr, wsvnc_port) #  return wsvnc port if ahket as proxy
                    data["instance_ws_paths"] = additional_ws_binding_paths
                    data["instance_http_paths"] = additional_http_binding_paths
                    data["instance_password"] = environment['AKHETBASE_VNCPASS']  # return password for vnc instance
                    data["host_port"] = config['external']['port'] # return akhet unssl port
                    data["host_ssl_port"] = config['external']['port_ssl'] # return akhet ssl port
                    data["host_name"] = config['external']['hostname'] # return akhet hostn
                    data["status"] = 1
                    data["docker_id"] = container.get('Id')


                    akhet_logger("Wait for VNC server ({})".format(token))
                    wait_for_vnc_server = True
                    while wait_for_vnc_server:
                        wait_vnc_server_exec = docker_client.exec_create(container=container.get('Id'),cmd="cat /var/run/akhet/vnc-server")
                        wait_vnc_server_exec_output = docker_client.exec_start(exec_id=wait_vnc_server_exec).decode('utf-8')
                        wait_vnc_server_exec_output_split = wait_vnc_server_exec_output.split('=')
                        wait_for_vnc_server = (wait_vnc_server_exec_output_split[0] != "PORT")
                        sleep(0.01)

                    akhet_logger("VNC server UP ({})".format(token))
                    instance_registry.update_data(token, data, False)

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
                    docker_client.put_archive(container=container.get('Id'),path="/",data=open(tar_name, "rb").read())
                    os.remove(info_file_name)
                    os.remove(tar_name)
                    os.rmdir(tmp_dir_name)

                    akhet_logger("Waiting for the death of {}  ({})".format(container.get('Id'),token))

                    docker_client.wait(container.get('Id'))
                    akhet_logger("Death of {}  ({})".format(container.get('Id'),token))

                    proxysecurity.set_wsvnc(False,nodeaddr,wsvnc_port)
                    proxysecurity.set_ws(False,nodeaddr,additional_ws_binding.keys())
                    proxysecurity.set_http(False,nodeaddr,additional_http_binding.keys())

    akhet_logger("Delete of {} instance".format(token))

    instance_registry.delete_data(token)

@app.route('/0.8/instance-resolution', methods=['GET'])
def do_0_8_instance_resolution_get():
    if request.args.get('token') == None:
        return resp_json({"errorno": 18, "error": "Missing token"})

    token = request.args.get('token')

    instance_data = instance_registry.get(token)

    vnc_server_exec = docker_client.exec_create(container=instance_data['docker_id'],cmd="/usr/local/bin/akhet-resolutions.sh get")
    vnc_server_exec_output = docker_client.exec_start(exec_id=vnc_server_exec).decode('utf-8').strip().split("\n")
    resolutions = []
    for row in vnc_server_exec_output:
        row_split_by_x = row.split('x')
        try:
            resolutions.append({'width':row_split_by_x[0],'height':row_split_by_x[1]})
        except:
            resolutions.append(row_split_by_x)
    return resp_json(resolutions)

@app.route('/0.8/instance-resolution', methods=['POST'])
def do_0_8_instance_resolution_post():
    if request.headers['Content-Type'] != 'application/json':
        return({"errorno": 7, "error": "You have to send application/json"})

    if 'token' not in request.json:
        return resp_json({"errorno": 18, "error": "Missing token"})
    token = request.json['token']

    if 'height' not in request.json:
        return resp_json({"errorno": 18, "error": "Missing height"})
    height = request.json['height']

    if 'width' not in request.json:
        return resp_json({"errorno": 18, "error": "Missing width"})
    width = request.json['width']

    instance_data = instance_registry.get(token)

    vnc_server_exec = docker_client.exec_create(container=instance_data['docker_id'],cmd="/usr/local/bin/akhet-resolutions.sh set {}x{}".format(width,height))
    vnc_server_exec_output = docker_client.exec_start(exec_id=vnc_server_exec).decode('utf-8').strip()
    return resp_json(vnc_server_exec_output)

def tarfile_info_akhet_json(tarinfo):
    tarinfo.uid = tarinfo.gid = 0
    tarinfo.uname = tarinfo.gname = "root"
    tarinfo.name = "/akhet.json"
    tarinfo.mode = 0o400
    return tarinfo

@app.route('/0.8/hostinfo')
def do_0_8_hostinfo():
    data = {}
    data["host_port"] = config['external']['port'] # return akhet unssl port
    data["host_ssl_port"] = config['external']['port_ssl'] # return akhet ssl port
    data["host_name"] = config['external']['hostname'] # return akhet hostn

    return resp_json(data)

@app.route('/0.8/imagesonline')
def do_0_8_imagesonline():
    data = []
    for image in docker_client.search('akhet'):
        if image_validate(image['name'],False):
            data.append(image['name'])
    return resp_json(data)

@app.route('/0.8/imageslocal')
def do_0_8_imageslocal():
    data = {}
    for image in docker_client.images():
        for image_tag in image['RepoTags']:
            if image_validate(image_tag,False):
                image_info = image_tag.split(':')
                if image_info[1] == "latest":
                    if not image_info[0] in data:
                        inspect = docker_client.inspect_image(image_tag)
                        versions=[]
                        for repo_tag in inspect['RepoTags']:
                            versions.append(repo_tag[len(image_info[0])+1:])
                        data[image_info[0]] = {"versions":versions}
    return resp_json(data)

if __name__ == '__main__':
    app.debug = True
    file_handler = RotatingFileHandler('/var/log/akhet/akhet.log', maxBytes=1024 * 1024 * 100, backupCount=20)
    file_handler.setLevel(logging.ERROR)
    app.logger.setLevel(logging.ERROR)
    app.logger.addHandler(file_handler)
    app.run()
