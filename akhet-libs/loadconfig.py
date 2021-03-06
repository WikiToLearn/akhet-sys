#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import configparser
import htpasswd
import os
import os.path
from akhet_logger import akhet_logger

def try_read_config(section, option, default_argument=None):
    if akhetconfig.has_option(section, option):
        return akhetconfig.get(section, option)
    else:
        return default_argument

def read_group_config(profile_list, section_prefix,default_required=True):
    profiles_data = {}
    for profile in profile_list:
        profile_section = "{}:{}".format(section_prefix, profile)
        try:
            if akhetconfig.has_section(profile_section):
                profiles_data[profile] = {}
                for option in profile_options[section_prefix]:
                    profiles_data[profile][option] = try_read_config(profile_section, option)
            else:
                akhet_logger("Missing {} profile for {}".format(profile, section_prefix))
        except:
            akhet_logger("Error loading {}:{} profile".format(section_prefix,profile))

    if default_required and 'default' not in profile_list:
        akhet_logger("Missing {} default profile".format(section_prefix))
        profiles_data['default'] = {}
        for option in profile_options[section_prefix]:
            profiles_data['default'][option] = None
    return profiles_data

profile_options = {}
profile_options['network'] = ['defaultrule', 'allowddest', 'allowdport', 'blacklistdest', 'blacklistport']
profile_options['resource'] = ['ram']
profile_options['storage'] = ['hostpath','guestpath']

akhetconfig = configparser.ConfigParser()

config = {}
def load_config():
    global config
    global c
    global akhetconfig
    akhetconfig.read("/etc/akhet.ini")
    config = {}

    config['profiles'] = {}
    config['profiles']['network'] = {}
    config['profiles']['resource'] = {}
    config['profiles']['storage'] = {}

    network_profiles = try_read_config("Akhet", "network_profiles")
    if network_profiles:
        config['profiles']['network'] = read_group_config(network_profiles.split(','), "network")

    resource_profiles = try_read_config("Akhet", "resource_profiles")
    if resource_profiles:
        config['profiles']['resource'] = read_group_config(resource_profiles.split(','), "resource")

    storages = try_read_config("Akhet", "storages")
    if storages:
        config['profiles']['storage'] =read_group_config(storages.split(','), "storage")

    config['ports'] = {}
    config['ports']['wsvnc'] = {}
    config['ports']['wsvnc']['start'] = int(try_read_config("Akhet", "wsvnc_port_start", 1000))
    config['ports']['wsvnc']['end'] = int(try_read_config("Akhet", "wsvnc_port_end", 1005))

    config['ports']['ws'] = {}
    config['ports']['ws']['start'] = int(try_read_config("Akhet", "ws_port_start", 2000))
    config['ports']['ws']['end'] = int(try_read_config("Akhet", "ws_port_end", 2010))

    config['ports']['http'] = {}
    config['ports']['http']['start'] = int(try_read_config("Akhet", "http_port_start", 3000))
    config['ports']['http']['end'] = int(try_read_config("Akhet", "http_port_end", 3010))

    config['external'] = {}
    config['external']['port'] = int(try_read_config("Akhet", "external_port", 80))
    config['external']['port_ssl'] = int(try_read_config("Akhet", "external_ssl_port", 443))
    config['external']['hostname'] = try_read_config("Akhet", "public_hostname", "localhost")

    config['docker'] = {}
    config['docker']['connection_type'] = try_read_config("Akhet", "connection_method", "socket")
    config['docker']['remote'] = {}
    config['docker']['remote']['host'] = try_read_config("Akhet", "remote_host", "swarm-manager")
    config['docker']['remote']['port'] = int(try_read_config("Akhet", "remote_port", 2375))
    config['docker']['remote']['ssl_key_file'] = try_read_config("Akhet", "ssl_key_file", "/akhet.key")
    config['docker']['remote']['ssl_cert_file'] = try_read_config("Akhet", "ssl_cert_file", "/akhet.crt")
    config['docker']['remote']['ssl_ca'] = try_read_config("Akhet", "ssl_ca", "/ca.crt")
    config['docker']['socket_file'] = try_read_config("Akhet", "socket_file", "/var/run/docker.sock")

    config['docker']['swarm'] = try_read_config("Akhet", "swarm_cluster", "off") == "on"

    config['api'] = {}
    config['api']['username'] = try_read_config("Akhet", "api_username", "akhetuser")
    config['api']['password'] = try_read_config("Akhet", "api_password", "akhetpass")
    config['api']['whitelist'] = try_read_config("Akhet", "api_whitelist_ip", None)

    config['cuda'] = {}
    config['cuda']['available'] =  try_read_config("Akhet", "cuda", "off") == "on"
    cuda_devices_raw = try_read_config("Akhet", "cuda_devices", "")
    config['cuda']['devices'] = []
    if len(cuda_devices_raw)>0:
        config['cuda']['devices'] = cuda_devices_raw.split(',')

    acl_file = '/var/run/akhet/allowed-ip-api.txt'
    if os.path.isfile(acl_file):
        os.remove(acl_file)
    if config['api']['whitelist'] != None:
        target = open(acl_file, 'w')
        for row in config['api']['whitelist'].split(","):
            target.write("{}\n".format(row))
        target.close()
    with htpasswd.Basic("/var/run/akhet/htpasswd") as userdb:
        try:
            userdb.add(config['api']['username'],config['api']['password'])
        except htpasswd.basic.UserExists as e:
            akhet_logger(e)

    return config
