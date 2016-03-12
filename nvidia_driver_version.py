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

c = Client(base_url="unix://var/run/docker.sock")
volumes_info = c.volumes()
volumes=volumes_info['Volumes']
for volume in volumes:
    if volume['Name'][0:14] == "nvidia_driver_":
        print volume['Name'][14:]
