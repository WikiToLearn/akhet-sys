#!/usr/bin/python
from flask import Flask, jsonify, abort, request
import os
import re
import random
import string
from docker.utils import create_host_config
from functools import cmp_to_key

from docker.client import Client as DockerClient
from docker.utils import compare_version

MINIMUM_API_VERSION = '1.14'

def get_api_version(*versions):
    # compare_version is backwards
    def cmp(a, b):
        return -1 * compare_version(a, b)
    return min(versions, key=cmp_to_key(cmp))


version_client = DockerClient(base_url='unix://var/run/docker.sock', version=MINIMUM_API_VERSION)
version = get_api_version('1.18', version_client.version()['ApiVersion'])

c = DockerClient(base_url='unix://var/run/docker.sock', version=version)

for d in c.containers(all=True,filters={"status":"exited"}):
	c.remove_container(d)
