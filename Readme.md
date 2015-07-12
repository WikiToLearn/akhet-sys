These scripts handle a web API for the creation/removal of web Dockers.

Each container will listen to an internal port assigned at runtime in the range START-END and will be shown to the world proxied by a web server.

It supports some parameters passed in as environment variables:
 * DOCKERAPI_START_PORT: The first available port for a virtual machine connection (default 1000)
 * DOCKERAPI_END_PORT: The first available port for a virtual machine connection (default 2000)
 * DOCKERAPI_HOSTNAME: Hostname for the (default: "dockers.wikifm.org")
 * DOCKERAPI_USER: User for accessing the VM creation web api. (default: "admin")
 * DOCKERAPI_PASS: Password for accessing the VM creation web api. (default: "admin")
