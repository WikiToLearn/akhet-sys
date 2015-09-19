These scripts handle a web API for the creation/removal of web Dockers.

Each container will listen to an internal port assigned at runtime in the range START-END and will be shown to the world proxied by a web server.

It supports some parameters passed in as environment variables:
 * `DOCKERAPI_START_PORT`: The first available port for a virtual machine connection (default 1000)
 * `DOCKERAPI_END_PORT`: The first available port for a virtual machine connection (default 2000)
 * `DOCKERAPI_HOSTNAME`: Hostname for the (default: `dockers.wikifm.org`)
 * `DOCKERAPI_USER`: User for accessing the VM creation web api. (default: `admin`)
 * `DOCKERAPI_PASS`: Password for accessing the VM creation web api. (default: `admin`)
 * `DOCKERAPI_HOMEDIRS`: The absolute path (of the parent machine) where the persistent homedirs will be stored. The directories will be created as `$DOCKERAPI_HOMEDIRS/$USER` (default: `/var/homedirs/`).

## API Doc

The API is very simple. It expects a GET request in the following form:

    http://dockerfactory.wikifm.org/create?user=foo&image=bar

and will return a PATH like:

    /vnc.html?params=...

This will instanciate the docker image named `wikifm/bar`, and will mount `foo`'s homedirectory as home. Both `user` and `image` have to be alphanumeric (aka match `[a-zA-Z0-9\-]*`).
The instance will be available at `hostname`/`returned path`, so in this example:

    http://dockerfactory.wikifm.org/vnc.html?params=...

Run command example:

    docker run -ti --privileged --name virtualfactory -v /var/run/docker.sock:/var/run/docker.sock -p 80:80 -p 443:443 -e wikifm/virtualfactory 

To use existent key/certificate you must add '-v <host cert path>/:/certs/' and name files virtualfactory.key and virtualfactory.crt , docker will copy cert and key in the right place
