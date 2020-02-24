## Docker Images

This project utilizes two `Dockerfiles` to give the option of building the `mosquitto-go-auth` plugin from either local or released source.

In both cases the resulting image contains a compiled and ready to run version of `mosquitto` with the `mosquitto-go-auth` plugin-in enabled.

### Base Image
Since there are several issues with using `alpine` based images we are using `debian:stable-slim` for both our build and final image. The final image size is about 128 MB.

Documented issues: 
- https://github.com/iegomez/mosquitto-go-auth/issues/14
- https://github.com/iegomez/mosquitto-go-auth/issues/15
- https://github.com/iegomez/mosquitto-go-auth/issues/20 

### Build method
The Dockerfiles utilize the [multi-stage](https://docs.docker.com/develop/develop-images/multistage-build/) build feature provided by the Docker CLI.

This feature allows you to optimize the final image output by copying select artifacts from the previous stage.

### mosquitto-go-auth Plug-in (Released Source)
The `Dockerfile` in the `/docker` directory compiles the plug-in using the specified `PLUGIN_VERSION` source code. The source code will come directly from our [GitHub Releases](https://github.com/iegomez/mosquitto-go-auth/releases).

### mosquitto-go-auth Plug-In (Local Source)
The `Dockerfile` located in the `root` (`/`) directory will compile the plug-in using your local source code.

### Mosquitto
Both Dockerfiles compile `mosquitto` using the source code from the version specified by `MOSQUITTO_VERSION`. 

>Mosquitto released versions can be found at https://mosquitto.org/files/source/

#### Conf files
The Dockerfiles can also copy `conf` files found in the `/docker/conf` project directory. 

>You will have to uncomment the instructions manually for the files to be copied.


### Docker Commands

In case you're not familiar with [Docker](https://docs.docker.com/), here are some basic commands for getting going.

Build Container:
```sh
# Ensure your PWD is either project root or /docker
docker build -t mosquitto-go-auth .
```

Run Container:
```sh
# This command will run the container and map the corresponding ports locally.
# You can access Mosquitto running inside the container on localhost:1883 and localhost:1884 (WebSockets)
docker run -it -p 1884:1884 -p 1883:1883 mosquitto-go-auth 
```

Stop Container:
```sh
docker stop $(docker ps -q --filter ancestor=mosquitto-go-auth)
```

Remove Container locally:
```sh
docker rmi $(docker images -q --filter reference='mosquitto-go-auth:*')
```

### Docker Compose
This is just a working example of how a docker image could be built for this project and composed with other images such as a `redis` one for cache (check [docker-compose](docker-compose.yml)). Any contributions to make it better are very welcome.

