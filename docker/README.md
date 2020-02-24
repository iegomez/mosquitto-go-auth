## Docker Images

This project offers two seperate images for building the plug-in using either released or local source code.

### Base Image
Since there are several issues with using `alpine` based images we are using `debian:stable-slim` for both our build and final image. The final image size is about 113 MB.

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
The Dockerfiles will also copy `conf` files found in the `/docker/conf` directory. For your safety we have commented these instructions out, so you will have to uncomment the instructions for the files to be copied.

### Docker Compose
This is just a working example of how a docker image could be built for this project and composed with other images such as a `redis` one for cache (check [docker-compose](docker-compose.yml)). Any contributions to make it better are very welcome.

