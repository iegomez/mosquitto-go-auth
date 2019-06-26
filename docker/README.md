### Docker image

This is an attempt on building a *not so heavy* image given the impossibility of using `alpine` based ones (see https://github.com/iegomez/mosquitto-go-auth/issues/14, https://github.com/iegomez/mosquitto-go-auth/issues/15 and https://github.com/iegomez/mosquitto-go-auth/issues/20).  

It uses an intermediate image based on `debian:stable-slim` to build both mosquitto and the plugin and later on copies the binaries to the final image, also absed in `debian:stable-slim`, which stands at 113 MB.  

The example `Dockerfile` will also copy `conf` files present at the current dir as well as set the versions for Go, mosquitto and the plugin. Please change values as needed.

This is just a working example of how a docker image could be built for this project. Any contributions to make it better are very welcome.