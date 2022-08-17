# Define Mosquitto version
ARG MOSQUITTO_VERSION=2.0.15
# Define libwebsocket version
ARG LWS_VERSION=4.2.2

# Use debian:stable-slim as a builder for Mosquitto and dependencies.
FROM debian:stable-slim as mosquitto_builder
ARG MOSQUITTO_VERSION
ARG LWS_VERSION

# Get mosquitto build dependencies.
RUN set -ex; \
    apt-get update; \
    apt-get install -y wget build-essential cmake libssl-dev libcjson-dev

# Get libwebsocket. Debian's libwebsockets is too old for Mosquitto version > 2.x so it gets built from source.
RUN set -ex; \
    wget https://github.com/warmcat/libwebsockets/archive/v${LWS_VERSION}.tar.gz -O /tmp/lws.tar.gz; \
    mkdir -p /build/lws; \
    tar --strip=1 -xf /tmp/lws.tar.gz -C /build/lws; \
    rm /tmp/lws.tar.gz; \
    cd /build/lws; \
    cmake . \
        -DCMAKE_BUILD_TYPE=MinSizeRel \
        -DCMAKE_INSTALL_PREFIX=/usr \
        -DLWS_IPV6=ON \
        -DLWS_WITHOUT_BUILTIN_GETIFADDRS=ON \
        -DLWS_WITHOUT_CLIENT=ON \
        -DLWS_WITHOUT_EXTENSIONS=ON \
        -DLWS_WITHOUT_TESTAPPS=ON \
        -DLWS_WITH_HTTP2=OFF \
        -DLWS_WITH_SHARED=OFF \
        -DLWS_WITH_ZIP_FOPS=OFF \
        -DLWS_WITH_ZLIB=OFF \
        -DLWS_WITH_EXTERNAL_POLL=ON; \
    make -j "$(nproc)"; \
    rm -rf /root/.cmake

WORKDIR /app

RUN mkdir -p mosquitto/auth mosquitto/conf.d

RUN wget http://mosquitto.org/files/source/mosquitto-${MOSQUITTO_VERSION}.tar.gz

RUN tar xzvf mosquitto-${MOSQUITTO_VERSION}.tar.gz

# Build mosquitto.
RUN set -ex; \
    cd mosquitto-${MOSQUITTO_VERSION}; \
    make CFLAGS="-Wall -O2 -I/build/lws/include" LDFLAGS="-L/build/lws/lib" WITH_WEBSOCKETS=yes; \
    make install;

# Use golang:latest as a builder for the Mosquitto Go Auth plugin.
FROM --platform=$BUILDPLATFORM golang:latest AS go_auth_builder

ENV CGO_CFLAGS="-I/usr/local/include -fPIC"
ENV CGO_LDFLAGS="-shared -Wl,-unresolved-symbols=ignore-all"
ENV CGO_ENABLED=1

# Bring TARGETPLATFORM to the build scope
ARG TARGETPLATFORM
ARG BUILDPLATFORM

# Install TARGETPLATFORM parser to translate its value to GOOS, GOARCH, and GOARM
COPY --from=tonistiigi/xx:golang / /
RUN go env

# Install needed libc and gcc for target platform.
RUN set -ex; \
  if [ ! -z "$TARGETPLATFORM" ]; then \
    case "$TARGETPLATFORM" in \
  "linux/arm64") \
    apt update && apt install -y gcc-aarch64-linux-gnu libc6-dev-arm64-cross \
    ;; \
  "linux/arm/v7") \
    apt update && apt install -y gcc-arm-linux-gnueabihf libc6-dev-armhf-cross \
    ;; \
  "linux/arm/v6") \
    apt update && apt install -y gcc-arm-linux-gnueabihf libc6-dev-armel-cross libc6-dev-armhf-cross \
    ;; \
  esac \
  fi

WORKDIR /app
COPY --from=mosquitto_builder /usr/local/include/ /usr/local/include/

COPY ./ ./
RUN set -ex; \
    go build -buildmode=c-archive go-auth.go; \
    go build -buildmode=c-shared -o go-auth.so; \
	  go build pw-gen/pw.go

#Start from a new image.
FROM debian:stable-slim

RUN set -ex; \
    apt update; \
    apt install -y libc-ares2 openssl uuid tini wget libssl-dev libcjson-dev

RUN mkdir -p /var/lib/mosquitto /var/log/mosquitto
RUN set -ex; \
    groupadd mosquitto; \
    useradd -s /sbin/nologin mosquitto -g mosquitto -d /var/lib/mosquitto; \
    chown -R mosquitto:mosquitto /var/log/mosquitto/; \
    chown -R mosquitto:mosquitto /var/lib/mosquitto/

#Copy confs, plugin so and mosquitto binary.
COPY --from=mosquitto_builder /app/mosquitto/ /mosquitto/
COPY --from=go_auth_builder /app/pw /mosquitto/pw
COPY --from=go_auth_builder /app/go-auth.so /mosquitto/go-auth.so
COPY --from=mosquitto_builder /usr/local/sbin/mosquitto /usr/sbin/mosquitto

COPY --from=mosquitto_builder /usr/local/lib/libmosquitto* /usr/local/lib/

COPY --from=mosquitto_builder /usr/local/bin/mosquitto_passwd /usr/bin/mosquitto_passwd
COPY --from=mosquitto_builder /usr/local/bin/mosquitto_sub /usr/bin/mosquitto_sub
COPY --from=mosquitto_builder /usr/local/bin/mosquitto_pub /usr/bin/mosquitto_pub
COPY --from=mosquitto_builder /usr/local/bin/mosquitto_rr /usr/bin/mosquitto_rr

RUN ldconfig;

EXPOSE 1883 1884

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD [ "/usr/sbin/mosquitto" ,"-c", "/etc/mosquitto/mosquitto.conf" ]
