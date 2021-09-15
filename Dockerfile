# Define Mosquitto version
ARG MOSQUITTO_VERSION=1.6.14

# Use debian:stable-slim as a builder for Mosquitto and dependencies.
FROM debian:stable-slim as mosquitto_builder
ARG MOSQUITTO_VERSION

# Get mosquitto build dependencies.
RUN apt update && apt install -y wget build-essential cmake libssl-dev  libcjson-dev

# Get libwebsocket. Debian's libwebsockets is too old for Mosquitto version > 2.x so it gets built from source.
RUN if [ "$(echo $MOSQUITTO_VERSION | head -c 1)" != 2 ]; then \
        apt install -y libwebsockets-dev ; \
    else \
        export LWS_VERSION=2.4.2  && \
        wget https://github.com/warmcat/libwebsockets/archive/v${LWS_VERSION}.tar.gz -O /tmp/lws.tar.gz && \
        mkdir -p /build/lws && \
        tar --strip=1 -xf /tmp/lws.tar.gz -C /build/lws && \
        rm /tmp/lws.tar.gz && \
        cd /build/lws && \
        cmake . \
            -DCMAKE_BUILD_TYPE=MinSizeRel \
            -DCMAKE_INSTALL_PREFIX=/usr \
            -DLWS_IPV6=ON \
            -DLWS_WITHOUT_BUILTIN_GETIFADDRS=ON \
            -DLWS_WITHOUT_CLIENT=ON \
            -DLWS_WITHOUT_EXTENSIONS=ON \
            -DLWS_WITHOUT_TESTAPPS=ON \
            -DLWS_WITH_SHARED=OFF \
            -DLWS_WITH_ZIP_FOPS=OFF \
            -DLWS_WITH_ZLIB=OFF && \
        make -j "$(nproc)" && \
        rm -rf /root/.cmake ; \
    fi

WORKDIR /app

RUN mkdir -p mosquitto/auth mosquitto/conf.d

RUN wget http://mosquitto.org/files/source/mosquitto-${MOSQUITTO_VERSION}.tar.gz
RUN tar xzvf mosquitto-${MOSQUITTO_VERSION}.tar.gz

# Build mosquitto.
RUN if [ "$(echo $MOSQUITTO_VERSION | head -c 1)" != 2 ]; then \
   cd mosquitto-${MOSQUITTO_VERSION} && make WITH_WEBSOCKETS=yes && make install ; \
   else \
   cd mosquitto-${MOSQUITTO_VERSION} && make CFLAGS="-Wall -O2 -I/build/lws/include" LDFLAGS="-L/build/lws/lib" WITH_WEBSOCKETS=yes && make install ; \
   fi

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
RUN if [ ! -z "$TARGETPLATFORM" ]; then \
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
RUN go build -buildmode=c-archive go-auth.go && \
    go build -buildmode=c-shared -o go-auth.so && \
	go build pw-gen/pw.go


#Start from a new image.
FROM debian:stable-slim

RUN apt update && apt install -y libc-ares2 openssl uuid tini

# Get libwebsocket. Debian's libwebsockets is too old for Mosquitto version > 2.x so it gets built from source.
RUN if [ "$(echo $MOSQUITTO_VERSION | head -c 1)" != 2 ]; then \
        apt install -y libwebsockets-dev ; \
    else \
        export LWS_VERSION=2.4.2  && \
        wget https://github.com/warmcat/libwebsockets/archive/v${LWS_VERSION}.tar.gz -O /tmp/lws.tar.gz && \
        mkdir -p /build/lws && \
        tar --strip=1 -xf /tmp/lws.tar.gz -C /build/lws && \
        rm /tmp/lws.tar.gz && \
        cd /build/lws && \
        cmake . \
            -DCMAKE_BUILD_TYPE=MinSizeRel \
            -DCMAKE_INSTALL_PREFIX=/usr \
            -DLWS_IPV6=ON \
            -DLWS_WITHOUT_BUILTIN_GETIFADDRS=ON \
            -DLWS_WITHOUT_CLIENT=ON \
            -DLWS_WITHOUT_EXTENSIONS=ON \
            -DLWS_WITHOUT_TESTAPPS=ON \
            -DLWS_WITH_SHARED=OFF \
            -DLWS_WITH_ZIP_FOPS=OFF \
            -DLWS_WITH_ZLIB=OFF && \
        make -j "$(nproc)" && \
        rm -rf /root/.cmake ; \
    fi

RUN mkdir -p /var/lib/mosquitto /var/log/mosquitto
RUN groupadd mosquitto \
    && useradd -s /sbin/nologin mosquitto -g mosquitto -d /var/lib/mosquitto \
    && chown -R mosquitto:mosquitto /var/log/mosquitto/ \
    && chown -R mosquitto:mosquitto /var/lib/mosquitto/

#Copy confs, plugin so and mosquitto binary.
COPY --from=mosquitto_builder /app/mosquitto/ /mosquitto/
COPY --from=go_auth_builder /app/pw /mosquitto/pw
COPY --from=go_auth_builder /app/go-auth.so /mosquitto/go-auth.so
COPY --from=mosquitto_builder /usr/local/sbin/mosquitto /usr/sbin/mosquitto

EXPOSE 1883 1884

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD [ "/usr/sbin/mosquitto" ,"-c", "/etc/mosquitto/mosquitto.conf" ]
