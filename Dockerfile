FROM alpine:3.12 AS build

RUN mkdir /fastsub

COPY thisdns/ /fastsub/thisdns

RUN rm /fastsub/thisdns/CMakeCache.txt

RUN apk add --no-cache --virtual .build-deps \
        alpine-sdk \
        build-base \
        cmake \
        linux-headers \
        gcc \
    && cd /fastsub/thisdns \
    && cmake . \
    && make

FROM alpine:3.12

RUN apk add --no-cache \
    libstdc++ 

COPY --from=build /fastsub/thisdns/fastsub /usr/sbin

ENTRYPOINT ["/usr/sbin/fastsub"]
