ARG GOVERSION=1.24

FROM docker.io/golang:${GOVERSION}-alpine AS build

WORKDIR /go/src/cs-custom-bouncer

RUN apk add --update --no-cache make git
COPY . .

RUN make build DOCKER_BUILD=1

FROM alpine:3.21
COPY --from=build /go/src/cs-custom-bouncer/crowdsec-custom-bouncer /usr/local/bin/crowdsec-custom-bouncer
COPY --from=build /go/src/cs-custom-bouncer/config/crowdsec-custom-bouncer.yaml /etc/crowdsec/bouncers/crowdsec-custom-bouncer.yaml

ENTRYPOINT ["/usr/local/bin/crowdsec-custom-bouncer", "-c", "/etc/crowdsec/bouncers/crowdsec-custom-bouncer.yaml"]
