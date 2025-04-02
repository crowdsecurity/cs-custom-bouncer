ARG GOVERSION=1.24

FROM docker.io/golang:${GOVERSION}-alpine AS build

WORKDIR /go/src/cs-custom-bouncer

RUN apk add --update --no-cache make git
COPY . .

RUN make build DOCKER_BUILD=1

FROM alpine:3.21
COPY --from=build /go/src/cs-custom-bouncer/crowdsec-custom-bouncer /crowdsec-custom-bouncer
COPY --from=build /go/src/cs-custom-bouncer/config/crowdsec-custom-bouncer.yaml /crowdsec-custom-bouncer.yaml

ENTRYPOINT ["/crowdsec-custom-bouncer", "-c", "/crowdsec-custom-bouncer.yaml"]
