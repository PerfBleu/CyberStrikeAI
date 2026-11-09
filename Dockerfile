# syntax=docker/dockerfile:1

FROM golang:1.25-bookworm AS build

ARG GOPROXY=https://goproxy.cn,direct
ARG GOSUMDB=sum.golang.google.cn
ENV GOPROXY=${GOPROXY} \
    GOSUMDB=${GOSUMDB}

RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc libc6-dev libsqlite3-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ENV CGO_ENABLED=1
RUN go build -trimpath -ldflags="-s -w" -o /out/cyberstrike-ai ./cmd/server

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl libsqlite3-0 \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /opt/cyberstrike /data

WORKDIR /opt/cyberstrike

COPY --from=build /out/cyberstrike-ai /opt/cyberstrike/cyberstrike-ai
COPY config.example.yaml docker/entrypoint.sh /opt/cyberstrike/
COPY web /opt/cyberstrike/web
COPY tools /opt/cyberstrike/tools
COPY roles /opt/cyberstrike/roles
COPY skills /opt/cyberstrike/skills
COPY agents /opt/cyberstrike/agents
COPY knowledge_base /opt/cyberstrike/knowledge_base

RUN chmod 755 /opt/cyberstrike/cyberstrike-ai /opt/cyberstrike/entrypoint.sh

EXPOSE 8080 8081

VOLUME ["/data"]

ENTRYPOINT ["/opt/cyberstrike/entrypoint.sh"]
