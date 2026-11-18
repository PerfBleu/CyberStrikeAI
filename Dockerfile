# syntax=docker/dockerfile:1

ARG DEBIAN_SUITE=trixie

FROM golang:1.25-${DEBIAN_SUITE} AS build

ARG GOPROXY=https://goproxy.cn,direct
ARG GOSUMDB=sum.golang.google.cn
ARG DEBIAN_SUITE
ENV GOPROXY=${GOPROXY} \
    GOSUMDB=${GOSUMDB} \
    DEBIAN_SUITE=${DEBIAN_SUITE}

COPY docker/setup-debian-tuna-apt.sh /tmp/
RUN DEBIAN_SUITE="${DEBIAN_SUITE}" sh /tmp/setup-debian-tuna-apt.sh \
    && apt-get update \
    && apt-get install -y --no-install-recommends gcc libc6-dev libsqlite3-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ENV CGO_ENABLED=1
RUN go build -trimpath -ldflags="-s -w" -o /out/cyberstrike-ai ./cmd/server

FROM golang:1.25-${DEBIAN_SUITE} AS go-tools

ARG GOPROXY=https://goproxy.cn,direct
ARG GOSUMDB=sum.golang.google.cn
ARG INSTALL_SECURITY_TOOLS=1
ARG DEBIAN_SUITE
ENV GOPROXY=${GOPROXY} \
    GOSUMDB=${GOSUMDB} \
    GOTOOLCHAIN=auto \
    DEBIAN_SUITE=${DEBIAN_SUITE} \
    PATH="/go/bin:${PATH}"

COPY docker/setup-debian-tuna-apt.sh /tmp/
RUN DEBIAN_SUITE="${DEBIAN_SUITE}" sh /tmp/setup-debian-tuna-apt.sh

COPY docker/go-tools.txt /tmp/go-tools.txt
RUN mkdir -p /go/bin \
    && if [ "${INSTALL_SECURITY_TOOLS}" = "1" ]; then \
      set -ux; \
      while IFS= read -r line || [ -n "${line}" ]; do \
        line="${line%%#*}"; \
        line="$(echo "${line}" | xargs)"; \
        [ -z "${line}" ] && continue; \
        go install -trimpath -ldflags="-s -w" "${line}" || printf 'go-tools: 跳过失败模块 %s\n' "${line}" >&2; \
      done < /tmp/go-tools.txt; \
    else \
      touch /go/bin/.keep; \
    fi

FROM debian:${DEBIAN_SUITE}-slim

ARG PIP_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple
ARG INSTALL_SECURITY_TOOLS=1
ARG DEBIAN_SUITE

ENV DEBIAN_SUITE=${DEBIAN_SUITE}

COPY docker/setup-debian-tuna-apt.sh /tmp/
RUN DEBIAN_SUITE="${DEBIAN_SUITE}" sh /tmp/setup-debian-tuna-apt.sh \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates curl libsqlite3-0 \
        python3 python3-venv python3-pip \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /opt/cyberstrike /data

COPY requirements.txt /tmp/requirements.txt
RUN python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --upgrade pip -i "${PIP_INDEX_URL}" \
    && /opt/venv/bin/pip install --no-cache-dir -i "${PIP_INDEX_URL}" -r /tmp/requirements.txt \
    && rm /tmp/requirements.txt

ENV PATH="/opt/venv/bin:/usr/local/bin:${PATH}"

WORKDIR /opt/cyberstrike

COPY docker/apt-security-packages.txt docker/requirements-security-tools.txt \
     docker/install-security-tools.sh docker/mirrors.sh /opt/cyberstrike/
RUN chmod 755 /opt/cyberstrike/install-security-tools.sh

COPY --from=go-tools /go/bin/ /usr/local/bin/

RUN if [ "${INSTALL_SECURITY_TOOLS}" = "1" ]; then \
      DEBIAN_SUITE="${DEBIAN_SUITE}" PIP_INDEX_URL="${PIP_INDEX_URL}" /opt/cyberstrike/install-security-tools.sh; \
    fi

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
