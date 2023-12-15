FROM golang:1.21.4-bookworm

RUN apt-get update && apt-get install -y \
                iputils-ping \
                jq \
                vim \
    && rm -rf /var/lib/apt/lists/*

RUN curl -L https://foundry.paradigm.xyz | bash
RUN /root/.foundry/bin/foundryup

WORKDIR /usr/src/suapps

COPY foundry.toml go.mod go.sum Makefile .

COPY examples /usr/src/suapps/examples
COPY framework /usr/src/suapps/framework
COPY lib /usr/src/suapps/lib
COPY suave-geth /usr/src/suapps/suave-geth
