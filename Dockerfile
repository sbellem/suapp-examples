FROM golang:1.21.4-bookworm

ENV FOUNDRY_BIN /root/.foundry/bin
RUN curl -L https://foundry.paradigm.xyz | bash
RUN ${FOUNDRY_BIN}/foundryup

WORKDIR /usr/src/suapp-examples

COPY foundry.toml go.mod go.sum Makefile .

COPY examples /usr/src/suapp-examples/examples
COPY framework /usr/src/suapp-examples/framework
COPY lib /usr/src/suapp-examples/lib
COPY suave-geth /usr/src/suapp-examples/suave-geth

RUN ${FOUNDRY_BIN}/forge build
