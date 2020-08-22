FROM golang:1.14-alpine

RUN apk add curl make build-base

RUN curl  -LO https://github.com/operator-framework/operator-sdk/releases/download/v1.0.0/operator-sdk-v1.0.0-x86_64-linux-gnu

RUN curl -LO https://github.com/operator-framework/operator-sdk/releases/download/v1.0.0/helm-operator-v1.0.0-x86_64-linux-gnu

RUN chmod +x operator-sdk-v1.0.0-x86_64-linux-gnu &&  mkdir -p /usr/local/bin/ &&  cp operator-sdk-v1.0.0-x86_64-linux-gnu /usr/local/bin/operator-sdk && rm operator-sdk-v1.0.0-x86_64-linux-gnu

RUN chmod +x helm-operator-v1.0.0-x86_64-linux-gnu &&  mkdir -p /usr/local/bin/ &&  cp helm-operator-v1.0.0-x86_64-linux-gnu /usr/local/bin/helm-operator && rm helm-operator-v1.0.0-x86_64-linux-gnu

WORKDIR /hexhibit/tokator