FROM golang:1.20.2-alpine as builder

RUN apk --update upgrade \
&& apk --no-cache --no-progress add git bash curl \
&& rm -rf /var/cache/apk/*

ENV CGO_ENABLED=0 GOFLAGS=-mod=vendor

WORKDIR /ct-woodpecker-src
COPY . .

RUN go install -v ./test/cttestsrv/cmd/ct-test-srv/...

## main
FROM alpine:3.17.3

RUN apk update && apk add --no-cache --virtual ca-certificates

COPY --from=builder /go/bin/ct-test-srv /usr/bin/ct-test-srv
COPY --from=builder /ct-woodpecker-src/test/ /test/

CMD [ "/usr/bin/ct-test-srv" ]
