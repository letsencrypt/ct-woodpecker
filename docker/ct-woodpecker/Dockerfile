FROM golang:1.11-alpine as builder

RUN apk --update upgrade \
&& apk --no-cache --no-progress add git bash curl sqlite-libs sqlite-dev build-base \
&& rm -rf /var/cache/apk/*

ENV GOFLAGS=-mod=vendor

WORKDIR /ct-woodpecker-src
COPY . .

RUN go install -v ./cmd/ct-woodpecker/...

## main
FROM alpine:3.8

RUN apk update && apk add --no-cache --virtual ca-certificates

COPY --from=builder /go/bin/ct-woodpecker /usr/bin/ct-woodpecker
COPY --from=builder /ct-woodpecker-src/test/ /test/

CMD [ "/usr/bin/ct-woodpecker" ]
