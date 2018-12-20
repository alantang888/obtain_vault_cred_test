FROM golang:1.11 AS builder

RUN mkdir /go/src/obtain_vault_cred_test
WORKDIR /go/src/obtain_vault_cred_test
COPY . .

RUN go get -d -v ./...
RUN go install -v ./...

CMD ["obtain_vault_cred_test"]



FROM alpine:3.7

RUN apk add --no-cache libc6-compat
COPY --from=builder /go/bin/obtain_vault_cred_test /usr/local/bin/obtain_vault_cred_test

ENTRYPOINT ["/usr/local/bin/obtain_vault_cred_test"]