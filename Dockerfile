FROM golang:1.23-alpine as builder

WORKDIR /workspace

COPY go.mod go.sum main.go ./
COPY pkg pkg/
RUN go mod download

RUN CGO_ENABLED=0 go build -ldflags="-extldflags=-static" -o /cozy-proxy main.go

FROM scratch

COPY --from=builder /cozy-proxy /cozy-proxy

ENTRYPOINT ["/cozy-proxy"]
