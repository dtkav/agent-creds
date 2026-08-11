FROM golang:1.25-alpine AS build
RUN apk add --no-cache build-base
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=1 go build -trimpath -ldflags="-s -w" -o /out/agent-creds-tap .

FROM alpine:3.23
RUN apk add --no-cache ca-certificates && \
    addgroup -S tap && adduser -S -G tap -h /nonexistent tap && \
    mkdir /data && chown tap:tap /data
COPY --from=build /out/agent-creds-tap /usr/local/bin/agent-creds-tap
USER tap
ENTRYPOINT ["/usr/local/bin/agent-creds-tap"]
