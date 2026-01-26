FROM golang:1.21-alpine AS builder

# Install build dependencies for CGO (needed for sqlite3)
RUN apk add --no-cache gcc musl-dev

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .

# Build with CGO enabled for sqlite3
RUN CGO_ENABLED=1 go build -o authz .
RUN CGO_ENABLED=1 go build -o mint ./cmd/mint
RUN CGO_ENABLED=1 go build -o mintfs ./cmd/mintfs
RUN CGO_ENABLED=1 go build -o authz-admin ./cmd/authz-admin

FROM alpine:latest
RUN apk --no-cache add ca-certificates fuse libfido2
WORKDIR /app
COPY --from=builder /app/authz .
COPY --from=builder /app/mint .
COPY --from=builder /app/mintfs .
COPY --from=builder /app/authz-admin .

# Create data directory for SQLite database
RUN mkdir -p /data

# gRPC port for ext_authz
EXPOSE 9001
# HTTP port for API
EXPOSE 8080

CMD ["./authz"]
