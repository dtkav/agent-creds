FROM golang:1.24-alpine AS builder

# Install build dependencies for CGO (needed for sqlite3)
RUN apk add --no-cache gcc musl-dev

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .

# Build with CGO enabled for sqlite3
RUN CGO_ENABLED=1 go build -o vault .
RUN CGO_ENABLED=1 go build -o mint ./cmd/mint
RUN CGO_ENABLED=1 go build -o mintfs ./cmd/mintfs
RUN CGO_ENABLED=1 go build -o vault-admin ./cmd/vault-admin
RUN CGO_ENABLED=1 go build -o vault-ssh ./cmd/vault-ssh
RUN CGO_ENABLED=0 go build -o vaultctl ./cmd/vaultctl

FROM alpine:latest
RUN apk --no-cache add ca-certificates fuse libfido2
WORKDIR /app
COPY --from=builder /app/vault .
COPY --from=builder /app/mint .
COPY --from=builder /app/mintfs .
COPY --from=builder /app/vault-admin .
COPY --from=builder /app/vault-ssh .
COPY --from=builder /app/vaultctl .
COPY providers ./providers

# Standard reviewed adapters ship in /app/providers. Compose can additionally
# mount administrator-owned deployment extensions in /app/providers.d.
RUN mkdir -p /data /app/providers.d

# wish generates an Ed25519 keypair here on first start. /data is persistent.
ENV SSH_HOST_KEY=/data/vault_host_key

# gRPC port for ext_authz
EXPOSE 9001
# HTTP port for API
EXPOSE 8033
# SSH port for vault-ssh
EXPOSE 2222

# Run both vault and vault-ssh
CMD sh -c './vault & ./vault-ssh & wait'
