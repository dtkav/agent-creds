.PHONY: up down deploy deploy-vault build test clean-certs binaries

# Docker Compose
up:
	docker compose up --build

down:
	docker compose down

# Fly.io deployment
deploy: deploy-vault

deploy-vault:
	cd vault && fly deploy --local-only --flycast

build:
	docker build -t sandbox --build-arg USER_UID=$$(id -u) --build-arg USER_GID=$$(id -g) -f claude-dev/Dockerfile .

test:
	bin/arun curl -v https://api.stripe.com/v1/customers -H "Authorization: Bearer $$(cat /creds/stripe)"

# Build all binaries
binaries: bin/actl bin/adev bin/aenv bin/arun bin/odev bin/cdp-proxy bin/mint bin/mintfs bin/vault-admin bin/vault-ssh

# Root-level cmd binaries
bin/actl: cmd/actl/main.go cmd/actl/go.mod
	cd cmd/actl && go build -o ../../bin/actl .

bin/adev: cmd/adev/main.go cmd/adev/go.mod
	cd cmd/adev && go build -o ../../bin/adev .

bin/arun: cmd/arun/main.go cmd/arun/go.mod
	cd cmd/arun && go build -o ../../bin/arun .

bin/aenv: cmd/aenv/main.go cmd/aenv/go.mod
	cd cmd/aenv && go build -o ../../bin/aenv .

bin/odev: cmd/odev/main.go cmd/odev/go.mod
	cd cmd/odev && go build -o ../../bin/odev .

bin/cdp-proxy: cmd/cdp-proxy/main.go cmd/cdp-proxy/go.mod
	cd cmd/cdp-proxy && go build -o ../../bin/cdp-proxy .

# Vault binaries (share vault/go.mod)
bin/mint: vault/cmd/mint/main.go vault/go.mod
	cd vault && go build -o ../bin/mint ./cmd/mint

bin/mintfs: vault/cmd/mintfs/main.go vault/go.mod
	cd vault && go build -o ../bin/mintfs ./cmd/mintfs

bin/vault-admin: vault/cmd/vault-admin/main.go vault/go.mod
	cd vault && go build -o ../bin/vault-admin ./cmd/vault-admin

bin/vault-ssh: vault/cmd/vault-ssh/main.go vault/go.mod
	cd vault && go build -o ../bin/vault-ssh ./cmd/vault-ssh

# Remove generated certs (forces regeneration on next adev run)
clean-certs:
	rm -rf generated/certs
