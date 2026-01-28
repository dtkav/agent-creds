.PHONY: up down reload deploy deploy-proxy deploy-authz dev build test apply-changes discard-changes generate generate-fly clean-certs binaries

# Docker Compose (primary)
up: generate
	docker compose up --build

down:
	docker compose down

# Reload envoy with new certs/domains (doesn't touch sandbox or obsidian)
reload: generate
	docker compose restart envoy

# Fly.io deployment (requires .flycast routing)
deploy: deploy-authz deploy-proxy

deploy-proxy: generate-fly
	fly deploy --local-only --flycast

deploy-authz:
	cd authz && fly deploy --local-only --flycast

generate-fly: bin/generate
	@if [ ! -f authz/fly.toml ]; then echo "Error: authz/fly.toml not found. Create it with your Fly.io app name."; exit 1; fi
	$(eval AUTHZ_APP := $(shell grep "^app = " authz/fly.toml | sed "s/app = '\\(.*\\)'/\\1/"))
	./bin/generate --authz-address $(AUTHZ_APP).flycast:80 --port 8443 --proxy-host 127.0.0.1

build: generate
	docker build -t sandbox --build-arg USER_UID=$$(id -u) --build-arg USER_GID=$$(id -g) -f claude-dev/Dockerfile .

dev:
	bin/adev

apply-changes:
	@if [ -d claude-dev/overlay-changes ] && [ "$$(ls -A claude-dev/overlay-changes 2>/dev/null)" ]; then \
		cp -rv claude-dev/overlay-changes/. . && rm -rf claude-dev/overlay-changes; \
	else \
		echo "No changes to apply"; \
	fi

discard-changes:
	rm -rf claude-dev/overlay-changes

test:
	bin/arun curl -v https://api.stripe.com/v1/customers -H "Authorization: Bearer $$(cat /creds/stripe)"

# Build all binaries
binaries: bin/generate bin/actl bin/adev bin/aenv bin/odev bin/cdp-proxy bin/mint bin/mintfs bin/authz-admin bin/authz-ssh

# Root-level cmd binaries
bin/generate: cmd/generate/main.go cmd/generate/go.mod
	cd cmd/generate && go build -o ../../bin/generate .

bin/actl: cmd/actl/main.go cmd/actl/go.mod
	cd cmd/actl && go build -o ../../bin/actl .

bin/adev: cmd/adev/main.go cmd/adev/go.mod
	cd cmd/adev && go build -o ../../bin/adev .

bin/aenv: cmd/aenv/main.go cmd/aenv/go.mod
	cd cmd/aenv && go build -o ../../bin/aenv .

bin/odev: cmd/odev/main.go cmd/odev/go.mod
	cd cmd/odev && go build -o ../../bin/odev .

bin/cdp-proxy: cmd/cdp-proxy/main.go cmd/cdp-proxy/go.mod
	cd cmd/cdp-proxy && go build -o ../../bin/cdp-proxy .

# Authz binaries (share authz/go.mod)
bin/mint: authz/cmd/mint/main.go authz/go.mod
	cd authz && go build -o ../bin/mint ./cmd/mint

bin/mintfs: authz/cmd/mintfs/main.go authz/go.mod
	cd authz && go build -o ../bin/mintfs ./cmd/mintfs

bin/authz-admin: authz/cmd/authz-admin/main.go authz/go.mod
	cd authz && go build -o ../bin/authz-admin ./cmd/authz-admin

bin/authz-ssh: authz/cmd/authz-ssh/main.go authz/go.mod
	cd authz && go build -o ../bin/authz-ssh ./cmd/authz-ssh

# Generate certs and configs from domains.toml
generate: bin/generate
	./bin/generate

# Remove generated certs (forces regeneration on next `make generate`)
clean-certs:
	rm -rf generated/certs
