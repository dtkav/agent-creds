.PHONY: up down deploy deploy-authz dev build test apply-changes discard-changes clean-certs binaries

# Docker Compose
up:
	docker compose up --build

down:
	docker compose down

# Fly.io deployment
deploy: deploy-authz

deploy-authz:
	cd authz && fly deploy --local-only --flycast

build:
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
binaries: bin/actl bin/adev bin/aenv bin/odev bin/cdp-proxy bin/mint bin/mintfs bin/authz-admin bin/authz-ssh

# Root-level cmd binaries
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

# Remove generated certs (forces regeneration on next adev run)
clean-certs:
	rm -rf generated/certs
