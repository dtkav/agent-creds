.PHONY: up down reload deploy deploy-proxy deploy-authz dev build test apply-changes discard-changes generate generate-fly clean-certs

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

# Build the generate CLI
bin/generate: cmd/generate/main.go cmd/generate/go.mod
	cd cmd/generate && go build -o ../../bin/generate .

# Generate certs and configs from domains.toml
generate: bin/generate
	./bin/generate

# Remove generated certs (forces regeneration on next `make generate`)
clean-certs:
	rm -rf generated/certs
