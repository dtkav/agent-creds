#!/usr/bin/env python3
"""
Generate certificates and configs from domains.toml.

Usage: python scripts/generate.py [--authz-address HOST:PORT]

Options:
    --authz-address    Address of authz service (default: authz:9001 for docker-compose)
                       Use <your-authz-app>.flycast:80 for Fly.io deployment
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path

# Python 3.11+ has tomllib in stdlib
try:
    import tomllib
except ImportError:
    import tomli as tomllib

ROOT = Path(__file__).parent.parent
DOMAINS_TOML = ROOT / "domains.toml"
GENERATED = ROOT / "generated"
CERTS_DIR = GENERATED / "certs"


def run(cmd: list[str], **kwargs):
    """Run a command, exit on failure."""
    result = subprocess.run(cmd, **kwargs)
    if result.returncode != 0:
        sys.exit(result.returncode)


def generate_ca(config: dict):
    """Generate CA certificate if it doesn't exist."""
    ca_key = CERTS_DIR / "ca.key"
    ca_crt = CERTS_DIR / "ca.crt"

    if ca_key.exists() and ca_crt.exists():
        print(f"CA certificate already exists at {ca_crt}")
        return

    ca_config = config.get("ca", {})
    cn = ca_config.get("common_name", "Agent-Creds Proxy CA")
    days = ca_config.get("days_valid", 3650)

    print(f"Generating CA certificate: {cn}")

    # Generate CA private key
    run(["openssl", "genrsa", "-out", str(ca_key), "4096"])

    # Generate CA certificate
    run([
        "openssl", "req", "-new", "-x509",
        "-days", str(days),
        "-key", str(ca_key),
        "-out", str(ca_crt),
        "-subj", f"/CN={cn}"
    ])

    print(f"CA certificate generated: {ca_crt}")


def generate_domain_cert(host: str):
    """Generate certificate for a domain."""
    # Sanitize hostname for filename
    safe_name = host.replace(".", "_")
    key_file = CERTS_DIR / f"{safe_name}.key"
    crt_file = CERTS_DIR / f"{safe_name}.crt"
    csr_file = CERTS_DIR / f"{safe_name}.csr"

    ca_key = CERTS_DIR / "ca.key"
    ca_crt = CERTS_DIR / "ca.crt"

    if key_file.exists() and crt_file.exists():
        print(f"Certificate for {host} already exists")
        return

    print(f"Generating certificate for {host}")

    # Generate private key
    run(["openssl", "genrsa", "-out", str(key_file), "2048"])

    # Generate CSR
    run([
        "openssl", "req", "-new",
        "-key", str(key_file),
        "-out", str(csr_file),
        "-subj", f"/CN={host}"
    ])

    # Sign with CA
    run([
        "openssl", "x509", "-req",
        "-days", "365",
        "-in", str(csr_file),
        "-CA", str(ca_crt),
        "-CAkey", str(ca_key),
        "-CAcreateserial",
        "-out", str(crt_file)
    ])

    # Clean up CSR
    csr_file.unlink()

    print(f"Certificate generated: {crt_file}")


def generate_envoy_yaml(domains: dict, authz_address: str = "authz:9001", listen_port: int = 443):
    """Generate envoy.yaml with TLS termination and SNI routing."""
    authz_host, authz_port = authz_address.rsplit(":", 1)
    authz_port = int(authz_port)
    # Use IPv6 for .flycast addresses, IPv4 otherwise
    dns_family = "V6_ONLY" if ".flycast" in authz_host else "V4_ONLY"
    hosts = [d["host"] for d in domains.values()]

    # Build filter chains for each domain
    filter_chains = []
    clusters = []

    for name, domain in domains.items():
        host = domain["host"]
        safe_name = host.replace(".", "_")

        filter_chains.append({
            "filter_chain_match": {
                "server_names": [host]
            },
            "transport_socket": {
                "name": "envoy.transport_sockets.tls",
                "typed_config": {
                    "@type": "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext",
                    "common_tls_context": {
                        "tls_certificates": [{
                            "certificate_chain": {"filename": f"/certs/{safe_name}.crt"},
                            "private_key": {"filename": f"/certs/{safe_name}.key"}
                        }]
                    }
                }
            },
            "filters": [{
                "name": "envoy.filters.network.http_connection_manager",
                "typed_config": {
                    "@type": "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager",
                    "stat_prefix": "ingress_http",
                    "access_log": [{
                        "name": "envoy.access_loggers.stdout",
                        "typed_config": {
                            "@type": "type.googleapis.com/envoy.extensions.access_loggers.stream.v3.StdoutAccessLog"
                        }
                    }],
                    "http_filters": [
                        {
                            "name": "envoy.filters.http.ext_authz",
                            "typed_config": {
                                "@type": "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz",
                                "grpc_service": {
                                    "envoy_grpc": {
                                        "cluster_name": "authz_cluster"
                                    },
                                    "timeout": "5s"
                                },
                                "transport_api_version": "V3",
                                "failure_mode_allow": False,
                                "with_request_body": {
                                    "max_request_bytes": 8192,
                                    "allow_partial_message": True
                                }
                            }
                        },
                        {
                            "name": "envoy.filters.http.router",
                            "typed_config": {
                                "@type": "type.googleapis.com/envoy.extensions.filters.http.router.v3.Router"
                            }
                        }
                    ],
                    "route_config": {
                        "name": "local_route",
                        "virtual_hosts": [{
                            "name": f"{name}_vhost",
                            "domains": ["*"],
                            "routes": [{
                                "match": {"prefix": "/"},
                                "route": {
                                    "cluster": f"{name}_cluster",
                                    "host_rewrite_literal": host
                                }
                            }]
                        }]
                    }
                }
            }]
        })

        clusters.append({
            "name": f"{name}_cluster",
            "type": "LOGICAL_DNS",
            "dns_lookup_family": "V4_ONLY",
            "load_assignment": {
                "cluster_name": f"{name}_cluster",
                "endpoints": [{
                    "lb_endpoints": [{
                        "endpoint": {
                            "address": {
                                "socket_address": {
                                    "address": host,
                                    "port_value": 443
                                }
                            }
                        }
                    }]
                }]
            },
            "transport_socket": {
                "name": "envoy.transport_sockets.tls",
                "typed_config": {
                    "@type": "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext",
                    "sni": host
                }
            }
        })

    # Add authz cluster
    clusters.append({
        "name": "authz_cluster",
        "type": "LOGICAL_DNS",
        "dns_lookup_family": dns_family,
        "load_assignment": {
            "cluster_name": "authz_cluster",
            "endpoints": [{
                "lb_endpoints": [{
                    "endpoint": {
                        "address": {
                            "socket_address": {
                                "address": authz_host,
                                "port_value": authz_port
                            }
                        }
                    }
                }]
            }]
        },
        "typed_extension_protocol_options": {
            "envoy.extensions.upstreams.http.v3.HttpProtocolOptions": {
                "@type": "type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions",
                "explicit_http_config": {
                    "http2_protocol_options": {}
                }
            }
        }
    })

    envoy_config = {
        "static_resources": {
            "listeners": [{
                "name": "https_listener",
                "address": {
                    "socket_address": {
                        "address": "0.0.0.0",
                        "port_value": listen_port
                    }
                },
                "listener_filters": [{
                    "name": "envoy.filters.listener.tls_inspector",
                    "typed_config": {
                        "@type": "type.googleapis.com/envoy.extensions.filters.listener.tls_inspector.v3.TlsInspector"
                    }
                }],
                "filter_chains": filter_chains
            }],
            "clusters": clusters
        }
    }

    # Envoy accepts JSON config
    output = GENERATED / "envoy.json"
    output.write_text(json.dumps(envoy_config, indent=2))
    print(f"Generated {output}")


def generate_hosts_file(domains: dict, proxy_host: str = "envoy"):
    """Generate hosts file entries."""
    output = GENERATED / "hosts"
    lines = ["# Generated by scripts/generate.py - add to /etc/hosts"]
    for domain in domains.values():
        lines.append(f"{proxy_host} {domain['host']}")

    output.write_text("\n".join(lines) + "\n")
    print(f"Generated {output}")


def generate_domains_json(domains: dict):
    """Generate domains.json for other tools to consume."""
    output = GENERATED / "domains.json"
    output.write_text(json.dumps(domains, indent=2))
    print(f"Generated {output}")


def generate_authz_domains_go(domains: dict):
    """Generate authz/domains_gen.go with domain config."""
    lines = [
        "// Code generated by scripts/generate.py from domains.toml. DO NOT EDIT.",
        "",
        "package main",
        "",
        "// hostEnvMap maps API hosts to their environment variable names.",
        "var hostEnvMap = map[string]string{",
    ]

    for domain in domains.values():
        lines.append(f'\t"{domain["host"]}": "{domain["env_var"]}",')

    lines.append("}")
    lines.append("")

    output = ROOT / "authz" / "domains_gen.go"
    output.write_text("\n".join(lines))
    print(f"Generated {output}")


def main():
    parser = argparse.ArgumentParser(description="Generate certificates and configs from domains.toml")
    parser.add_argument(
        "--authz-address",
        default="authz:9001",
        help="Address of authz service (default: authz:9001 for docker-compose, use <your-authz-app>.flycast:80 for Fly.io)"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=443,
        help="Port for envoy to listen on (default: 443 for docker-compose, use 8443 for Fly.io)"
    )
    parser.add_argument(
        "--proxy-host",
        default="envoy",
        help="Hostname for proxy in /etc/hosts (default: envoy for docker-compose)"
    )
    args = parser.parse_args()

    # Ensure directories exist
    CERTS_DIR.mkdir(parents=True, exist_ok=True)

    # Parse config
    with open(DOMAINS_TOML, "rb") as f:
        config = tomllib.load(f)

    domains = config.get("domains", {})
    if not domains:
        print("No domains configured in domains.toml")
        sys.exit(1)

    print(f"Found {len(domains)} domain(s): {', '.join(d['host'] for d in domains.values())}")
    print(f"Authz address: {args.authz_address}")
    print(f"Listen port: {args.port}")

    # Generate CA
    generate_ca(config)

    # Generate domain certs
    for domain in domains.values():
        generate_domain_cert(domain["host"])

    # Generate configs
    generate_envoy_yaml(domains, args.authz_address, args.port)
    generate_hosts_file(domains, args.proxy_host)
    generate_domains_json(domains)
    generate_authz_domains_go(domains)

    print("\nDone! Run 'docker-compose up' to start the proxy.")


if __name__ == "__main__":
    main()
