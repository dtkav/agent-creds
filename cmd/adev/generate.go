package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

type Generator struct {
	rootDir   string
	certsDir  string
	genDir    string
	hosts     []string            // all upstream hosts
	upstream  map[string]UpstreamConfig
	vaultHost string
	vaultPort int
}

func NewGenerator(rootDir string, cfg ProjectConfig) (*Generator, error) {
	vaultHost, vaultPort := cfg.Vault.VaultAddr()
	g := &Generator{
		rootDir:   rootDir,
		certsDir:  filepath.Join(rootDir, "generated", "certs"),
		genDir:    filepath.Join(rootDir, "generated"),
		upstream:  cfg.Upstream,
		vaultHost: vaultHost,
		vaultPort: vaultPort,
	}

	for host := range cfg.Upstream {
		g.hosts = append(g.hosts, host)
	}
	sort.Strings(g.hosts)

	// Ensure directories
	os.MkdirAll(g.certsDir, 0755)

	return g, nil
}

func (g *Generator) Generate() error {
	if len(g.hosts) == 0 {
		return fmt.Errorf("no upstream hosts configured in agent-creds.toml")
	}

	// Generate CA
	if err := g.generateCA(); err != nil {
		return err
	}

	// Generate configs
	if err := g.generateEnvoyJSON(); err != nil {
		return err
	}
	if err := g.generateHostsFile(); err != nil {
		return err
	}
	if err := g.generateDomainsJSON(); err != nil {
		return err
	}

	return nil
}

func (g *Generator) generateCA() error {
	caKey := filepath.Join(g.certsDir, "ca.key")
	caCrt := filepath.Join(g.certsDir, "ca.crt")

	if fileExists(caKey) && fileExists(caCrt) {
		return nil
	}

	cn := "Agent-Creds Proxy CA"
	days := 3650

	// Generate CA private key
	if err := runCmd("openssl", "genrsa", "-out", caKey, "4096"); err != nil {
		return fmt.Errorf("generating CA key: %w", err)
	}

	// Generate CA certificate
	if err := runCmd("openssl", "req", "-new", "-x509",
		"-days", fmt.Sprintf("%d", days),
		"-key", caKey,
		"-out", caCrt,
		"-subj", fmt.Sprintf("/CN=%s", cn)); err != nil {
		return fmt.Errorf("generating CA cert: %w", err)
	}

	return nil
}

func (g *Generator) generateEnvoyJSON() error {
	vaultHost := g.vaultHost
	vaultPort := g.vaultPort
	listenPort := 443

	var filterChains []map[string]interface{}
	var clusters []map[string]interface{}

	for _, host := range g.hosts {
		safeName := strings.ReplaceAll(host, ".", "_")
		clusterName := safeName + "_cluster"

		// All domains go through ext_authz for token validation
		// Credential injection is controlled by vault.toml in vault
		httpFilters := []map[string]interface{}{
			{
				"name": "envoy.filters.http.ext_authz",
				"typed_config": map[string]interface{}{
					"@type": "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz",
					"grpc_service": map[string]interface{}{
						"envoy_grpc": map[string]interface{}{
							"cluster_name": "vault_cluster",
						},
						"timeout": "5s",
					},
					"transport_api_version": "V3",
					"failure_mode_allow":    false,
					"with_request_body": map[string]interface{}{
						"max_request_bytes":     8192,
						"allow_partial_message": true,
					},
				},
			},
			{
				"name": "envoy.filters.http.router",
				"typed_config": map[string]interface{}{
					"@type": "type.googleapis.com/envoy.extensions.filters.http.router.v3.Router",
				},
			},
		}

		filterChains = append(filterChains, map[string]interface{}{
			"filter_chain_match": map[string]interface{}{
				"server_names": []string{host},
			},
			"transport_socket": map[string]interface{}{
				"name": "envoy.transport_sockets.tls",
				"typed_config": map[string]interface{}{
					"@type": "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext",
					"common_tls_context": map[string]interface{}{
						"tls_certificates": []map[string]interface{}{{
							"certificate_chain": map[string]string{"filename": fmt.Sprintf("/tmp/certs/%s.crt", safeName)},
							"private_key":       map[string]string{"filename": fmt.Sprintf("/tmp/certs/%s.key", safeName)},
						}},
					},
				},
			},
			"filters": []map[string]interface{}{{
				"name": "envoy.filters.network.http_connection_manager",
				"typed_config": map[string]interface{}{
					"@type":       "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager",
					"stat_prefix": "ingress_http",
					"access_log": []map[string]interface{}{{
						"name": "envoy.access_loggers.stdout",
						"typed_config": map[string]interface{}{
							"@type": "type.googleapis.com/envoy.extensions.access_loggers.stream.v3.StdoutAccessLog",
						},
					}},
					"http_filters": httpFilters,
					"route_config": map[string]interface{}{
						"name": "local_route",
						"virtual_hosts": []map[string]interface{}{{
							"name":    safeName + "_vhost",
							"domains": []string{"*"},
							"routes": []map[string]interface{}{{
								"match": map[string]string{"prefix": "/"},
								"route": map[string]interface{}{
									"cluster":              clusterName,
									"host_rewrite_literal": host,
									"timeout":              "300s",
								},
							}},
						}},
					},
				},
			}},
		})

		clusters = append(clusters, map[string]interface{}{
			"name":              clusterName,
			"type":              "LOGICAL_DNS",
			"dns_lookup_family": "V4_ONLY",
			"load_assignment": map[string]interface{}{
				"cluster_name": clusterName,
				"endpoints": []map[string]interface{}{{
					"lb_endpoints": []map[string]interface{}{{
						"endpoint": map[string]interface{}{
							"address": map[string]interface{}{
								"socket_address": map[string]interface{}{
									"address":    host,
									"port_value": 443,
								},
							},
						},
					}},
				}},
			},
			"transport_socket": map[string]interface{}{
				"name": "envoy.transport_sockets.tls",
				"typed_config": map[string]interface{}{
					"@type": "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext",
					"sni":   host,
				},
			},
		})
	}

	// Add vault cluster
	clusters = append(clusters, map[string]interface{}{
		"name":              "vault_cluster",
		"type":              "LOGICAL_DNS",
		"dns_lookup_family": "V4_ONLY",
		"load_assignment": map[string]interface{}{
			"cluster_name": "vault_cluster",
			"endpoints": []map[string]interface{}{{
				"lb_endpoints": []map[string]interface{}{{
					"endpoint": map[string]interface{}{
						"address": map[string]interface{}{
							"socket_address": map[string]interface{}{
								"address":    vaultHost,
								"port_value": vaultPort,
							},
						},
					},
				}},
			}},
		},
		"typed_extension_protocol_options": map[string]interface{}{
			"envoy.extensions.upstreams.http.v3.HttpProtocolOptions": map[string]interface{}{
				"@type": "type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions",
				"explicit_http_config": map[string]interface{}{
					"http2_protocol_options": map[string]interface{}{},
				},
			},
		},
	})

	envoyConfig := map[string]interface{}{
		"static_resources": map[string]interface{}{
			"listeners": []map[string]interface{}{{
				"name": "https_listener",
				"address": map[string]interface{}{
					"socket_address": map[string]interface{}{
						"address":      "::",
						"port_value":   listenPort,
						"ipv4_compat":  true,
					},
				},
				"listener_filters": []map[string]interface{}{{
					"name": "envoy.filters.listener.tls_inspector",
					"typed_config": map[string]interface{}{
						"@type": "type.googleapis.com/envoy.extensions.filters.listener.tls_inspector.v3.TlsInspector",
					},
				}},
				"filter_chains": filterChains,
			}},
			"clusters": clusters,
		},
	}

	data, _ := json.MarshalIndent(envoyConfig, "", "  ")
	return writeIfChanged(filepath.Join(g.genDir, "envoy.json"), data, 0644)
}

func (g *Generator) generateHostsFile() error {
	var lines []string
	lines = append(lines, "# Generated by adev from agent-creds.toml")
	for _, host := range g.hosts {
		lines = append(lines, fmt.Sprintf("envoy %s", host))
	}
	return writeIfChanged(filepath.Join(g.genDir, "hosts"), []byte(strings.Join(lines, "\n")+"\n"), 0644)
}

func (g *Generator) generateDomainsJSON() error {
	type domainEntry struct {
		Host string `json:"host"`
	}

	var domains []domainEntry
	for _, host := range g.hosts {
		domains = append(domains, domainEntry{Host: host})
	}

	data, _ := json.MarshalIndent(domains, "", "  ")
	return writeIfChanged(filepath.Join(g.genDir, "domains.json"), data, 0644)
}

// writeIfChanged writes data to path only if the content differs from what's on disk.
// This preserves mtimes for unchanged files, avoiding unnecessary Docker rebuilds.
func writeIfChanged(path string, data []byte, perm os.FileMode) error {
	existing, err := os.ReadFile(path)
	if err == nil && string(existing) == string(data) {
		return nil
	}
	return os.WriteFile(path, data, perm)
}

func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.Run()
}
