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
	authzHost string
	authzPort int
}

func NewGenerator(rootDir string, cfg ProjectConfig) (*Generator, error) {
	authzHost, authzPort := cfg.Vault.AuthzAddr()
	g := &Generator{
		rootDir:   rootDir,
		certsDir:  filepath.Join(rootDir, "generated", "certs"),
		genDir:    filepath.Join(rootDir, "generated"),
		upstream:  cfg.Upstream,
		authzHost: authzHost,
		authzPort: authzPort,
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
	if err := g.generateAuthzGo(); err != nil {
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
	authzHost := g.authzHost
	authzPort := g.authzPort
	listenPort := 443

	var filterChains []map[string]interface{}
	var clusters []map[string]interface{}

	for _, host := range g.hosts {
		up := g.upstream[host]
		safeName := strings.ReplaceAll(host, ".", "_")
		clusterName := safeName + "_cluster"

		// Domains with akey need ext_authz; others are passthrough
		needsAuth := up.Akey != ""

		// Build http_filters
		var httpFilters []map[string]interface{}
		if needsAuth {
			httpFilters = append(httpFilters, map[string]interface{}{
				"name": "envoy.filters.http.ext_authz",
				"typed_config": map[string]interface{}{
					"@type": "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz",
					"grpc_service": map[string]interface{}{
						"envoy_grpc": map[string]interface{}{
							"cluster_name": "authz_cluster",
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
			})
		}
		httpFilters = append(httpFilters, map[string]interface{}{
			"name": "envoy.filters.http.router",
			"typed_config": map[string]interface{}{
				"@type": "type.googleapis.com/envoy.extensions.filters.http.router.v3.Router",
			},
		})

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

	// Add authz cluster
	clusters = append(clusters, map[string]interface{}{
		"name":              "authz_cluster",
		"type":              "LOGICAL_DNS",
		"dns_lookup_family": "V4_ONLY",
		"load_assignment": map[string]interface{}{
			"cluster_name": "authz_cluster",
			"endpoints": []map[string]interface{}{{
				"lb_endpoints": []map[string]interface{}{{
					"endpoint": map[string]interface{}{
						"address": map[string]interface{}{
							"socket_address": map[string]interface{}{
								"address":    authzHost,
								"port_value": authzPort,
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
		Host     string `json:"host"`
		AuthType string `json:"auth_type"`
	}

	var domains []domainEntry
	for _, host := range g.hosts {
		up := g.upstream[host]
		authType := "passthrough"
		if up.Akey != "" {
			authType = "static"
		}
		domains = append(domains, domainEntry{Host: host, AuthType: authType})
	}

	data, _ := json.MarshalIndent(domains, "", "  ")
	return writeIfChanged(filepath.Join(g.genDir, "domains.json"), data, 0644)
}

func (g *Generator) generateAuthzGo() error {
	var lines []string
	lines = append(lines, "// Code generated by adev from agent-creds.toml. DO NOT EDIT.")
	lines = append(lines, "")
	lines = append(lines, "package main")
	lines = append(lines, "")
	lines = append(lines, "// DomainConfig holds configuration for credential injection.")
	lines = append(lines, "type DomainConfig struct {")
	lines = append(lines, "\tEnvVar       string")
	lines = append(lines, "\tHeaderName   string")
	lines = append(lines, "\tHeaderPrefix string")
	lines = append(lines, "\tAuthType     string")
	lines = append(lines, "}")
	lines = append(lines, "")
	lines = append(lines, "// domainConfigMap maps API hosts to their credential injection config.")
	lines = append(lines, "var domainConfigMap = map[string]DomainConfig{")

	for _, host := range g.hosts {
		up := g.upstream[host]
		if up.Akey == "" {
			continue // passthrough domains don't need authz config
		}

		// Derive env var from akey filename: "stripe.akey" -> "STRIPE_API_KEY"
		envVar := akeyToEnvVar(up.Akey)

		lines = append(lines, fmt.Sprintf("\t%q: {", host))
		lines = append(lines, fmt.Sprintf("\t\tEnvVar: %q,", envVar))
		lines = append(lines, fmt.Sprintf("\t\tHeaderName: %q,", "authorization"))
		lines = append(lines, fmt.Sprintf("\t\tHeaderPrefix: %q,", "Bearer "))
		lines = append(lines, fmt.Sprintf("\t\tAuthType: %q,", "static"))
		lines = append(lines, "\t},")
	}

	lines = append(lines, "}")
	lines = append(lines, "")

	return writeIfChanged(filepath.Join(g.rootDir, "authz", "domains_gen.go"), []byte(strings.Join(lines, "\n")), 0644)
}

// akeyToEnvVar converts an akey filename to an env var name.
// "stripe.akey" -> "STRIPE_API_KEY"
func akeyToEnvVar(akey string) string {
	name := strings.TrimSuffix(akey, ".akey")
	return strings.ToUpper(name) + "_API_KEY"
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
