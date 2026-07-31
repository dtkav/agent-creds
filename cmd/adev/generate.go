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
	hosts     []string // all upstream hosts
	upstream  map[string]UpstreamConfig
	vaultHost string
	vaultPort int
	vaultDNS  string        // optional DNS server for resolving vault host
	cfg       ProjectConfig // full merged config for aenv display
}

func NewGenerator(rootDir, genDir string, cfg ProjectConfig) (*Generator, error) {
	vaultHost, vaultPort := cfg.Vault.VaultAddr()
	g := &Generator{
		rootDir:   rootDir,
		certsDir:  filepath.Join(rootDir, "generated", "certs"),
		genDir:    genDir,
		upstream:  cfg.Upstream,
		vaultHost: vaultHost,
		vaultPort: vaultPort,
		vaultDNS:  cfg.Vault.DNS,
		cfg:       cfg,
	}

	for host := range cfg.Upstream {
		g.hosts = append(g.hosts, host)
	}
	sort.Strings(g.hosts)

	// Ensure directories
	os.MkdirAll(g.certsDir, 0755)
	os.MkdirAll(g.genDir, 0700)

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
	if err := g.generateDomainsJSON(); err != nil {
		return err
	}
	if err := g.generateMergedConfig(); err != nil {
		return err
	}

	return nil
}

// generateMergedConfig writes the fully-merged project config (with agent/plugin
// upstreams) as TOML. This is mounted into the sandbox at /etc/aenv/agent-creds.toml
// so the aenv display shows the complete allowlist, not just the project-level upstreams.
func (g *Generator) generateMergedConfig() error {
	var sb strings.Builder
	sb.WriteString("# Auto-generated merged config (project + agent + plugins)\n")
	sb.WriteString("# Do not edit — regenerated on every adev start\n\n")

	// [sandbox] section
	sb.WriteString("[sandbox]\n")
	if g.cfg.Sandbox.Name != "" {
		sb.WriteString(fmt.Sprintf("name = %q\n", g.cfg.Sandbox.Name))
	}
	if g.cfg.Sandbox.Agent != "" {
		sb.WriteString(fmt.Sprintf("agent = %q\n", g.cfg.Sandbox.Agent))
	}
	sb.WriteString("\n")

	// [vault] section
	if g.cfg.Vault.Host != "" {
		sb.WriteString("[vault]\n")
		sb.WriteString(fmt.Sprintf("host = %q\n\n", g.cfg.Vault.Host))
	}

	// [upstream."host"] sections — sorted for stable output
	for _, host := range g.hosts {
		sb.WriteString(fmt.Sprintf("[upstream.%q]\n", host))
		ucfg := g.upstream[host]
		if ucfg.Mode != "" {
			sb.WriteString(fmt.Sprintf("mode = %q\n", ucfg.Mode))
		}
		if ucfg.Credential != "" {
			sb.WriteString(fmt.Sprintf("credential = %q\n", ucfg.Credential))
		}
		if ucfg.Scheme != "" {
			sb.WriteString(fmt.Sprintf("scheme = %q\n", ucfg.Scheme))
		}
		if ucfg.Port != 0 {
			sb.WriteString(fmt.Sprintf("port = %d\n", ucfg.Port))
		}
		if ucfg.Address != "" {
			sb.WriteString(fmt.Sprintf("address = %q\n", ucfg.Address))
		}
		if ucfg.Network != "" {
			sb.WriteString(fmt.Sprintf("network = %q\n", ucfg.Network))
		}
		if ucfg.ForwardToken {
			sb.WriteString("forward_token = true\n")
		}
		if len(ucfg.Methods) > 0 {
			sb.WriteString(fmt.Sprintf("methods = [%s]\n", quotedList(ucfg.Methods)))
		}
		if len(ucfg.Paths) > 0 {
			sb.WriteString(fmt.Sprintf("paths = [%s]\n", quotedList(ucfg.Paths)))
		}
	}

	// [[browser_target]] sections
	for _, bt := range g.cfg.BrowserTargets {
		sb.WriteString(fmt.Sprintf("\n[[browser_target]]\nurl = %q\n", bt.URL))
	}

	// [[cdp_target]] sections
	for _, ct := range g.cfg.CDPTargets {
		sb.WriteString("\n[[cdp_target]]\n")
		if ct.Port != 0 {
			sb.WriteString(fmt.Sprintf("port = %d\n", ct.Port))
		}
		if ct.Type != "" {
			sb.WriteString(fmt.Sprintf("type = %q\n", ct.Type))
		}
		if ct.Title != "" {
			sb.WriteString(fmt.Sprintf("title = %q\n", ct.Title))
		}
		if ct.URL != "" {
			sb.WriteString(fmt.Sprintf("url = %q\n", ct.URL))
		}
	}

	return writeIfChanged(filepath.Join(g.genDir, "merged-config.toml"), []byte(sb.String()), 0644)
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

// extAuthzFilter returns the ext_authz HTTP filter config pointing at the vault cluster.
func (g *Generator) extAuthzFilter() map[string]interface{} {
	return map[string]interface{}{
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
	}
}

// routerFilter returns the standard HTTP router filter.
func routerFilter() map[string]interface{} {
	return map[string]interface{}{
		"name": "envoy.filters.http.router",
		"typed_config": map[string]interface{}{
			"@type": "type.googleapis.com/envoy.extensions.filters.http.router.v3.Router",
		},
	}
}

func (g *Generator) httpFilters() []map[string]interface{} {
	return []map[string]interface{}{g.extAuthzFilter(), routerFilter()}
}

func (g *Generator) connectHTTPFilters() []map[string]interface{} {
	return []map[string]interface{}{g.extAuthzFilter(), routerFilter()}
}

// accessLogConfig returns the access log config used by all HTTP connection managers.
func accessLogConfig() []map[string]interface{} {
	return []map[string]interface{}{
		{
			"name": "envoy.access_loggers.stdout",
			"typed_config": map[string]interface{}{
				"@type": "type.googleapis.com/envoy.extensions.access_loggers.stream.v3.StdoutAccessLog",
			},
		},
		{
			"name": "envoy.access_loggers.file",
			"typed_config": map[string]interface{}{
				"@type": "type.googleapis.com/envoy.extensions.access_loggers.file.v3.FileAccessLog",
				"path":  "/var/log/adev/access.log",
				"log_format": map[string]interface{}{
					"text_format_source": map[string]interface{}{
						"inline_string": "%START_TIME(%Y-%m-%dT%H:%M:%SZ)% %REQ(:METHOD)% %REQ(:AUTHORITY)%%REQ(:PATH)% %RESPONSE_CODE% %RESPONSE_CODE_DETAILS%\n",
					},
				},
			},
		},
	}
}

func (g *Generator) routeForHost(host string) map[string]interface{} {
	safeName := strings.ReplaceAll(host, ".", "_")
	clusterName := safeName + "_cluster"
	upstreamCfg := g.upstream[host]

	route := map[string]interface{}{
		"match": map[string]string{"prefix": "/"},
		"route": map[string]interface{}{
			"cluster":              clusterName,
			"host_rewrite_literal": host,
			"timeout":              "300s",
		},
	}
	if len(upstreamCfg.Methods) > 0 || len(upstreamCfg.Paths) > 0 || upstreamCfg.Credential != "" || upstreamCfg.Mode != "" {
		contextExtensions := map[string]string{}
		contextExtensions["agent_creds_mode"] = upstreamCfg.ModeValue()
		if upstreamCfg.Credential != "" {
			contextExtensions["credential"] = upstreamCfg.Credential
		}
		if len(upstreamCfg.Methods) > 0 {
			contextExtensions["allowed_methods"] = strings.Join(upstreamCfg.Methods, ",")
		}
		if len(upstreamCfg.Paths) > 0 {
			contextExtensions["allowed_paths"] = strings.Join(upstreamCfg.Paths, ",")
		}
		route["typed_per_filter_config"] = map[string]interface{}{
			"envoy.filters.http.ext_authz": map[string]interface{}{
				"@type": "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute",
				"check_settings": map[string]interface{}{
					"context_extensions": contextExtensions,
				},
			},
		}
	}

	return route
}

// tlsFilterChain builds a per-domain filter chain with SNI matching, TLS termination,
// ext_authz, and routing to the domain's upstream cluster. Used by both the DNAT
// listener (port 443) and the internal listener (CONNECT TLS bumping).
func (g *Generator) tlsFilterChain(host, statPrefix string) map[string]interface{} {
	safeName := strings.ReplaceAll(host, ".", "_")
	return map[string]interface{}{
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
				"@type":        "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager",
				"stat_prefix":  statPrefix,
				"access_log":   accessLogConfig(),
				"http_filters": g.httpFilters(),
				"route_config": map[string]interface{}{
					"name": "local_route",
					"virtual_hosts": []map[string]interface{}{{
						"name":    safeName + "_vhost",
						"domains": []string{"*"},
						"routes":  []map[string]interface{}{g.routeForHost(host)},
					}},
				},
			},
		}},
	}
}

func (g *Generator) httpVirtualHosts(hosts []string) []map[string]interface{} {
	virtualHosts := make([]map[string]interface{}, 0, len(hosts))
	for _, host := range hosts {
		safeName := strings.ReplaceAll(host, ".", "_")
		virtualHosts = append(virtualHosts, map[string]interface{}{
			"name":    safeName + "_vhost",
			"domains": []string{host, host + ":*"},
			"routes":  []map[string]interface{}{g.routeForHost(host)},
		})
	}
	return virtualHosts
}

// httpFilterChain routes plaintext HTTP by Host header while applying the
// same vault authorization and credential injection as HTTPS upstreams.
func (g *Generator) httpFilterChain(hosts []string) map[string]interface{} {
	return map[string]interface{}{
		"filters": []map[string]interface{}{{
			"name": "envoy.filters.network.http_connection_manager",
			"typed_config": map[string]interface{}{
				"@type":        "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager",
				"stat_prefix":  "ingress_http_plaintext",
				"access_log":   accessLogConfig(),
				"http_filters": g.httpFilters(),
				"route_config": map[string]interface{}{
					"name":          "plaintext_route",
					"virtual_hosts": g.httpVirtualHosts(hosts),
				},
			},
		}},
	}
}

// connectFilterChain accepts HTTPS CONNECT tunnels and plaintext forward-proxy
// requests on the bwrap runtime's single Envoy port.
func (g *Generator) connectFilterChain(httpHosts []string) map[string]interface{} {
	connectFilterConfig := map[string]interface{}{
		"envoy.filters.http.ext_authz": map[string]interface{}{
			"@type":    "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute",
			"disabled": true,
		},
	}
	connectRoute := map[string]interface{}{
		"match": map[string]interface{}{
			"connect_matcher": map[string]interface{}{},
		},
		"route": map[string]interface{}{
			"cluster": "connect_internal",
			"upgrade_configs": []map[string]interface{}{{
				"upgrade_type":   "CONNECT",
				"connect_config": map[string]interface{}{},
			}},
		},
		"typed_per_filter_config": connectFilterConfig,
	}
	virtualHosts := g.httpVirtualHosts(httpHosts)
	virtualHosts = append(virtualHosts, map[string]interface{}{
		"name":    "connect_vhost",
		"domains": []string{"*"},
		"routes":  []map[string]interface{}{connectRoute},
	})
	return map[string]interface{}{
		"filters": []map[string]interface{}{{
			"name": "envoy.filters.network.http_connection_manager",
			"typed_config": map[string]interface{}{
				"@type":       "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager",
				"stat_prefix": "connect_proxy",
				"access_log":  accessLogConfig(),
				"http_protocol_options": map[string]interface{}{
					"allow_absolute_url": true,
				},
				"http2_protocol_options": map[string]interface{}{
					"allow_connect": true,
				},
				"upgrade_configs": []map[string]interface{}{{
					"upgrade_type": "CONNECT",
				}},
				"http_filters": g.connectHTTPFilters(),
				"route_config": map[string]interface{}{
					"name":          "connect_route",
					"virtual_hosts": virtualHosts,
				},
			},
		}},
	}
}

// upstreamCluster builds a cluster definition for an upstream domain.
func upstreamCluster(host string, cfg UpstreamConfig) map[string]interface{} {
	safeName := strings.ReplaceAll(host, ".", "_")
	clusterName := safeName + "_cluster"
	cluster := map[string]interface{}{
		"name":              clusterName,
		"type":              "LOGICAL_DNS",
		"dns_lookup_family": "AUTO",
		"load_assignment": map[string]interface{}{
			"cluster_name": clusterName,
			"endpoints": []map[string]interface{}{{
				"lb_endpoints": []map[string]interface{}{{
					"endpoint": map[string]interface{}{
						"address": map[string]interface{}{
							"socket_address": map[string]interface{}{
								"address":    cfg.AddressValue(host),
								"port_value": cfg.PortValue(),
							},
						},
					},
				}},
			}},
		},
	}
	if cfg.SchemeValue() == "https" {
		cluster["transport_socket"] = map[string]interface{}{
			"name": "envoy.transport_sockets.tls",
			"typed_config": map[string]interface{}{
				"@type": "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext",
				"sni":   host,
			},
		}
	}
	// Use the Envoy container's resolver. Besides public DNS, this supports
	// private resolvers installed for Flycast/WireGuard names.
	return cluster
}

func (g *Generator) generateEnvoyJSON() error {
	vaultHost := g.vaultHost
	vaultPort := g.vaultPort

	var filterChains []map[string]interface{}
	var internalFilterChains []map[string]interface{}
	var httpHosts []string
	var clusters []map[string]interface{}

	for _, host := range g.hosts {
		cfg := g.upstream[host]
		clusters = append(clusters, upstreamCluster(host, cfg))
		if cfg.SchemeValue() == "http" {
			httpHosts = append(httpHosts, host)
			continue
		}
		filterChains = append(filterChains, g.tlsFilterChain(host, "ingress_http"))
		internalFilterChains = append(internalFilterChains, g.tlsFilterChain(host, "connect_bump"))
	}

	// Add vault cluster
	vaultCluster := map[string]interface{}{
		"name":              "vault_cluster",
		"type":              "LOGICAL_DNS",
		"dns_lookup_family": "AUTO",
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
	}
	if g.vaultDNS != "" {
		vaultCluster["dns_resolvers"] = []map[string]interface{}{{
			"socket_address": map[string]interface{}{
				"address":    g.vaultDNS,
				"port_value": 53,
			},
		}}
	}
	clusters = append(clusters, vaultCluster)

	// Cluster that routes to the internal listener for TLS bumping
	clusters = append(clusters, map[string]interface{}{
		"name": "connect_internal",
		"type": "STATIC",
		"load_assignment": map[string]interface{}{
			"cluster_name": "connect_internal",
			"endpoints": []map[string]interface{}{{
				"lb_endpoints": []map[string]interface{}{{
					"endpoint": map[string]interface{}{
						"address": map[string]interface{}{
							"envoy_internal_address": map[string]interface{}{
								"server_listener_name": "connect_tls_bump",
							},
						},
					},
				}},
			}},
		},
	})

	// Listener 1: Existing DNAT reverse proxy (port 443)
	httpsListener := map[string]interface{}{
		"name": "https_listener",
		"address": map[string]interface{}{
			"socket_address": map[string]interface{}{
				"address":     "::",
				"port_value":  443,
				"ipv4_compat": true,
			},
		},
		"listener_filters": []map[string]interface{}{{
			"name": "envoy.filters.listener.tls_inspector",
			"typed_config": map[string]interface{}{
				"@type": "type.googleapis.com/envoy.extensions.filters.listener.tls_inspector.v3.TlsInspector",
			},
		}},
		"filter_chains": filterChains,
	}

	// Listener 2: Forward proxy accepting CONNECT (port 10000)
	// Terminates the CONNECT tunnel and routes inner TCP to the internal listener
	// for TLS bumping + credential injection.
	connectListener := map[string]interface{}{
		"name": "connect_listener",
		"address": map[string]interface{}{
			"socket_address": map[string]interface{}{
				"address":     "::",
				"port_value":  10000,
				"ipv4_compat": true,
			},
		},
		"filter_chains": []map[string]interface{}{
			g.connectFilterChain(httpHosts),
		},
	}

	// Listener 3: Internal listener for TLS bumping
	// Receives raw TCP from terminated CONNECT tunnels, inspects SNI,
	// terminates TLS with per-domain certs, runs ext_authz, routes upstream.
	internalListener := map[string]interface{}{
		"name":              "connect_tls_bump",
		"internal_listener": map[string]interface{}{},
		"listener_filters": []map[string]interface{}{{
			"name": "envoy.filters.listener.tls_inspector",
			"typed_config": map[string]interface{}{
				"@type": "type.googleapis.com/envoy.extensions.filters.listener.tls_inspector.v3.TlsInspector",
			},
		}},
		"filter_chains": internalFilterChains,
	}

	listeners := make([]map[string]interface{}, 0, 4)
	if len(httpHosts) > 0 {
		listeners = append(listeners, map[string]interface{}{
			"name": "http_listener",
			"address": map[string]interface{}{
				"socket_address": map[string]interface{}{
					"address":     "::",
					"port_value":  80,
					"ipv4_compat": true,
				},
			},
			"filter_chains": []map[string]interface{}{g.httpFilterChain(httpHosts)},
		})
	}
	if len(filterChains) > 0 {
		listeners = append(listeners, httpsListener)
	}
	if len(httpHosts) > 0 || len(filterChains) > 0 {
		listeners = append(listeners, connectListener)
	}
	if len(internalFilterChains) > 0 {
		listeners = append(listeners, internalListener)
	}

	envoyConfig := map[string]interface{}{
		"static_resources": map[string]interface{}{
			"listeners": listeners,
			"clusters":  clusters,
		},
		"bootstrap_extensions": []map[string]interface{}{{
			"name": "envoy.bootstrap.internal_listener",
			"typed_config": map[string]interface{}{
				"@type": "type.googleapis.com/envoy.extensions.bootstrap.internal_listener.v3.InternalListener",
			},
		}},
	}

	data, _ := json.MarshalIndent(envoyConfig, "", "  ")
	return writeIfChanged(filepath.Join(g.genDir, "envoy.json"), data, 0644)
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

func quotedList(items []string) string {
	quoted := make([]string, len(items))
	for i, s := range items {
		quoted[i] = fmt.Sprintf("%q", s)
	}
	return strings.Join(quoted, ", ")
}

func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.Run()
}
