package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
)

type Config struct {
	CA      CAConfig          `toml:"ca"`
	Domains map[string]Domain `toml:"domains"`
}

type CAConfig struct {
	CommonName string `toml:"common_name"`
	DaysValid  int    `toml:"days_valid"`
}

type Domain struct {
	Host                  string `toml:"host" json:"host"`
	EnvVar                string `toml:"env_var" json:"env_var,omitempty"`
	HeaderName            string `toml:"header_name" json:"header_name,omitempty"`
	HeaderPrefix          string `toml:"header_prefix" json:"header_prefix,omitempty"`
	AuthType              string `toml:"auth_type" json:"auth_type,omitempty"`
	OAuth2ClientIDVar     string `toml:"oauth2_client_id_var" json:"oauth2_client_id_var,omitempty"`
	OAuth2ClientSecretVar string `toml:"oauth2_client_secret_var" json:"oauth2_client_secret_var,omitempty"`
	OAuth2TokenURL        string `toml:"oauth2_token_url" json:"oauth2_token_url,omitempty"`
}

type Generator struct {
	rootDir     string
	certsDir    string
	genDir      string
	config      Config
	authzAddr   string // authz service address (host:port)
	listenPort  int    // envoy listen port
	proxyHost   string // hostname for /etc/hosts entries
}

type Options struct {
	AuthzAddr  string
	ListenPort int
	ProxyHost  string
}

func NewGenerator(rootDir string, opts Options) (*Generator, error) {
	g := &Generator{
		rootDir:    rootDir,
		certsDir:   filepath.Join(rootDir, "generated", "certs"),
		genDir:     filepath.Join(rootDir, "generated"),
		authzAddr:  opts.AuthzAddr,
		listenPort: opts.ListenPort,
		proxyHost:  opts.ProxyHost,
	}

	// Apply defaults
	if g.authzAddr == "" {
		g.authzAddr = "authz:9001"
	}
	if g.listenPort == 0 {
		g.listenPort = 443
	}
	if g.proxyHost == "" {
		g.proxyHost = "envoy"
	}

	configPath := filepath.Join(rootDir, "domains.toml")
	if _, err := toml.DecodeFile(configPath, &g.config); err != nil {
		return nil, fmt.Errorf("parsing domains.toml: %w", err)
	}

	os.MkdirAll(g.certsDir, 0755)
	return g, nil
}

func (g *Generator) Generate() error {
	if len(g.config.Domains) == 0 {
		return fmt.Errorf("no domains configured")
	}

	hosts := make([]string, 0, len(g.config.Domains))
	for _, d := range g.config.Domains {
		hosts = append(hosts, d.Host)
	}
	fmt.Printf("Found %d domain(s): %s\n", len(g.config.Domains), strings.Join(hosts, ", "))

	if err := g.generateCA(); err != nil {
		return err
	}

	for _, domain := range g.config.Domains {
		if err := g.generateDomainCert(domain.Host); err != nil {
			return err
		}
	}

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

	fmt.Println("\nDone! Run 'docker-compose up' to start the proxy.")
	return nil
}

func (g *Generator) generateCA() error {
	caKey := filepath.Join(g.certsDir, "ca.key")
	caCrt := filepath.Join(g.certsDir, "ca.crt")

	if fileExists(caKey) && fileExists(caCrt) {
		fmt.Printf("CA certificate already exists at %s\n", caCrt)
		return nil
	}

	cn := g.config.CA.CommonName
	if cn == "" {
		cn = "Agent-Creds Proxy CA"
	}
	days := g.config.CA.DaysValid
	if days == 0 {
		days = 3650
	}

	fmt.Printf("Generating CA certificate: %s\n", cn)

	if err := runCmd("openssl", "genrsa", "-out", caKey, "4096"); err != nil {
		return fmt.Errorf("generating CA key: %w", err)
	}

	if err := runCmd("openssl", "req", "-new", "-x509",
		"-days", fmt.Sprintf("%d", days),
		"-key", caKey,
		"-out", caCrt,
		"-subj", fmt.Sprintf("/CN=%s", cn)); err != nil {
		return fmt.Errorf("generating CA cert: %w", err)
	}

	return nil
}

func (g *Generator) generateDomainCert(host string) error {
	safeName := strings.ReplaceAll(host, ".", "_")
	keyFile := filepath.Join(g.certsDir, safeName+".key")
	crtFile := filepath.Join(g.certsDir, safeName+".crt")
	csrFile := filepath.Join(g.certsDir, safeName+".csr")
	extFile := filepath.Join(g.certsDir, safeName+".ext")

	caKey := filepath.Join(g.certsDir, "ca.key")
	caCrt := filepath.Join(g.certsDir, "ca.crt")

	if fileExists(keyFile) && fileExists(crtFile) {
		fmt.Printf("Certificate for %s already exists\n", host)
		return nil
	}

	fmt.Printf("Generating certificate for %s\n", host)

	if err := runCmd("openssl", "genrsa", "-out", keyFile, "2048"); err != nil {
		return err
	}

	if err := runCmd("openssl", "req", "-new",
		"-key", keyFile,
		"-out", csrFile,
		"-subj", fmt.Sprintf("/CN=%s", host)); err != nil {
		return err
	}

	os.WriteFile(extFile, []byte(fmt.Sprintf("subjectAltName=DNS:%s\n", host)), 0644)

	if err := runCmd("openssl", "x509", "-req",
		"-days", "365",
		"-in", csrFile,
		"-CA", caCrt,
		"-CAkey", caKey,
		"-CAcreateserial",
		"-extfile", extFile,
		"-out", crtFile); err != nil {
		return err
	}

	// Fix key permissions for envoy
	os.Chmod(keyFile, 0644)

	os.Remove(csrFile)
	os.Remove(extFile)

	return nil
}

func (g *Generator) generateEnvoyJSON() error {
	// Parse authz address
	authzHost, authzPortStr, _ := strings.Cut(g.authzAddr, ":")
	authzPort, _ := strconv.Atoi(authzPortStr)
	if authzPort == 0 {
		authzPort = 9001
	}

	// Use IPv6 for .flycast addresses
	dnsFamily := "V4_ONLY"
	if strings.Contains(authzHost, ".flycast") {
		dnsFamily = "V6_ONLY"
	}

	var filterChains []map[string]interface{}
	var clusters []map[string]interface{}

	for name, domain := range g.config.Domains {
		host := domain.Host
		safeName := strings.ReplaceAll(host, ".", "_")
		authType := domain.AuthType
		if authType == "" {
			authType = "static"
		}

		var httpFilters []map[string]interface{}
		if authType != "passthrough" {
			httpFilters = append(httpFilters, map[string]interface{}{
				"name": "envoy.filters.http.ext_authz",
				"typed_config": map[string]interface{}{
					"@type": "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz",
					"grpc_service": map[string]interface{}{
						"envoy_grpc": map[string]interface{}{
							"cluster_name": "ext_authz_grpc",
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
							"certificate_chain": map[string]string{"filename": fmt.Sprintf("/certs/%s.crt", safeName)},
							"private_key":       map[string]string{"filename": fmt.Sprintf("/certs/%s.key", safeName)},
						}},
					},
				},
			},
			"filters": []map[string]interface{}{{
				"name": "envoy.filters.network.http_connection_manager",
				"typed_config": map[string]interface{}{
					"@type":       "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager",
					"stat_prefix": "ingress_http",
					"upgrade_configs": []map[string]interface{}{
						{"upgrade_type": "websocket"},
					},
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
							"name":    fmt.Sprintf("%s_vhost", name),
							"domains": []string{"*"},
							"routes": []map[string]interface{}{{
								"match": map[string]string{"prefix": "/"},
								"route": map[string]interface{}{
									"cluster":              fmt.Sprintf("%s_cluster", name),
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
			"name":              fmt.Sprintf("%s_cluster", name),
			"type":              "LOGICAL_DNS",
			"dns_lookup_family": "V4_ONLY",
			"load_assignment": map[string]interface{}{
				"cluster_name": fmt.Sprintf("%s_cluster", name),
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

	// Add ext_authz gRPC cluster
	clusters = append(clusters, map[string]interface{}{
		"name":              "ext_authz_grpc",
		"type":              "LOGICAL_DNS",
		"dns_lookup_family": dnsFamily,
		"load_assignment": map[string]interface{}{
			"cluster_name": "ext_authz_grpc",
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
						"address":    "0.0.0.0",
						"port_value": g.listenPort,
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
	outPath := filepath.Join(g.genDir, "envoy.json")
	fmt.Printf("Generated %s\n", outPath)
	return os.WriteFile(outPath, data, 0644)
}

func (g *Generator) generateHostsFile() error {
	var lines []string
	lines = append(lines, "# Generated by generate - add to /etc/hosts")
	for _, domain := range g.config.Domains {
		lines = append(lines, fmt.Sprintf("%s %s", g.proxyHost, domain.Host))
	}
	outPath := filepath.Join(g.genDir, "hosts")
	fmt.Printf("Generated %s\n", outPath)
	return os.WriteFile(outPath, []byte(strings.Join(lines, "\n")+"\n"), 0644)
}

func (g *Generator) generateDomainsJSON() error {
	data, _ := json.MarshalIndent(g.config.Domains, "", "  ")
	outPath := filepath.Join(g.genDir, "domains.json")
	fmt.Printf("Generated %s\n", outPath)
	return os.WriteFile(outPath, data, 0644)
}

func (g *Generator) generateAuthzGo() error {
	var lines []string
	lines = append(lines, "// Code generated by generate from domains.toml. DO NOT EDIT.")
	lines = append(lines, "")
	lines = append(lines, "package main")
	lines = append(lines, "")
	lines = append(lines, "// DomainConfig holds configuration for credential injection.")
	lines = append(lines, "type DomainConfig struct {")
	lines = append(lines, "\tEnvVar       string")
	lines = append(lines, "\tHeaderName   string")
	lines = append(lines, "\tHeaderPrefix string")
	lines = append(lines, "")
	lines = append(lines, "\t// OAuth2 fields (only used when AuthType == \"oauth2\")")
	lines = append(lines, "\tAuthType           string")
	lines = append(lines, "\tOAuth2ClientIDVar  string")
	lines = append(lines, "\tOAuth2ClientSecVar string")
	lines = append(lines, "\tOAuth2TokenURL     string")
	lines = append(lines, "}")
	lines = append(lines, "")
	lines = append(lines, "// domainConfigMap maps API hosts to their credential injection config.")
	lines = append(lines, "var domainConfigMap = map[string]DomainConfig{")

	for _, domain := range g.config.Domains {
		authType := domain.AuthType
		if authType == "" {
			authType = "static"
		}
		if authType == "passthrough" {
			continue
		}

		headerName := domain.HeaderName
		if headerName == "" {
			headerName = "authorization"
		}
		headerPrefix := domain.HeaderPrefix
		if headerPrefix == "" {
			headerPrefix = "Bearer "
		}

		lines = append(lines, fmt.Sprintf("\t%q: {", domain.Host))
		lines = append(lines, fmt.Sprintf("\t\tEnvVar: %q,", domain.EnvVar))
		lines = append(lines, fmt.Sprintf("\t\tHeaderName: %q,", headerName))
		lines = append(lines, fmt.Sprintf("\t\tHeaderPrefix: %q,", headerPrefix))
		lines = append(lines, fmt.Sprintf("\t\tAuthType: %q,", authType))
		if authType == "oauth2" {
			lines = append(lines, fmt.Sprintf("\t\tOAuth2ClientIDVar: %q,", domain.OAuth2ClientIDVar))
			lines = append(lines, fmt.Sprintf("\t\tOAuth2ClientSecVar: %q,", domain.OAuth2ClientSecretVar))
			lines = append(lines, fmt.Sprintf("\t\tOAuth2TokenURL: %q,", domain.OAuth2TokenURL))
		}
		lines = append(lines, "\t},")
	}

	lines = append(lines, "}")
	lines = append(lines, "")

	outPath := filepath.Join(g.rootDir, "authz", "domains_gen.go")
	fmt.Printf("Generated %s\n", outPath)
	return os.WriteFile(outPath, []byte(strings.Join(lines, "\n")), 0644)
}

func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.Run()
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func main() {
	// Parse flags
	authzAddr := flag.String("authz-address", "authz:9001", "Address of authz service (host:port)")
	listenPort := flag.Int("port", 443, "Envoy listen port")
	proxyHost := flag.String("proxy-host", "envoy", "Hostname for /etc/hosts entries")
	flag.Parse()

	// Find repo root (where domains.toml is)
	wd, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Walk up to find domains.toml
	rootDir := wd
	for {
		if fileExists(filepath.Join(rootDir, "domains.toml")) {
			break
		}
		parent := filepath.Dir(rootDir)
		if parent == rootDir {
			fmt.Fprintf(os.Stderr, "Error: domains.toml not found\n")
			os.Exit(1)
		}
		rootDir = parent
	}

	opts := Options{
		AuthzAddr:  *authzAddr,
		ListenPort: *listenPort,
		ProxyHost:  *proxyHost,
	}

	gen, err := NewGenerator(rootDir, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if err := gen.Generate(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
