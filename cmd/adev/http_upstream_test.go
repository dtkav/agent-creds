package main

import "testing"

func TestExtAuthzBuffersRawRequestPrefix(t *testing.T) {
	g := &Generator{}
	filter := g.extAuthzFilter()
	typed := filter["typed_config"].(map[string]interface{})
	body := typed["with_request_body"].(map[string]interface{})
	if body["max_request_bytes"] != 8192 {
		t.Fatalf("max request bytes = %#v", body["max_request_bytes"])
	}
	if body["allow_partial_message"] != true || body["pack_as_bytes"] != true {
		t.Fatalf("request body buffering = %#v", body)
	}
}

func TestUpstreamTransportDefaults(t *testing.T) {
	https := UpstreamConfig{}
	if https.SchemeValue() != "https" || https.PortValue() != 443 {
		t.Fatalf("default transport = %s:%d", https.SchemeValue(), https.PortValue())
	}
	http := UpstreamConfig{Scheme: "http"}
	if http.PortValue() != 80 {
		t.Fatalf("http default port = %d", http.PortValue())
	}
	custom := UpstreamConfig{Scheme: "http", Port: 8080}
	if custom.PortValue() != 8080 {
		t.Fatalf("custom port = %d", custom.PortValue())
	}
}

func TestHTTPUpstreamClusterHasNoTLS(t *testing.T) {
	cluster := upstreamCluster("telemetry.internal", UpstreamConfig{Scheme: "http"})
	if _, ok := cluster["transport_socket"]; ok {
		t.Fatal("HTTP cluster unexpectedly enables TLS")
	}
	assignment := cluster["load_assignment"].(map[string]interface{})
	endpoints := assignment["endpoints"].([]map[string]interface{})
	lb := endpoints[0]["lb_endpoints"].([]map[string]interface{})
	endpoint := lb[0]["endpoint"].(map[string]interface{})
	address := endpoint["address"].(map[string]interface{})
	socket := address["socket_address"].(map[string]interface{})
	if socket["port_value"] != 80 {
		t.Fatalf("HTTP cluster port = %#v", socket["port_value"])
	}
}

func TestUpstreamClusterCanUseFixedOriginAddress(t *testing.T) {
	cluster := upstreamCluster("service.internal", UpstreamConfig{
		Scheme:  "http",
		Port:    8890,
		Address: "host.docker.internal",
	})
	assignment := cluster["load_assignment"].(map[string]interface{})
	endpoints := assignment["endpoints"].([]map[string]interface{})
	lb := endpoints[0]["lb_endpoints"].([]map[string]interface{})
	endpoint := lb[0]["endpoint"].(map[string]interface{})
	address := endpoint["address"].(map[string]interface{})
	socket := address["socket_address"].(map[string]interface{})
	if socket["address"] != "host.docker.internal" || socket["port_value"] != 8890 {
		t.Fatalf("fixed origin = %#v", socket)
	}
}

func TestHTTPListenerHasOnlyExplicitVirtualHostsAndExtAuthz(t *testing.T) {
	g := &Generator{upstream: map[string]UpstreamConfig{
		"telemetry.internal": {Scheme: "http"},
	}}
	chain := g.httpFilterChain([]string{"telemetry.internal"})
	filters := chain["filters"].([]map[string]interface{})
	hcm := filters[0]["typed_config"].(map[string]interface{})
	httpFilters := hcm["http_filters"].([]map[string]interface{})
	if got := httpFilters[0]["name"]; got != "envoy.filters.http.ext_authz" {
		t.Fatalf("first HTTP filter = %v, want ext_authz", got)
	}
	routeConfig := hcm["route_config"].(map[string]interface{})
	vhosts := routeConfig["virtual_hosts"].([]map[string]interface{})
	if len(vhosts) != 1 {
		t.Fatalf("virtual hosts = %d", len(vhosts))
	}
	domains := vhosts[0]["domains"].([]string)
	if len(domains) != 2 || domains[0] != "telemetry.internal" || domains[1] != "telemetry.internal:*" {
		t.Fatalf("HTTP domains = %#v", domains)
	}
	routes := vhosts[0]["routes"].([]map[string]interface{})
	route := routes[0]["route"].(map[string]interface{})
	if route["cluster"] != "telemetry_internal_cluster" || route["host_rewrite_literal"] != "telemetry.internal" {
		t.Fatalf("HTTP route = %#v", route)
	}
}

func TestConnectListenerRoutesPlainHTTPThroughExtAuthz(t *testing.T) {
	g := &Generator{upstream: map[string]UpstreamConfig{
		"service.internal": {
			Scheme:  "http",
			Port:    8890,
			Methods: []string{"POST"},
			Paths:   []string{"/graphql"},
		},
	}}
	chain := g.connectFilterChain([]string{"service.internal"})
	filters := chain["filters"].([]map[string]interface{})
	hcm := filters[0]["typed_config"].(map[string]interface{})
	httpFilters := hcm["http_filters"].([]map[string]interface{})
	if got := httpFilters[0]["name"]; got != "envoy.filters.http.ext_authz" {
		t.Fatalf("first CONNECT-listener filter = %v, want ext_authz", got)
	}

	routeConfig := hcm["route_config"].(map[string]interface{})
	vhosts := routeConfig["virtual_hosts"].([]map[string]interface{})
	if len(vhosts) != 2 {
		t.Fatalf("CONNECT-listener virtual hosts = %d, want 2", len(vhosts))
	}
	domains := vhosts[0]["domains"].([]string)
	if len(domains) != 2 || domains[0] != "service.internal" || domains[1] != "service.internal:*" {
		t.Fatalf("plaintext proxy domains = %#v", domains)
	}
	plainRoutes := vhosts[0]["routes"].([]map[string]interface{})
	plainRoute := plainRoutes[0]["route"].(map[string]interface{})
	if plainRoute["cluster"] != "service_internal_cluster" {
		t.Fatalf("plaintext proxy route = %#v", plainRoute)
	}

	connectRoutes := vhosts[1]["routes"].([]map[string]interface{})
	perFilter := connectRoutes[0]["typed_per_filter_config"].(map[string]interface{})
	extAuthz := perFilter["envoy.filters.http.ext_authz"].(map[string]interface{})
	if extAuthz["disabled"] != true {
		t.Fatalf("CONNECT route ext_authz config = %#v", extAuthz)
	}
}

func TestValidateUpstreamScheme(t *testing.T) {
	err := ValidateUpstreams(map[string]UpstreamConfig{
		"example.test": {Scheme: "ftp"},
	})
	if err == nil {
		t.Fatal("invalid scheme was accepted")
	}
}

func TestUpstreamPolicyIsBoundIntoExtAuthzContext(t *testing.T) {
	g := &Generator{upstream: map[string]UpstreamConfig{
		"records.internal": {
			Scheme: "http",
			Policy: "/records/read",
		},
	}}
	route := g.routeForHost("records.internal")
	typed := route["typed_per_filter_config"].(map[string]interface{})
	extAuthz := typed["envoy.filters.http.ext_authz"].(map[string]interface{})
	settings := extAuthz["check_settings"].(map[string]interface{})
	extensions := settings["context_extensions"].(map[string]string)
	if got := extensions["policy"]; got != "/records/read" {
		t.Fatalf("policy context extension = %q", got)
	}
	if err := ValidateUpstreams(g.upstream); err != nil {
		t.Fatal(err)
	}
}

func TestUpstreamPolicyPathMustBeAbsolute(t *testing.T) {
	err := ValidateUpstreams(map[string]UpstreamConfig{
		"records.internal": {Policy: "records/read"},
	})
	if err == nil {
		t.Fatal("relative upstream policy path was accepted")
	}
}
