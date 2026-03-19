package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

func runCredentials(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: actl vault credentials <command>")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Commands:")
		fmt.Fprintln(os.Stderr, "  add [path]    Add a new credential to vault.yaml")
		os.Exit(1)
	}

	switch args[0] {
	case "add":
		credentialsAdd(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown credentials command: %s\n", args[0])
		os.Exit(1)
	}
}

func credentialsAdd(args []string) {
	yamlPath := vaultYAMLPath()
	if _, err := os.Stat(yamlPath); os.IsNotExist(err) {
		fmt.Fprintln(os.Stderr, "No vault.yaml found. Run: actl vault init")
		os.Exit(1)
	}

	reader := bufio.NewReader(os.Stdin)

	// Get credential path
	credPath := ""
	if len(args) > 0 {
		credPath = args[0]
	} else {
		credPath = prompt(reader, "Credential path (e.g. /stripe/prod): ")
	}
	credPath = strings.TrimSpace(credPath)
	if credPath == "" {
		fmt.Fprintln(os.Stderr, "Error: credential path is required")
		os.Exit(1)
	}
	// Normalize: strip leading / for map key
	credKey := strings.TrimPrefix(credPath, "/")

	// Get credential type
	credType := prompt(reader, "Type (bearer/basic/sigv4): ")
	credType = strings.TrimSpace(credType)
	if credType == "" {
		credType = "bearer"
	}
	if credType != "bearer" && credType != "basic" && credType != "sigv4" {
		fmt.Fprintf(os.Stderr, "Error: unsupported type %q (must be bearer, basic, or sigv4)\n", credType)
		os.Exit(1)
	}

	// Build credential node
	credNode := &yaml.Node{Kind: yaml.MappingNode}
	addScalar(credNode, "type", credType)

	switch credType {
	case "bearer":
		token := prompt(reader, "Secret (API key or $secret ref): ")
		token = strings.TrimSpace(token)
		if token == "" {
			fmt.Fprintln(os.Stderr, "Error: secret is required")
			os.Exit(1)
		}
		addSecretOrScalar(credNode, "token", token)

		envVar := prompt(reader, "Env var name (e.g. STRIPE_API_KEY): ")
		envVar = strings.TrimSpace(envVar)
		if envVar != "" {
			addScalar(credNode, "env", envVar)
		}

	case "basic":
		username := prompt(reader, "Username (or $secret ref): ")
		username = strings.TrimSpace(username)
		if username == "" {
			fmt.Fprintln(os.Stderr, "Error: username is required")
			os.Exit(1)
		}
		addSecretOrScalar(credNode, "username", username)

		password := prompt(reader, "Password (or $secret ref): ")
		password = strings.TrimSpace(password)
		if password == "" {
			fmt.Fprintln(os.Stderr, "Error: password is required")
			os.Exit(1)
		}
		addSecretOrScalar(credNode, "password", password)

		envUser := prompt(reader, "Env var for username (e.g. REGISTRY_USER): ")
		envUser = strings.TrimSpace(envUser)
		if envUser != "" {
			addScalar(credNode, "env_user", envUser)
		}
		envPass := prompt(reader, "Env var for password (e.g. REGISTRY_PASS): ")
		envPass = strings.TrimSpace(envPass)
		if envPass != "" {
			addScalar(credNode, "env_pass", envPass)
		}

	case "sigv4":
		region := prompt(reader, "AWS region (e.g. us-east-1): ")
		region = strings.TrimSpace(region)
		if region != "" {
			addScalar(credNode, "region", region)
		}

		accessKey := prompt(reader, "Access Key ID (or $secret ref): ")
		accessKey = strings.TrimSpace(accessKey)
		if accessKey == "" {
			fmt.Fprintln(os.Stderr, "Error: access key ID is required")
			os.Exit(1)
		}
		addSecretOrScalar(credNode, "access_key_id", accessKey)

		secretKey := prompt(reader, "Secret Access Key (or $secret ref): ")
		secretKey = strings.TrimSpace(secretKey)
		if secretKey == "" {
			fmt.Fprintln(os.Stderr, "Error: secret access key is required")
			os.Exit(1)
		}
		addSecretOrScalar(credNode, "secret_access_key", secretKey)
	}

	// Optional capabilities
	capsFile := ""
	for _, a := range args {
		if strings.HasPrefix(a, "--capabilities=") {
			capsFile = strings.TrimPrefix(a, "--capabilities=")
		}
	}
	// Also check positional: --capabilities <file>
	for i, a := range args {
		if a == "--capabilities" && i+1 < len(args) {
			capsFile = args[i+1]
		}
	}

	if capsFile != "" {
		capsData, err := os.ReadFile(capsFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading capabilities file: %v\n", err)
			os.Exit(1)
		}
		var capsNode yaml.Node
		if err := yaml.Unmarshal(capsData, &capsNode); err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing capabilities YAML: %v\n", err)
			os.Exit(1)
		}
		if capsNode.Kind == yaml.DocumentNode && len(capsNode.Content) > 0 {
			credNode.Content = append(credNode.Content,
				&yaml.Node{Kind: yaml.ScalarNode, Value: "capabilities"},
				capsNode.Content[0],
			)
		}
	} else {
		desc := prompt(reader, "Describe capabilities (or press enter to skip): ")
		desc = strings.TrimSpace(desc)
		if desc != "" {
			// Parse hosts and endpoints from description
			capsNode := buildCapsFromDescription(reader, desc)
			if capsNode != nil {
				credNode.Content = append(credNode.Content,
					&yaml.Node{Kind: yaml.ScalarNode, Value: "capabilities"},
					capsNode,
				)
			}
		}
	}

	// Decrypt vault.yaml
	out, err := runSops("--decrypt", yamlPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error decrypting vault.yaml: %v\n", err)
		os.Exit(1)
	}

	var doc yaml.Node
	if err := yaml.Unmarshal(out, &doc); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing vault.yaml: %v\n", err)
		os.Exit(1)
	}

	// Check for existing credential
	root := doc.Content[0]
	credsNode := findOrCreateMapping(root, "credentials")
	for i := 0; i < len(credsNode.Content)-1; i += 2 {
		if credsNode.Content[i].Value == credKey {
			fmt.Fprintf(os.Stderr, "Error: credential /%s already exists. Use 'actl vault edit' to modify.\n", credKey)
			os.Exit(1)
		}
	}

	// Add the credential
	credsNode.Content = append(credsNode.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Value: credKey},
		credNode,
	)

	// Write modified YAML to temp file, re-encrypt
	modified, err := yaml.Marshal(&doc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error serializing vault.yaml: %v\n", err)
		os.Exit(1)
	}

	tmpFile, err := os.CreateTemp("", "vault-*.yaml")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	if _, err := tmpFile.Write(modified); err != nil {
		tmpFile.Close()
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	tmpFile.Close()

	encrypted, err := sopsEncrypt(tmpPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error encrypting vault.yaml: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(yamlPath, encrypted, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing %s: %v\n", yamlPath, err)
		os.Exit(1)
	}

	fmt.Printf("Added credential /%s (type: %s)\n", credKey, credType)
}

func prompt(reader *bufio.Reader, msg string) string {
	fmt.Print(msg)
	line, _ := reader.ReadString('\n')
	return strings.TrimRight(line, "\n\r")
}

// addScalar appends a key-value scalar pair to a mapping node.
func addScalar(node *yaml.Node, key, value string) {
	node.Content = append(node.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Value: key},
		&yaml.Node{Kind: yaml.ScalarNode, Value: value},
	)
}

// addSecretOrScalar adds a value either as a plain scalar or as a $secret mapping.
// If value starts with "$secret:", it's treated as a secret reference.
func addSecretOrScalar(node *yaml.Node, key, value string) {
	if strings.HasPrefix(value, "$secret:") {
		ref := strings.TrimPrefix(value, "$secret:")
		ref = strings.TrimSpace(ref)
		ref = strings.Trim(ref, "'\"")
		valNode := &yaml.Node{Kind: yaml.MappingNode}
		valNode.Content = append(valNode.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Value: "$secret"},
			&yaml.Node{Kind: yaml.ScalarNode, Value: ref, Style: yaml.SingleQuotedStyle},
		)
		node.Content = append(node.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Value: key},
			valNode,
		)
	} else {
		addScalar(node, key, value)
	}
}

// buildCapsFromDescription creates a capabilities YAML node from interactive prompts.
func buildCapsFromDescription(reader *bufio.Reader, description string) *yaml.Node {
	capsNode := &yaml.Node{Kind: yaml.MappingNode}

	hosts := prompt(reader, "Hosts (comma-separated, e.g. api.stripe.com): ")
	hosts = strings.TrimSpace(hosts)
	if hosts != "" {
		hostList := strings.Split(hosts, ",")
		hostsSeq := &yaml.Node{Kind: yaml.SequenceNode, Style: yaml.FlowStyle}
		for _, h := range hostList {
			h = strings.TrimSpace(h)
			if h != "" {
				hostsSeq.Content = append(hostsSeq.Content,
					&yaml.Node{Kind: yaml.ScalarNode, Value: h},
				)
			}
		}
		capsNode.Content = append(capsNode.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Value: "hosts"},
			hostsSeq,
		)
	}

	// Add description as a comment for reference, build endpoints interactively
	endpointsSeq := &yaml.Node{Kind: yaml.SequenceNode}
	fmt.Printf("Description: %s\n", description)
	fmt.Println("Add endpoints (empty methods line to finish):")
	for {
		methods := prompt(reader, "  Methods (e.g. GET,POST): ")
		methods = strings.TrimSpace(methods)
		if methods == "" {
			break
		}
		paths := prompt(reader, "  Paths (e.g. /v1/customers/**): ")
		paths = strings.TrimSpace(paths)
		if paths == "" {
			continue
		}
		epDesc := prompt(reader, "  Description (optional): ")
		epDesc = strings.TrimSpace(epDesc)

		epNode := &yaml.Node{Kind: yaml.MappingNode}

		methodSeq := &yaml.Node{Kind: yaml.SequenceNode, Style: yaml.FlowStyle}
		for _, m := range strings.Split(methods, ",") {
			m = strings.TrimSpace(m)
			if m != "" {
				methodSeq.Content = append(methodSeq.Content,
					&yaml.Node{Kind: yaml.ScalarNode, Value: m},
				)
			}
		}
		epNode.Content = append(epNode.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Value: "methods"},
			methodSeq,
		)

		pathSeq := &yaml.Node{Kind: yaml.SequenceNode, Style: yaml.FlowStyle}
		for _, p := range strings.Split(paths, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				pathSeq.Content = append(pathSeq.Content,
					&yaml.Node{Kind: yaml.ScalarNode, Value: p},
				)
			}
		}
		epNode.Content = append(epNode.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Value: "paths"},
			pathSeq,
		)

		if epDesc != "" {
			epNode.Content = append(epNode.Content,
				&yaml.Node{Kind: yaml.ScalarNode, Value: "description"},
				&yaml.Node{Kind: yaml.ScalarNode, Value: epDesc},
			)
		}

		endpointsSeq.Content = append(endpointsSeq.Content, epNode)
	}

	if len(endpointsSeq.Content) > 0 {
		capsNode.Content = append(capsNode.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Value: "endpoints"},
			endpointsSeq,
		)
	}

	if len(capsNode.Content) == 0 {
		return nil
	}
	return capsNode
}
