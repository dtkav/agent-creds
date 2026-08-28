package main

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"vault/api"
)

func runtimeInventory(_ context.Context, store *runtimeStore) (api.InventoryResponse, error) {
	snapshot := store.Load()
	if snapshot == nil || snapshot.config == nil {
		return api.InventoryResponse{}, fmt.Errorf("vault runtime is not initialized")
	}

	credentialNames := make([]string, 0, len(snapshot.config.Credentials))
	for name := range snapshot.config.Credentials {
		credentialNames = append(credentialNames, name)
	}
	sort.Strings(credentialNames)

	credentials := make([]api.CredentialInventory, 0, len(credentialNames))
	for _, name := range credentialNames {
		configured := snapshot.config.Credentials[name]
		entry := api.CredentialInventory{
			Name:   "/" + strings.TrimPrefix(name, "/"),
			Type:   configured.Type,
			Policy: strings.TrimPrefix(configured.Policy, "/"),
		}
		for _, environment := range []string{configured.Env, configured.EnvUser, configured.EnvPass} {
			if environment != "" {
				entry.Environment = append(entry.Environment, environment)
			}
		}
		for _, reference := range snapshot.config.CredentialSecretRefs[name] {
			entry.SecretRefs = append(entry.SecretRefs, api.CredentialSecretPointer{
				Field:     reference.Field,
				Reference: reference.Reference,
			})
		}
		if configured.Capabilities != nil {
			entry.Hosts = append([]string(nil), configured.Capabilities.Hosts...)
			for _, endpoint := range configured.Capabilities.Endpoints {
				entry.Endpoints = append(entry.Endpoints, api.CredentialEndpoint{
					Methods:     append([]string(nil), endpoint.Methods...),
					Paths:       append([]string(nil), endpoint.Paths...),
					Description: endpoint.Description,
				})
			}
		}
		credentials = append(credentials, entry)
	}

	policyNames := make([]string, 0, len(snapshot.config.Policies))
	for name := range snapshot.config.Policies {
		policyNames = append(policyNames, name)
	}
	sort.Strings(policyNames)
	policies := make([]api.PolicyInventory, 0, len(policyNames))
	for _, name := range policyNames {
		policies = append(policies, api.PolicyInventory{
			Name: name,
			Type: snapshot.config.Policies[name].Type,
		})
	}

	return api.InventoryResponse{
		Generation:  snapshot.generation,
		Credentials: credentials,
		Policies:    policies,
	}, nil
}
