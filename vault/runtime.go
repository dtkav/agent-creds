package main

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"vault/policy"
	"vault/provider"
	"vault/provider/jsvm"
	vaultcfg "vault/vault"
)

// runtimeSnapshot is the complete configuration-derived authorization state.
// A request loads one pointer and uses that immutable snapshot throughout, so
// it can never observe a partial configuration reload.
type runtimeSnapshot struct {
	generation    uint64
	config        *vaultcfg.Config
	credentials   map[string]configuredCredential
	policies      map[string]policy.Authorizer
	stopProviders context.CancelFunc
}

// runtimeStore serializes reloads and publishes last-known-good snapshots with
// one atomic pointer swap.
type runtimeStore struct {
	current       atomic.Pointer[runtimeSnapshot]
	reloadMu      sync.Mutex
	providerPaths []string
	providerPool  int
}

func newRuntimeStore(initial *runtimeSnapshot, paths []string, poolSize int) *runtimeStore {
	store := &runtimeStore{
		providerPaths: append([]string(nil), paths...),
		providerPool:  poolSize,
	}
	if initial != nil {
		if initial.generation == 0 {
			initial.generation = 1
		}
		store.current.Store(initial)
	}
	return store
}

func (s *runtimeStore) Load() *runtimeSnapshot {
	if s == nil {
		return nil
	}
	return s.current.Load()
}

func (s *runtimeStore) Reload(config *vaultcfg.Config) ([]string, error) {
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()

	active := s.current.Load()
	if active == nil || active.config == nil {
		return nil, fmt.Errorf("vault runtime is not initialized")
	}
	if config == nil {
		return nil, fmt.Errorf("vault config is required")
	}
	// vault-ssh keeps the original key material in memory for minting and
	// discharge. Reject key changes so both processes remain cryptographically
	// consistent and existing capability tokens stay valid.
	if config.SigningKey != active.config.SigningKey || config.EncryptionKey != active.config.EncryptionKey {
		return nil, fmt.Errorf("live reload cannot change macaroon signing or encryption keys")
	}

	next, warnings, err := buildRuntimeSnapshot(config, s.providerPaths, s.providerPool)
	if err != nil {
		return warnings, err
	}
	next.generation = active.generation + 1
	s.current.Store(next)
	if active.stopProviders != nil {
		// Stop only the old snapshot's file watcher. Existing requests retain
		// their providers and can finish against the old immutable snapshot.
		active.stopProviders()
	}
	return warnings, nil
}

func (s *runtimeStore) Close() {
	if s == nil {
		return
	}
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()
	if active := s.current.Load(); active != nil && active.stopProviders != nil {
		active.stopProviders()
	}
}

func buildRuntimeSnapshot(config *vaultcfg.Config, paths []string, poolSize int) (*runtimeSnapshot, []string, error) {
	if config == nil {
		return nil, nil, fmt.Errorf("vault config is required")
	}
	warnings, err := config.Validate()
	if err != nil {
		return nil, warnings, fmt.Errorf("invalid vault config: %w", err)
	}

	registry := provider.NewRegistry()
	if err := provider.RegisterBuiltins(registry); err != nil {
		return nil, warnings, fmt.Errorf("registering built-in credential providers: %w", err)
	}

	var jsSpecs []jsvm.Spec
	for name, credential := range config.Credentials {
		if registry.Has(credential.Type) {
			continue
		}
		jsSpecs = append(jsSpecs, jsvm.Spec{
			Name:   name,
			Type:   credential.Type,
			Config: credential.ProviderConfig(),
		})
	}
	sort.Slice(jsSpecs, func(i, j int) bool { return jsSpecs[i].Name < jsSpecs[j].Name })

	var jsPolicySpecs []jsvm.PolicySpec
	for name, configuredPolicy := range config.Policies {
		jsPolicySpecs = append(jsPolicySpecs, jsvm.PolicySpec{
			Name:   name,
			Type:   configuredPolicy.Type,
			Config: configuredPolicy.Config(),
		})
	}
	sort.Slice(jsPolicySpecs, func(i, j int) bool { return jsPolicySpecs[i].Name < jsPolicySpecs[j].Name })

	var jsManager *jsvm.Manager
	if len(jsSpecs) > 0 || len(jsPolicySpecs) > 0 {
		jsManager, err = jsvm.NewManagerWithPolicies(paths, poolSize, jsSpecs, jsPolicySpecs)
		if err != nil {
			return nil, warnings, fmt.Errorf("loading JavaScript extensions: %w", err)
		}
	}

	policies := make(map[string]policy.Authorizer, len(jsPolicySpecs))
	for _, spec := range jsPolicySpecs {
		policies[spec.Name] = jsManager.Policy(spec)
	}

	credentials := make(map[string]configuredCredential, len(config.Credentials))
	for name, credential := range config.Credentials {
		var credentialProvider provider.CredentialProvider
		var credentialExtractor provider.CredentialExtractor
		if registry.Has(credential.Type) {
			credentialProvider, err = registry.Build(credential.Type, credential.ProviderConfig())
		} else if jsManager != nil {
			spec := jsvm.Spec{
				Name:   name,
				Type:   credential.Type,
				Config: credential.ProviderConfig(),
			}
			credentialProvider = jsManager.Provider(spec)
			credentialExtractor = jsManager.Extractor(spec)
		} else {
			err = fmt.Errorf("credential provider %q is not registered", credential.Type)
		}
		if err != nil {
			return nil, warnings, fmt.Errorf("configuring credentials for %s: %w", name, err)
		}
		credentials[name] = configuredCredential{
			name:           name,
			credentialType: credential.Type,
			extractor:      credentialExtractor,
			provider:       credentialProvider,
			policy:         strings.TrimPrefix(credential.Policy, "/"),
		}
	}

	providerContext, stopProviders := context.WithCancel(context.Background())
	if jsManager != nil {
		jsManager.StartHotReload(providerContext)
	}
	return &runtimeSnapshot{
		config:        config,
		credentials:   credentials,
		policies:      policies,
		stopProviders: stopProviders,
	}, warnings, nil
}

// currentRuntime preserves the direct map fields for focused authServer unit
// tests while production requests use the atomically published runtime store.
func (s *authServer) currentRuntime() *runtimeSnapshot {
	if s.runtime != nil {
		if snapshot := s.runtime.Load(); snapshot != nil {
			return snapshot
		}
	}
	return &runtimeSnapshot{credentials: s.credentials, policies: s.policies}
}
