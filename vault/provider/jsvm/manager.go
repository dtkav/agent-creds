package jsvm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dop251/goja"
	"github.com/santhosh-tekuri/jsonschema/v6"

	"vault/macaroon"
	"vault/policy"
	"vault/provider"
)

const (
	reloadInterval           = 500 * time.Millisecond
	initializationTimeout    = 2 * time.Second
	providerExecutionTimeout = 30 * time.Second
	maxHTTPResponseBytes     = 4 << 20
	maxExecOutputBytes       = 4 << 20
	maxExecStderrBytes       = 64 << 10
)

// Spec identifies a configured JavaScript-backed credential. Specs are used to
// validate a newly loaded provider set before it becomes active.
type Spec struct {
	Name   string
	Type   string
	Config map[string]any
}

// PolicySpec identifies a configured JavaScript-backed upstream policy.
type PolicySpec struct {
	Name   string
	Type   string
	Config map[string]any
}

// Manager owns a hot-reloadable pool of JavaScript runtimes. Reloads are
// atomic: requests keep using the last known-good runtime set until every
// script, configured provider, and configured policy validates successfully.
type Manager struct {
	paths       []string
	poolSize    int
	specs       []Spec
	policySpecs []PolicySpec

	current atomic.Pointer[runtimeSet]

	mu                     sync.Mutex
	lastAttemptFingerprint string
}

type runtimeSet struct {
	fingerprint   string
	generation    uint64
	pool          chan *scriptRuntime
	extractorPool chan *extractorRuntime
	plans         []registrationPlan
	macaroons     map[string]string
}

type scriptRuntime struct {
	vm              *goja.Runtime
	httpClient      *http.Client
	credentialTypes map[string]credentialTypeRegistration
	registrations   []registration
	policies        []policyRegistration
	names           map[string]string
	policyNames     map[string]string
	callContext     context.Context
	source          string
	nextOrder       int
}

type credentialTypeRegistration struct {
	configSchema *jsonschema.Schema
	validate     goja.Callable
	macaroon     *credentialMacaroonRegistration
	source       string
}

type credentialMacaroonRegistration struct {
	namespace                string
	constraintSchema         *jsonschema.Schema
	constraintSchemaDocument map[string]any
	validateConstraint       goja.Callable
	constraint               goja.Callable
	authorize                goja.Callable
}

type rejectingSchemaLoader struct{}

func (rejectingSchemaLoader) Load(schemaURL string) (any, error) {
	return nil, fmt.Errorf("external schema references are disabled: %s", schemaURL)
}

type registration struct {
	name           string
	credentialType string
	priority       int
	match          matchSpec
	cacheScope     string
	validate       goja.Callable
	resolve        goja.Callable
	source         string
	order          int
}

type registrationPlan struct {
	name           string
	credentialType string
	match          matchSpec
	cacheScope     string
}

type policyRegistration struct {
	name       string
	policyType string
	validate   goja.Callable
	authorize  goja.Callable
	source     string
}

type matchSpec struct {
	hosts   []string
	methods []string
	paths   []string
}

type scriptFile struct {
	path   string
	source []byte
}

// NewManager loads and validates the initial provider set.
func NewManager(paths []string, poolSize int, specs []Spec) (*Manager, error) {
	return NewManagerWithPolicies(paths, poolSize, specs, nil)
}

// NewManagerWithPolicies loads credential providers and upstream policies
// into one atomically reloadable runtime pool.
func NewManagerWithPolicies(paths []string, poolSize int, specs []Spec, policySpecs []PolicySpec) (*Manager, error) {
	if poolSize <= 0 {
		poolSize = runtime.GOMAXPROCS(0)
		if poolSize > 8 {
			poolSize = 8
		}
		if poolSize < 1 {
			poolSize = 1
		}
	}

	manager := &Manager{
		paths:       cleanPaths(paths),
		poolSize:    poolSize,
		specs:       cloneSpecs(specs),
		policySpecs: clonePolicySpecs(policySpecs),
	}
	files, fingerprint, err := scanScripts(manager.paths)
	if err != nil {
		return nil, err
	}
	set, err := manager.buildSet(files, fingerprint, 1)
	if err != nil {
		return nil, err
	}
	manager.current.Store(set)
	manager.lastAttemptFingerprint = fingerprint
	return manager, nil
}

// StartHotReload polls provider paths until ctx is canceled. Polling handles
// atomic editor renames and provider directories that appear after startup.
func (m *Manager) StartHotReload(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(reloadInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.reloadIfChanged()
			}
		}
	}()
}

func (m *Manager) reloadIfChanged() {
	files, fingerprint, err := scanScripts(m.paths)
	if err != nil {
		log.Printf("Extension reload scan failed; keeping last known-good set: %v", err)
		return
	}

	m.mu.Lock()
	if fingerprint == m.lastAttemptFingerprint {
		m.mu.Unlock()
		return
	}
	m.lastAttemptFingerprint = fingerprint
	m.mu.Unlock()

	current := m.current.Load()
	generation := uint64(1)
	if current != nil {
		generation = current.generation + 1
	}
	next, err := m.buildSet(files, fingerprint, generation)
	if err != nil {
		log.Printf("Extension reload failed; keeping last known-good set: %v", err)
		return
	}
	if current != nil && !sameConfiguredMacaroonNamespaces(current.macaroons, next.macaroons, m.specs) {
		log.Printf("Extension reload failed; keeping last known-good set: credential macaroon namespaces cannot change during provider hot reload")
		return
	}
	m.current.Store(next)
	log.Printf("Reloaded %d JavaScript extension runtime(s) from %d script(s)", m.poolSize, len(files))
}

// Provider returns a CredentialProvider bound to one configured credential.
func (m *Manager) Provider(spec Spec) provider.CredentialProvider {
	return &jsCredentialProvider{
		manager: m,
		spec: Spec{
			Name:   spec.Name,
			Type:   spec.Type,
			Config: cloneMap(spec.Config),
		},
	}
}

// Extractor returns a capability extractor bound to one configured
// credential. It executes in a separate, restricted JavaScript runtime and
// never receives spec.Config.
func (m *Manager) Extractor(spec Spec) provider.CredentialExtractor {
	return &jsCredentialExtractor{
		manager: m,
		spec: Spec{
			Name: spec.Name,
			Type: spec.Type,
		},
	}
}

// Policy returns an Authorizer bound to one configured upstream policy.
func (m *Manager) Policy(spec PolicySpec) policy.Authorizer {
	return &jsUpstreamPolicy{
		manager: m,
		spec: PolicySpec{
			Name:   spec.Name,
			Type:   spec.Type,
			Config: cloneMap(spec.Config),
		},
	}
}

// CredentialMacaroon binds one configured credential to the macaroon
// namespace and callbacks declared by its JavaScript credential type.
// Constraint returns public attenuation data suitable for embedding in a
// minted capability; Authorize enforces both current config and verified
// caveats at request time.
type CredentialMacaroon struct {
	manager   *Manager
	spec      Spec
	namespace string
}

func (m *Manager) Macaroon(spec Spec) (*CredentialMacaroon, bool) {
	set := m.current.Load()
	if set == nil {
		return nil, false
	}
	namespace, ok := set.macaroons[spec.Type]
	if !ok {
		return nil, false
	}
	return &CredentialMacaroon{
		manager: m,
		spec: Spec{
			Name:   spec.Name,
			Type:   spec.Type,
			Config: cloneMap(spec.Config),
		},
		namespace: namespace,
	}, true
}

func (m *CredentialMacaroon) Namespace() string { return m.namespace }

func (m *CredentialMacaroon) Constraint(ctx context.Context) (*policy.Constraint, error) {
	return m.manager.credentialConstraint(ctx, m.spec, m.namespace)
}

func (m *CredentialMacaroon) ConstraintSchema(ctx context.Context) (map[string]any, error) {
	return m.manager.credentialConstraintSchema(ctx, m.spec, m.namespace)
}

func (m *CredentialMacaroon) ValidateConstraint(ctx context.Context, body map[string]any) error {
	return m.manager.validateCredentialConstraint(ctx, m.spec, m.namespace, body)
}

func (m *CredentialMacaroon) Authorize(ctx context.Context, request policy.Request) (policy.Decision, error) {
	request.Policy = m.spec.Name
	request.PolicyType = m.spec.Type
	request.Credential = m.spec.Name
	request.CredentialType = m.spec.Type
	return m.manager.authorizeCredential(ctx, request, m.spec, m.namespace)
}

func (m *Manager) buildSet(files []scriptFile, fingerprint string, generation uint64) (*runtimeSet, error) {
	pool := make(chan *scriptRuntime, m.poolSize)
	extractorPool := make(chan *extractorRuntime, m.poolSize)
	var plans []registrationPlan
	var macaroons map[string]string
	for i := 0; i < m.poolSize; i++ {
		scriptVM, err := newScriptRuntime(files)
		if err != nil {
			return nil, err
		}
		if i == 0 {
			if err := scriptVM.validateSpecs(m.specs); err != nil {
				return nil, err
			}
			if err := scriptVM.validatePolicySpecs(m.policySpecs); err != nil {
				return nil, err
			}
			plans = scriptVM.registrationPlans()
			macaroons = scriptVM.macaroonNamespaces()
		}
		pool <- scriptVM
	}
	for i := 0; i < m.poolSize; i++ {
		extractorVM, err := newExtractorRuntime(files)
		if err != nil {
			return nil, err
		}
		extractorPool <- extractorVM
	}
	return &runtimeSet{
		fingerprint:   fingerprint,
		generation:    generation,
		pool:          pool,
		extractorPool: extractorPool,
		plans:         plans,
		macaroons:     macaroons,
	}, nil
}

func (m *Manager) extract(ctx context.Context, request provider.ExtractionRequest) (string, error) {
	set := m.current.Load()
	if set == nil {
		return "", fmt.Errorf("JavaScript extractor runtime is not loaded")
	}

	var extractorVM *extractorRuntime
	select {
	case extractorVM = <-set.extractorPool:
	case <-ctx.Done():
		return "", ctx.Err()
	}
	defer func() {
		extractorVM.callContext = nil
		set.extractorPool <- extractorVM
	}()
	return extractorVM.extractRequest(ctx, request)
}

func (m *Manager) resolve(ctx context.Context, request provider.Request, config map[string]any) (provider.Result, uint64, error) {
	set := m.current.Load()
	if set == nil {
		return provider.Result{}, 0, fmt.Errorf("JavaScript provider runtime is not loaded")
	}

	var scriptVM *scriptRuntime
	select {
	case scriptVM = <-set.pool:
	case <-ctx.Done():
		return provider.Result{}, set.generation, ctx.Err()
	}
	defer func() {
		scriptVM.callContext = nil
		set.pool <- scriptVM
	}()

	result, err := scriptVM.resolve(ctx, request, config)
	return result, set.generation, err
}

func (m *Manager) authorize(ctx context.Context, request policy.Request, config map[string]any) (policy.Decision, error) {
	set := m.current.Load()
	if set == nil {
		return policy.Decision{}, fmt.Errorf("JavaScript policy runtime is not loaded")
	}

	var scriptVM *scriptRuntime
	select {
	case scriptVM = <-set.pool:
	case <-ctx.Done():
		return policy.Decision{}, ctx.Err()
	}
	defer func() {
		scriptVM.callContext = nil
		set.pool <- scriptVM
	}()
	return scriptVM.authorizeRequest(ctx, request, config)
}

func (m *Manager) credentialConstraint(ctx context.Context, spec Spec, namespace string) (*policy.Constraint, error) {
	set := m.current.Load()
	if set == nil {
		return nil, fmt.Errorf("JavaScript credential runtime is not loaded")
	}

	var scriptVM *scriptRuntime
	select {
	case scriptVM = <-set.pool:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() {
		scriptVM.callContext = nil
		set.pool <- scriptVM
	}()
	return scriptVM.credentialConstraint(ctx, spec, namespace)
}

func (m *Manager) credentialConstraintSchema(ctx context.Context, spec Spec, namespace string) (map[string]any, error) {
	set := m.current.Load()
	if set == nil {
		return nil, fmt.Errorf("JavaScript credential runtime is not loaded")
	}

	var scriptVM *scriptRuntime
	select {
	case scriptVM = <-set.pool:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { set.pool <- scriptVM }()
	return scriptVM.credentialConstraintSchema(spec, namespace)
}

func (m *Manager) validateCredentialConstraint(ctx context.Context, spec Spec, namespace string, body map[string]any) error {
	set := m.current.Load()
	if set == nil {
		return fmt.Errorf("JavaScript credential runtime is not loaded")
	}

	var scriptVM *scriptRuntime
	select {
	case scriptVM = <-set.pool:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { set.pool <- scriptVM }()
	defer func() { scriptVM.callContext = nil }()
	return scriptVM.validateCredentialConstraint(ctx, spec, namespace, body)
}

func (m *Manager) authorizeCredential(ctx context.Context, request policy.Request, spec Spec, namespace string) (policy.Decision, error) {
	set := m.current.Load()
	if set == nil {
		return policy.Decision{}, fmt.Errorf("JavaScript credential runtime is not loaded")
	}

	var scriptVM *scriptRuntime
	select {
	case scriptVM = <-set.pool:
	case <-ctx.Done():
		return policy.Decision{}, ctx.Err()
	}
	defer func() {
		scriptVM.callContext = nil
		set.pool <- scriptVM
	}()
	return scriptVM.authorizeCredential(ctx, request, spec, namespace)
}

type jsUpstreamPolicy struct {
	manager *Manager
	spec    PolicySpec
}

func (p *jsUpstreamPolicy) Authorize(ctx context.Context, request policy.Request) (policy.Decision, error) {
	request.Policy = p.spec.Name
	request.PolicyType = p.spec.Type
	return p.manager.authorize(ctx, request, p.spec.Config)
}

type jsCredentialProvider struct {
	manager *Manager
	spec    Spec

	mu              sync.Mutex
	cached          map[string]provider.Result
	cacheGeneration uint64
}

type jsCredentialExtractor struct {
	manager *Manager
	spec    Spec
}

func (e *jsCredentialExtractor) Extract(ctx context.Context, request provider.ExtractionRequest) (string, error) {
	request.Credential = e.spec.Name
	request.CredentialType = e.spec.Type
	return e.manager.extract(ctx, request)
}

func (p *jsCredentialProvider) Resolve(ctx context.Context, request provider.Request) (provider.Result, error) {
	set := p.manager.current.Load()
	if set == nil {
		return provider.Result{}, fmt.Errorf("JavaScript provider runtime is not loaded")
	}

	request.Credential = p.spec.Name
	request.CredentialType = p.spec.Type
	cacheKey, cacheable := set.cacheKey(request)

	p.mu.Lock()
	if p.cacheGeneration != set.generation {
		p.cached = make(map[string]provider.Result)
		p.cacheGeneration = set.generation
	}
	if cacheable {
		cached := p.cached[cacheKey]
		if len(cached.Headers) > 0 &&
			!cached.ExpiresAt.IsZero() &&
			time.Now().Add(30*time.Second).Before(cached.ExpiresAt) {
			result := cloneResult(cached)
			p.mu.Unlock()
			return result, nil
		}
	}
	p.mu.Unlock()

	result, generation, err := p.manager.resolve(ctx, request, p.spec.Config)
	if err != nil {
		return provider.Result{}, err
	}
	if err := provider.ValidateHeaders(result.Headers); err != nil {
		return provider.Result{}, err
	}

	if cacheable && generation == set.generation && !result.ExpiresAt.IsZero() {
		p.mu.Lock()
		if p.cacheGeneration == generation {
			p.cached[cacheKey] = cloneResult(result)
		}
		p.mu.Unlock()
	}
	return result, nil
}

func newScriptRuntime(files []scriptFile) (*scriptRuntime, error) {
	scriptVM := &scriptRuntime{
		vm:              goja.New(),
		credentialTypes: make(map[string]credentialTypeRegistration),
		httpClient: &http.Client{
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		names:       make(map[string]string),
		policyNames: make(map[string]string),
	}
	scriptVM.vm.SetFieldNameMapper(goja.TagFieldNameMapper("json", true))
	if err := scriptVM.installGlobals(); err != nil {
		return nil, err
	}
	for _, file := range files {
		scriptVM.source = file.path
		loadContext, cancel := context.WithTimeout(context.Background(), initializationTimeout)
		scriptVM.callContext = loadContext
		err := scriptVM.runWithContext(loadContext, func() error {
			_, runErr := scriptVM.vm.RunScript(file.path, string(file.source))
			return runErr
		})
		cancel()
		scriptVM.callContext = nil
		if err != nil {
			return nil, fmt.Errorf("loading provider script %s: %w", file.path, err)
		}
	}
	sort.SliceStable(scriptVM.registrations, func(i, j int) bool {
		left := scriptVM.registrations[i]
		right := scriptVM.registrations[j]
		if left.priority != right.priority {
			return left.priority < right.priority
		}
		if left.source != right.source {
			return left.source < right.source
		}
		return left.order < right.order
	})
	sort.SliceStable(scriptVM.policies, func(i, j int) bool {
		if scriptVM.policies[i].source != scriptVM.policies[j].source {
			return scriptVM.policies[i].source < scriptVM.policies[j].source
		}
		return scriptVM.policies[i].name < scriptVM.policies[j].name
	})
	return scriptVM, nil
}

func (r *scriptRuntime) installGlobals() error {
	if err := r.vm.Set("registerCredentialType", r.registerCredentialType); err != nil {
		return err
	}
	if err := r.vm.Set("registerCredentialProvider", r.register); err != nil {
		return err
	}
	if err := r.vm.Set("registerUpstreamPolicy", r.registerPolicy); err != nil {
		return err
	}
	// The same plugin file may define both halves of a credential adapter. The
	// extractor registration is evaluated in its own restricted VM below.
	if err := r.vm.Set("registerCredentialExtractor", ignoredRegistration); err != nil {
		return err
	}
	if err := r.vm.Set("$exec", map[string]any{"run": r.execRun}); err != nil {
		return err
	}
	if err := r.vm.Set("$http", map[string]any{"request": r.httpRequest}); err != nil {
		return err
	}
	if err := r.vm.Set("$jwt", map[string]any{"expiresAt": r.jwtExpiresAt}); err != nil {
		return err
	}
	if err := r.vm.Set("$base64", map[string]any{
		"encode": func(value string) string {
			return base64.StdEncoding.EncodeToString([]byte(value))
		},
	}); err != nil {
		return err
	}
	if err := r.vm.Set("$log", map[string]any{
		"debug": func(message string) { log.Printf("provider: %s", message) },
		"info":  func(message string) { log.Printf("provider: %s", message) },
		"warn":  func(message string) { log.Printf("provider warning: %s", message) },
	}); err != nil {
		return err
	}
	return nil
}

func ignoredRegistration(goja.FunctionCall) goja.Value {
	return goja.Undefined()
}

func (r *scriptRuntime) registerCredentialType(call goja.FunctionCall) goja.Value {
	if len(call.Arguments) != 1 || isNullish(call.Arguments[0]) {
		panic(r.vm.NewTypeError("registerCredentialType expects one credential type object"))
	}
	object := call.Arguments[0].ToObject(r.vm)
	credentialType := requiredObjectString(r.vm, object, "credentialType")
	if previous, exists := r.credentialTypes[credentialType]; exists {
		panic(r.vm.NewTypeError(
			"credential type %q from %s is already registered by %s",
			credentialType,
			r.source,
			previous.source,
		))
	}

	schemaValue := object.Get("configSchema")
	if isNullish(schemaValue) {
		panic(r.vm.NewTypeError("credential type %q must define configSchema", credentialType))
	}
	compiledSchema, err := compileCredentialConfigSchema(credentialType, schemaValue.Export())
	if err != nil {
		panic(r.vm.NewTypeError("credential type %q has invalid configSchema: %v", credentialType, err))
	}

	var validate goja.Callable
	if value := object.Get("validate"); !isNullish(value) {
		var valid bool
		validate, valid = goja.AssertFunction(value)
		if !valid {
			panic(r.vm.NewTypeError("credential type %q validate must be a function", credentialType))
		}
	}

	var macaroonRegistration *credentialMacaroonRegistration
	if value := object.Get("macaroon"); !isNullish(value) {
		macaroonObject := value.ToObject(r.vm)
		namespace := requiredObjectString(r.vm, macaroonObject, "namespace")
		var constraintSchema *jsonschema.Schema
		var constraintSchemaDocument map[string]any
		if schemaValue := macaroonObject.Get("constraintSchema"); !isNullish(schemaValue) {
			constraintSchemaDocument, err = normalizeSchemaDocument(schemaValue.Export())
			if err != nil {
				panic(r.vm.NewTypeError("credential type %q has invalid macaroon.constraintSchema: %v", credentialType, err))
			}
			constraintSchema, err = compileCredentialConfigSchema(credentialType+"-authorization", constraintSchemaDocument)
			if err != nil {
				panic(r.vm.NewTypeError("credential type %q has invalid macaroon.constraintSchema: %v", credentialType, err))
			}
		}
		var validateConstraint goja.Callable
		if validateValue := macaroonObject.Get("validateConstraint"); !isNullish(validateValue) {
			var valid bool
			validateConstraint, valid = goja.AssertFunction(validateValue)
			if !valid {
				panic(r.vm.NewTypeError("credential type %q macaroon.validateConstraint must be a function", credentialType))
			}
		}
		constraint, ok := goja.AssertFunction(macaroonObject.Get("constraint"))
		if !ok {
			panic(r.vm.NewTypeError("credential type %q macaroon.constraint must be a function", credentialType))
		}
		authorize, ok := goja.AssertFunction(macaroonObject.Get("authorize"))
		if !ok {
			panic(r.vm.NewTypeError("credential type %q macaroon.authorize must be a function", credentialType))
		}
		macaroonRegistration = &credentialMacaroonRegistration{
			namespace:                namespace,
			constraintSchema:         constraintSchema,
			constraintSchemaDocument: constraintSchemaDocument,
			validateConstraint:       validateConstraint,
			constraint:               constraint,
			authorize:                authorize,
		}
	}

	r.credentialTypes[credentialType] = credentialTypeRegistration{
		configSchema: compiledSchema,
		validate:     validate,
		macaroon:     macaroonRegistration,
		source:       r.source,
	}
	return goja.Undefined()
}

func (r *scriptRuntime) register(call goja.FunctionCall) goja.Value {
	if len(call.Arguments) != 1 || isNullish(call.Arguments[0]) {
		panic(r.vm.NewTypeError("registerCredentialProvider expects one provider object"))
	}
	object := call.Arguments[0].ToObject(r.vm)

	name := requiredObjectString(r.vm, object, "name")
	credentialType := requiredObjectString(r.vm, object, "credentialType")
	if previousSource, exists := r.names[name]; exists {
		panic(r.vm.NewTypeError(
			"provider name %q from %s is already registered by %s",
			name,
			r.source,
			previousSource,
		))
	}
	priority := 0
	if value := object.Get("priority"); !isNullish(value) {
		priority = int(value.ToInteger())
	}
	resolve, ok := goja.AssertFunction(object.Get("resolve"))
	if !ok {
		panic(r.vm.NewTypeError("provider %q must define resolve(request, config)", name))
	}
	var validate goja.Callable
	if value := object.Get("validate"); !isNullish(value) {
		var valid bool
		validate, valid = goja.AssertFunction(value)
		if !valid {
			panic(r.vm.NewTypeError("provider %q validate must be a function", name))
		}
	}
	cacheScope := ""
	if value := object.Get("cache"); !isNullish(value) {
		cacheScope = value.String()
		if cacheScope != "credential" {
			panic(r.vm.NewTypeError("provider %q has unsupported cache scope %q", name, cacheScope))
		}
	}

	matcher := matchSpec{}
	if value := object.Get("match"); !isNullish(value) {
		matchObject := value.ToObject(r.vm)
		matcher.hosts = objectStringList(r.vm, matchObject, "hosts")
		matcher.methods = objectStringList(r.vm, matchObject, "methods")
		matcher.paths = objectStringList(r.vm, matchObject, "paths")
	}
	normalizeMatchPatterns(r.vm, &matcher)

	r.registrations = append(r.registrations, registration{
		name:           name,
		credentialType: credentialType,
		priority:       priority,
		match:          matcher,
		cacheScope:     cacheScope,
		validate:       validate,
		resolve:        resolve,
		source:         r.source,
		order:          r.nextOrder,
	})
	r.names[name] = r.source
	r.nextOrder++
	return goja.Undefined()
}

func (r *scriptRuntime) registerPolicy(call goja.FunctionCall) goja.Value {
	if len(call.Arguments) != 1 || isNullish(call.Arguments[0]) {
		panic(r.vm.NewTypeError("registerUpstreamPolicy expects one policy object"))
	}
	object := call.Arguments[0].ToObject(r.vm)
	name := requiredObjectString(r.vm, object, "name")
	policyType := requiredObjectString(r.vm, object, "policyType")
	if previousSource, exists := r.policyNames[name]; exists {
		panic(r.vm.NewTypeError(
			"policy name %q from %s is already registered by %s",
			name,
			r.source,
			previousSource,
		))
	}
	authorize, ok := goja.AssertFunction(object.Get("authorize"))
	if !ok {
		panic(r.vm.NewTypeError("policy %q must define authorize(request, config)", name))
	}
	var validate goja.Callable
	if value := object.Get("validate"); !isNullish(value) {
		var valid bool
		validate, valid = goja.AssertFunction(value)
		if !valid {
			panic(r.vm.NewTypeError("policy %q validate must be a function", name))
		}
	}
	r.policies = append(r.policies, policyRegistration{
		name:       name,
		policyType: policyType,
		validate:   validate,
		authorize:  authorize,
		source:     r.source,
	})
	r.policyNames[name] = r.source
	return goja.Undefined()
}

func (r *scriptRuntime) validateSpecs(specs []Spec) error {
	for _, spec := range specs {
		if registeredType, ok := r.credentialTypes[spec.Type]; ok {
			if err := registeredType.configSchema.Validate(cloneMap(spec.Config)); err != nil {
				return fmt.Errorf(
					"validating credential %q with schema for type %q: %s",
					spec.Name,
					spec.Type,
					safeSchemaValidationError(err),
				)
			}
			if registeredType.validate != nil {
				validationContext, cancel := context.WithTimeout(context.Background(), initializationTimeout)
				r.callContext = validationContext
				err := r.runWithContext(validationContext, func() error {
					_, validateErr := registeredType.validate(
						goja.Undefined(),
						r.vm.ToValue(cloneMap(spec.Config)),
					)
					return validateErr
				})
				cancel()
				r.callContext = nil
				if err != nil {
					return fmt.Errorf("validating credential %q with type %q: %w", spec.Name, spec.Type, err)
				}
			}
			if registeredType.macaroon != nil {
				validationContext, cancel := context.WithTimeout(context.Background(), initializationTimeout)
				_, err := r.credentialConstraint(validationContext, spec, registeredType.macaroon.namespace)
				cancel()
				if err != nil {
					return fmt.Errorf("deriving macaroon constraint for credential %q with type %q: %w", spec.Name, spec.Type, err)
				}
			}
		}

		matched := false
		for _, registration := range r.registrations {
			if !matchesCredentialType(registration.credentialType, spec.Type) {
				continue
			}
			matched = true
			if registration.validate == nil {
				continue
			}
			validationContext, cancel := context.WithTimeout(context.Background(), initializationTimeout)
			r.callContext = validationContext
			err := r.runWithContext(validationContext, func() error {
				_, validateErr := registration.validate(
					goja.Undefined(),
					r.vm.ToValue(cloneMap(spec.Config)),
				)
				return validateErr
			})
			cancel()
			r.callContext = nil
			if err != nil {
				return fmt.Errorf("validating credential %q with provider %q: %w", spec.Name, registration.name, err)
			}
		}
		if !matched {
			return fmt.Errorf("credential %q uses unregistered JavaScript provider type %q", spec.Name, spec.Type)
		}
	}
	return nil
}

func compileCredentialConfigSchema(credentialType string, exported any) (*jsonschema.Schema, error) {
	encoded, err := json.Marshal(exported)
	if err != nil {
		return nil, fmt.Errorf("schema must be a JSON value: %w", err)
	}
	document, err := jsonschema.UnmarshalJSON(bytes.NewReader(encoded))
	if err != nil {
		return nil, fmt.Errorf("decoding schema: %w", err)
	}

	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	// Built-in meta-schemas and document-local references work, while file and
	// network references fail closed without attempting I/O.
	compiler.UseLoader(rejectingSchemaLoader{})
	resourceURL := "https://agent-creds.invalid/schemas/credential/" + url.PathEscape(credentialType)
	if err := compiler.AddResource(resourceURL, document); err != nil {
		return nil, err
	}
	compiled, err := compiler.Compile(resourceURL)
	if err != nil {
		return nil, fmt.Errorf("compiling Draft 2020-12 schema: %w", err)
	}
	return compiled, nil
}

func normalizeSchemaDocument(exported any) (map[string]any, error) {
	encoded, err := json.Marshal(exported)
	if err != nil {
		return nil, fmt.Errorf("schema must be a JSON value: %w", err)
	}
	var document map[string]any
	if err := json.Unmarshal(encoded, &document); err != nil {
		return nil, fmt.Errorf("schema must be a JSON object: %w", err)
	}
	if document == nil {
		return nil, fmt.Errorf("schema must be a JSON object")
	}
	return document, nil
}

func safeSchemaValidationError(err error) string {
	var validationErr *jsonschema.ValidationError
	if !errors.As(err, &validationErr) {
		return "configuration does not match the registered schema"
	}

	var details []string
	appendSchemaValidationDetails(validationErr, &details)
	if len(details) == 0 {
		return "configuration does not match the registered schema"
	}
	if len(details) > 8 {
		details = append(details[:8], "additional validation errors omitted")
	}
	return "configuration does not match the registered schema: " + strings.Join(details, "; ")
}

func appendSchemaValidationDetails(err *jsonschema.ValidationError, details *[]string) {
	if len(*details) >= 9 {
		return
	}
	if len(err.Causes) > 0 {
		for _, cause := range err.Causes {
			appendSchemaValidationDetails(cause, details)
			if len(*details) >= 9 {
				return
			}
		}
		return
	}

	instancePath := schemaInstancePath(err.InstanceLocation)
	keyword := "schema"
	if path := err.ErrorKind.KeywordPath(); len(path) > 0 {
		keyword = path[len(path)-1]
	}
	*details = append(*details, fmt.Sprintf("%s (%s)", instancePath, keyword))
}

func schemaInstancePath(parts []string) string {
	if len(parts) == 0 {
		return "/"
	}
	escaped := make([]string, len(parts))
	for i, part := range parts {
		part = strings.ReplaceAll(part, "~", "~0")
		escaped[i] = strings.ReplaceAll(part, "/", "~1")
	}
	return "/" + strings.Join(escaped, "/")
}

func (r *scriptRuntime) validatePolicySpecs(specs []PolicySpec) error {
	for _, spec := range specs {
		matched := false
		for _, registration := range r.policies {
			if !matchesCredentialType(registration.policyType, spec.Type) {
				continue
			}
			matched = true
			if registration.validate == nil {
				continue
			}
			validationContext, cancel := context.WithTimeout(context.Background(), initializationTimeout)
			r.callContext = validationContext
			err := r.runWithContext(validationContext, func() error {
				_, validateErr := registration.validate(
					goja.Undefined(),
					r.vm.ToValue(cloneMap(spec.Config)),
				)
				return validateErr
			})
			cancel()
			r.callContext = nil
			if err != nil {
				return fmt.Errorf("validating upstream policy %q with implementation %q: %w", spec.Name, registration.name, err)
			}
		}
		if !matched {
			return fmt.Errorf("upstream policy %q uses unregistered JavaScript policy type %q", spec.Name, spec.Type)
		}
	}
	return nil
}

func (r *scriptRuntime) registrationPlans() []registrationPlan {
	plans := make([]registrationPlan, 0, len(r.registrations))
	for _, registration := range r.registrations {
		plans = append(plans, registrationPlan{
			name:           registration.name,
			credentialType: registration.credentialType,
			match:          registration.match,
			cacheScope:     registration.cacheScope,
		})
	}
	return plans
}

func (r *scriptRuntime) macaroonNamespaces() map[string]string {
	result := make(map[string]string)
	for credentialType, registration := range r.credentialTypes {
		if registration.macaroon != nil {
			result[credentialType] = registration.macaroon.namespace
		}
	}
	return result
}

func (r *scriptRuntime) resolve(ctx context.Context, request provider.Request, config map[string]any) (provider.Result, error) {
	providerContext, cancel := context.WithTimeout(ctx, providerExecutionTimeout)
	defer cancel()
	r.callContext = providerContext

	var result provider.Result
	err := r.runWithContext(providerContext, func() error {
		var resolveErr error
		result, resolveErr = r.resolveMatched(request, config)
		return resolveErr
	})
	return result, err
}

func (r *scriptRuntime) resolveMatched(request provider.Request, config map[string]any) (provider.Result, error) {
	merged := provider.Result{Headers: make(map[string]string)}
	matched := false
	hasUncachedResult := false

	requestValue := map[string]any{
		"credential":     request.Credential,
		"credentialType": request.CredentialType,
		"host":           request.Host,
		"method":         request.Method,
		"path":           request.Path,
		"headers":        cloneStringMap(request.Headers),
		"body":           r.vm.ToValue(r.vm.NewArrayBuffer(bytes.Clone(request.Body))),
		"bodyPartial":    request.BodyPartial,
	}

	for _, registration := range r.registrations {
		if !registration.matches(request) {
			continue
		}
		matched = true
		value, err := registration.resolve(
			goja.Undefined(),
			r.vm.ToValue(requestValue),
			r.vm.ToValue(cloneMap(config)),
		)
		if err != nil {
			return provider.Result{}, fmt.Errorf("provider %q failed: %w", registration.name, err)
		}
		result, err := exportResult(r.vm, registration.name, value)
		if err != nil {
			return provider.Result{}, err
		}
		for name, headerValue := range result.Headers {
			merged.Headers[strings.ToLower(name)] = headerValue
		}
		if result.ExpiresAt.IsZero() {
			hasUncachedResult = true
		} else if merged.ExpiresAt.IsZero() || result.ExpiresAt.Before(merged.ExpiresAt) {
			merged.ExpiresAt = result.ExpiresAt
		}
		if result.Stop {
			merged.Stop = true
			break
		}
	}

	if !matched {
		return provider.Result{}, fmt.Errorf(
			"no JavaScript provider matched credential type %q for %s %s%s",
			request.CredentialType,
			request.Method,
			request.Host,
			request.Path,
		)
	}
	if hasUncachedResult {
		merged.ExpiresAt = time.Time{}
	}
	if err := provider.ValidateHeaders(merged.Headers); err != nil {
		return provider.Result{}, err
	}
	return merged, nil
}

func (r *scriptRuntime) credentialConstraint(ctx context.Context, spec Spec, namespace string) (*policy.Constraint, error) {
	credentialContext, cancel := context.WithTimeout(ctx, providerExecutionTimeout)
	defer cancel()
	r.callContext = credentialContext

	var constraint *policy.Constraint
	err := r.runWithContext(credentialContext, func() error {
		registeredType, ok := r.credentialTypes[spec.Type]
		if !ok || registeredType.macaroon == nil {
			return fmt.Errorf("credential type %q has no macaroon registration", spec.Type)
		}
		if registeredType.macaroon.namespace != namespace {
			return fmt.Errorf("credential type %q changed macaroon namespace from %q to %q", spec.Type, namespace, registeredType.macaroon.namespace)
		}
		value, callErr := registeredType.macaroon.constraint(
			goja.Undefined(),
			r.vm.ToValue(cloneMap(spec.Config)),
		)
		if callErr != nil {
			return callErr
		}
		if isNullish(value) {
			return nil
		}
		exported, ok := value.Export().(map[string]any)
		if !ok {
			return fmt.Errorf("macaroon.constraint must return an object or null")
		}
		encoded, err := json.Marshal(exported)
		if err != nil {
			return fmt.Errorf("macaroon.constraint returned a non-JSON value: %w", err)
		}
		var body map[string]any
		if err := json.Unmarshal(encoded, &body); err != nil {
			return fmt.Errorf("normalizing macaroon.constraint result: %w", err)
		}
		constraint = &policy.Constraint{Namespace: namespace, Body: body}
		return nil
	})
	return constraint, err
}

func (r *scriptRuntime) credentialConstraintSchema(spec Spec, namespace string) (map[string]any, error) {
	registeredType, ok := r.credentialTypes[spec.Type]
	if !ok || registeredType.macaroon == nil {
		return nil, fmt.Errorf("credential type %q has no macaroon registration", spec.Type)
	}
	if registeredType.macaroon.namespace != namespace {
		return nil, fmt.Errorf("credential type %q changed macaroon namespace from %q to %q", spec.Type, namespace, registeredType.macaroon.namespace)
	}
	if registeredType.macaroon.constraintSchemaDocument == nil {
		return nil, nil
	}
	return cloneMap(registeredType.macaroon.constraintSchemaDocument), nil
}

func (r *scriptRuntime) validateCredentialConstraint(ctx context.Context, spec Spec, namespace string, body map[string]any) error {
	registeredType, ok := r.credentialTypes[spec.Type]
	if !ok || registeredType.macaroon == nil {
		return fmt.Errorf("credential type %q has no macaroon registration", spec.Type)
	}
	if registeredType.macaroon.namespace != namespace {
		return fmt.Errorf("credential type %q changed macaroon namespace from %q to %q", spec.Type, namespace, registeredType.macaroon.namespace)
	}
	if registeredType.macaroon.constraintSchema == nil {
		return fmt.Errorf("credential type %q does not declare macaroon.constraintSchema", spec.Type)
	}
	if err := registeredType.macaroon.constraintSchema.Validate(cloneMap(body)); err != nil {
		return fmt.Errorf("validating authorization for credential %q with type %q: %s", spec.Name, spec.Type, safeSchemaValidationError(err))
	}
	if registeredType.macaroon.validateConstraint != nil {
		validationContext, cancel := context.WithTimeout(ctx, providerExecutionTimeout)
		defer cancel()
		r.callContext = validationContext
		if err := r.runWithContext(validationContext, func() error {
			_, validateErr := registeredType.macaroon.validateConstraint(
				goja.Undefined(),
				r.vm.ToValue(cloneMap(body)),
			)
			return validateErr
		}); err != nil {
			return fmt.Errorf("validating authorization for credential %q with type %q: %w", spec.Name, spec.Type, err)
		}
	}
	return nil
}

func (r *scriptRuntime) authorizeCredential(ctx context.Context, request policy.Request, spec Spec, namespace string) (policy.Decision, error) {
	policyContext, cancel := context.WithTimeout(ctx, providerExecutionTimeout)
	defer cancel()
	r.callContext = policyContext

	decision := policy.Decision{}
	err := r.runWithContext(policyContext, func() error {
		registeredType, ok := r.credentialTypes[spec.Type]
		if !ok || registeredType.macaroon == nil {
			return fmt.Errorf("credential type %q has no macaroon registration", spec.Type)
		}
		if registeredType.macaroon.namespace != namespace {
			return fmt.Errorf("credential type %q changed macaroon namespace from %q to %q", spec.Type, namespace, registeredType.macaroon.namespace)
		}
		for _, constraint := range request.Constraints {
			if constraint.Namespace != namespace {
				decision = policy.Deny(fmt.Sprintf("credential type %s cannot consume macaroon constraint namespace %q", spec.Type, constraint.Namespace))
				return nil
			}
		}
		value, callErr := registeredType.macaroon.authorize(
			goja.Undefined(),
			r.vm.ToValue(r.policyRequestValue(request)),
			r.vm.ToValue(cloneMap(spec.Config)),
		)
		if callErr != nil {
			return callErr
		}
		var exportErr error
		decision, exportErr = exportPolicyDecision(r.vm, "credential type "+spec.Type+" macaroon authorizer", value)
		return exportErr
	})
	return decision, err
}

func (r *scriptRuntime) policyRequestValue(request policy.Request) map[string]any {
	constraints := make([]map[string]any, 0, len(request.Constraints))
	for _, constraint := range request.Constraints {
		constraints = append(constraints, map[string]any{
			"namespace":  constraint.Namespace,
			"body":       cloneMap(constraint.Body),
			"authorized": constraint.Authorized,
		})
	}
	return map[string]any{
		"policy":         request.Policy,
		"policyType":     request.PolicyType,
		"host":           request.Host,
		"method":         request.Method,
		"path":           request.Path,
		"body":           r.vm.ToValue(r.vm.NewArrayBuffer(bytes.Clone(request.Body))),
		"bodyPartial":    request.BodyPartial,
		"credential":     request.Credential,
		"credentialType": request.CredentialType,
		"constraints":    constraints,
	}
}

func (r *scriptRuntime) authorizeRequest(ctx context.Context, request policy.Request, config map[string]any) (policy.Decision, error) {
	policyContext, cancel := context.WithTimeout(ctx, providerExecutionTimeout)
	defer cancel()
	r.callContext = policyContext

	decision := policy.Decision{}
	err := r.runWithContext(policyContext, func() error {
		matched := false
		requestValue := r.policyRequestValue(request)
		for _, registration := range r.policies {
			if !matchesCredentialType(registration.policyType, request.PolicyType) {
				continue
			}
			matched = true
			value, callErr := registration.authorize(
				goja.Undefined(),
				r.vm.ToValue(requestValue),
				r.vm.ToValue(cloneMap(config)),
			)
			if callErr != nil {
				return fmt.Errorf("upstream policy %q failed: %w", registration.name, callErr)
			}
			registrationDecision, exportErr := exportPolicyDecision(r.vm, registration.name, value)
			if exportErr != nil {
				return exportErr
			}
			if !registrationDecision.Allow {
				decision = registrationDecision
				return nil
			}
		}
		if !matched {
			return fmt.Errorf("no JavaScript policy matched policy type %q", request.PolicyType)
		}
		decision = policy.Allow()
		return nil
	})
	return decision, err
}

func exportPolicyDecision(vm *goja.Runtime, policyName string, value goja.Value) (policy.Decision, error) {
	if isNullish(value) {
		return policy.Decision{}, fmt.Errorf("upstream policy %q returned no decision", policyName)
	}
	if boolean, ok := value.Export().(bool); ok {
		if boolean {
			return policy.Allow(), nil
		}
		return policy.Deny("request denied by upstream policy"), nil
	}
	object := value.ToObject(vm)
	allowValue := object.Get("allow")
	if isNullish(allowValue) {
		return policy.Decision{}, fmt.Errorf("upstream policy %q decision must include allow", policyName)
	}
	decision := policy.Decision{Allow: allowValue.ToBoolean()}
	if reasonValue := object.Get("reason"); !isNullish(reasonValue) {
		decision.Reason = strings.TrimSpace(reasonValue.String())
	}
	if !decision.Allow && decision.Reason == "" {
		decision.Reason = "request denied by upstream policy"
	}
	return decision, nil
}

func (r *scriptRuntime) runWithContext(ctx context.Context, run func() error) error {
	finished := make(chan struct{})
	interruptFinished := make(chan struct{})
	go func() {
		defer close(interruptFinished)
		select {
		case <-ctx.Done():
			r.vm.Interrupt(ctx.Err())
		case <-finished:
		}
	}()

	err := run()
	close(finished)
	<-interruptFinished
	r.vm.ClearInterrupt()
	return err
}

func (r registration) matches(request provider.Request) bool {
	return matchesRegistration(r.credentialType, r.match, request)
}

func (s *runtimeSet) cacheKey(request provider.Request) (string, bool) {
	var names []string
	for _, plan := range s.plans {
		if !matchesRegistration(plan.credentialType, plan.match, request) {
			continue
		}
		if plan.cacheScope != "credential" {
			return "", false
		}
		names = append(names, plan.name)
	}
	if len(names) == 0 {
		return "", false
	}
	return strings.Join(names, "\x00"), true
}

func matchesRegistration(credentialType string, matcher matchSpec, request provider.Request) bool {
	return matchesRequest(
		credentialType,
		matcher,
		request.CredentialType,
		request.Host,
		request.Method,
		request.Path,
	)
}

func matchesRequest(credentialType string, matcher matchSpec, requestCredentialType, host, method, requestPath string) bool {
	if !matchesCredentialType(credentialType, requestCredentialType) {
		return false
	}
	if !matchAny(matcher.hosts, strings.ToLower(host), false) {
		return false
	}
	if !matchAny(matcher.methods, strings.ToUpper(method), true) {
		return false
	}
	if len(matcher.paths) > 0 {
		if index := strings.IndexByte(requestPath, '?'); index >= 0 {
			requestPath = requestPath[:index]
		}
		pathMatched := false
		for _, pattern := range matcher.paths {
			if macaroon.MatchPath(pattern, requestPath) {
				pathMatched = true
				break
			}
		}
		if !pathMatched {
			return false
		}
	}
	return true
}

func matchesCredentialType(pattern, credentialType string) bool {
	return pattern == "*" || pattern == credentialType
}

func matchAny(patterns []string, value string, upper bool) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, patternValue := range patterns {
		candidate := patternValue
		if upper {
			candidate = strings.ToUpper(candidate)
		}
		if matched, _ := path.Match(candidate, value); matched {
			return true
		}
	}
	return false
}

func exportResult(vm *goja.Runtime, providerName string, value goja.Value) (provider.Result, error) {
	if isNullish(value) {
		return provider.Result{}, fmt.Errorf("provider %q returned no result", providerName)
	}
	object := value.ToObject(vm)
	headersValue := object.Get("headers")
	if isNullish(headersValue) {
		return provider.Result{}, fmt.Errorf("provider %q returned no headers", providerName)
	}
	exported, ok := headersValue.Export().(map[string]any)
	if !ok {
		return provider.Result{}, fmt.Errorf("provider %q headers must be an object", providerName)
	}
	headers := make(map[string]string, len(exported))
	for name, rawValue := range exported {
		value, ok := rawValue.(string)
		if !ok {
			return provider.Result{}, fmt.Errorf("provider %q header %q must be a string", providerName, name)
		}
		headers[name] = value
	}

	result := provider.Result{Headers: headers}
	if expiresAt := object.Get("expiresAt"); !isNullish(expiresAt) {
		seconds := expiresAt.ToInteger()
		if seconds > 0 {
			result.ExpiresAt = time.Unix(seconds, 0)
		}
	}
	if stop := object.Get("stop"); !isNullish(stop) {
		result.Stop = stop.ToBoolean()
	}
	return result, nil
}

func (r *scriptRuntime) execRun(call goja.FunctionCall) goja.Value {
	if len(call.Arguments) < 1 || len(call.Arguments) > 3 {
		panic(r.vm.NewTypeError("$exec.run expects a command, optional argument array, and optional options object"))
	}
	command := call.Arguments[0].String()
	if strings.TrimSpace(command) == "" {
		panic(r.vm.NewTypeError("$exec.run command must not be empty"))
	}
	var args []string
	if len(call.Arguments) > 1 && !isNullish(call.Arguments[1]) {
		exported := call.Arguments[1].Export()
		switch values := exported.(type) {
		case []any:
			for _, value := range values {
				text, ok := value.(string)
				if !ok {
					panic(r.vm.NewTypeError("$exec.run arguments must be strings"))
				}
				args = append(args, text)
			}
		case []string:
			args = append(args, values...)
		default:
			panic(r.vm.NewTypeError("$exec.run arguments must be an array"))
		}
	}
	environment, stdin := r.execOptions(call)

	ctx := r.callContext
	if ctx == nil {
		ctx = context.Background()
	}
	cmd := exec.CommandContext(ctx, command, args...)
	cmd.Env = explicitEnvironment(environment)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	stdout := &cappedBuffer{limit: maxExecOutputBytes}
	stderr := &cappedBuffer{limit: maxExecStderrBytes}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err := cmd.Run()
	if stdout.exceeded {
		panic(r.vm.NewGoError(fmt.Errorf("$exec.run output exceeded %d bytes", maxExecOutputBytes)))
	}
	if err != nil {
		stderrText := strings.TrimSpace(stderr.String())
		if stderr.exceeded {
			stderrText += " (truncated)"
		}
		if stderrText != "" {
			err = fmt.Errorf("%w: %s", err, stderrText)
		}
		panic(r.vm.NewGoError(err))
	}
	return r.vm.ToValue(strings.TrimSpace(stdout.String()))
}

func (r *scriptRuntime) execOptions(call goja.FunctionCall) (map[string]string, string) {
	environment := make(map[string]string)
	var stdin string
	if len(call.Arguments) < 3 || isNullish(call.Arguments[2]) {
		return environment, stdin
	}

	exported, ok := call.Arguments[2].Export().(map[string]any)
	if !ok {
		panic(r.vm.NewTypeError("$exec.run options must be an object"))
	}
	for key := range exported {
		if key != "env" && key != "stdin" {
			panic(r.vm.NewTypeError("$exec.run unknown option %q", key))
		}
	}
	if value, exists := exported["env"]; exists {
		values, ok := value.(map[string]any)
		if !ok {
			panic(r.vm.NewTypeError("$exec.run env must be an object"))
		}
		for key, rawValue := range values {
			text, ok := rawValue.(string)
			if !ok {
				panic(r.vm.NewTypeError("$exec.run environment values must be strings"))
			}
			if key == "" || strings.ContainsAny(key, "=\x00") {
				panic(r.vm.NewTypeError("$exec.run environment name %q is invalid", key))
			}
			if strings.ContainsRune(text, '\x00') {
				panic(r.vm.NewTypeError("$exec.run environment value for %q contains a null byte", key))
			}
			environment[key] = text
		}
	}
	if value, exists := exported["stdin"]; exists {
		text, ok := value.(string)
		if !ok {
			panic(r.vm.NewTypeError("$exec.run stdin must be a string"))
		}
		if len(text) > maxExecOutputBytes {
			panic(r.vm.NewTypeError("$exec.run stdin exceeded %d bytes", maxExecOutputBytes))
		}
		stdin = text
	}
	return environment, stdin
}

func explicitEnvironment(environment map[string]string) []string {
	names := make([]string, 0, len(environment))
	for name := range environment {
		names = append(names, name)
	}
	sort.Strings(names)
	result := make([]string, 0, len(names))
	for _, name := range names {
		result = append(result, name+"="+environment[name])
	}
	return result
}

type cappedBuffer struct {
	buffer   bytes.Buffer
	limit    int
	exceeded bool
}

func (b *cappedBuffer) Write(value []byte) (int, error) {
	written := len(value)
	remaining := b.limit - b.buffer.Len()
	if remaining <= 0 {
		b.exceeded = true
		return written, nil
	}
	if len(value) > remaining {
		_, _ = b.buffer.Write(value[:remaining])
		b.exceeded = true
		return written, nil
	}
	_, _ = b.buffer.Write(value)
	return written, nil
}

func (b *cappedBuffer) String() string {
	return b.buffer.String()
}

func (r *scriptRuntime) httpRequest(call goja.FunctionCall) goja.Value {
	if len(call.Arguments) != 1 || isNullish(call.Arguments[0]) {
		panic(r.vm.NewTypeError("$http.request expects one options object"))
	}
	options := call.Arguments[0].ToObject(r.vm)
	rawURL := requiredObjectString(r.vm, options, "url")
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		panic(r.vm.NewTypeError("$http.request url must be an absolute http or https URL"))
	}

	method := "GET"
	if value := options.Get("method"); !isNullish(value) {
		method = strings.ToUpper(strings.TrimSpace(value.String()))
		if method == "" {
			panic(r.vm.NewTypeError("$http.request method must not be empty"))
		}
	}
	var body []byte
	if value := options.Get("body"); !isNullish(value) {
		body = []byte(value.String())
	}

	ctx := r.callContext
	if ctx == nil {
		ctx = context.Background()
	}
	request, err := http.NewRequestWithContext(ctx, method, rawURL, bytes.NewReader(body))
	if err != nil {
		panic(r.vm.NewGoError(err))
	}
	if value := options.Get("headers"); !isNullish(value) {
		exported, ok := value.Export().(map[string]any)
		if !ok {
			panic(r.vm.NewTypeError("$http.request headers must be an object"))
		}
		for name, rawValue := range exported {
			headerValue, ok := rawValue.(string)
			if !ok {
				panic(r.vm.NewTypeError("$http.request header %q must be a string", name))
			}
			request.Header.Set(name, headerValue)
		}
	}

	response, err := r.httpClient.Do(request)
	if err != nil {
		panic(r.vm.NewGoError(err))
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, maxHTTPResponseBytes+1))
	if err != nil {
		panic(r.vm.NewGoError(err))
	}
	if len(responseBody) > maxHTTPResponseBytes {
		panic(r.vm.NewGoError(fmt.Errorf(
			"$http.request response exceeds %d bytes",
			maxHTTPResponseBytes,
		)))
	}

	responseHeaders := make(map[string][]string, len(response.Header))
	for name, values := range response.Header {
		responseHeaders[strings.ToLower(name)] = append([]string(nil), values...)
	}
	return r.vm.ToValue(map[string]any{
		"status":  response.StatusCode,
		"headers": responseHeaders,
		"body":    string(responseBody),
	})
}

func (r *scriptRuntime) jwtExpiresAt(token string) int64 {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return 0
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return 0
	}
	var claims struct {
		ExpiresAt json.Number `json:"exp"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.UseNumber()
	if err := decoder.Decode(&claims); err != nil {
		return 0
	}
	expiresAt, _ := strconv.ParseInt(string(claims.ExpiresAt), 10, 64)
	return expiresAt
}

func requiredObjectString(vm *goja.Runtime, object *goja.Object, key string) string {
	value := object.Get(key)
	if isNullish(value) {
		panic(vm.NewTypeError("%s is required", key))
	}
	text := strings.TrimSpace(value.String())
	if text == "" {
		panic(vm.NewTypeError("%s is required", key))
	}
	return text
}

func objectStringList(vm *goja.Runtime, object *goja.Object, key string) []string {
	value := object.Get(key)
	if isNullish(value) {
		return nil
	}
	exported := value.Export()
	var result []string
	switch values := exported.(type) {
	case []any:
		for _, value := range values {
			text, ok := value.(string)
			if !ok {
				panic(vm.NewTypeError("%s must contain only strings", key))
			}
			result = append(result, text)
		}
	case []string:
		result = append(result, values...)
	default:
		panic(vm.NewTypeError("%s must be an array of strings", key))
	}
	return result
}

func normalizeMatchPatterns(vm *goja.Runtime, matcher *matchSpec) {
	for i, patternValue := range matcher.hosts {
		patternValue = strings.ToLower(strings.TrimSpace(patternValue))
		if patternValue == "" {
			panic(vm.NewTypeError("match.hosts must not contain an empty pattern"))
		}
		if _, err := path.Match(patternValue, "validation-host"); err != nil {
			panic(vm.NewTypeError("invalid host pattern %q: %v", patternValue, err))
		}
		matcher.hosts[i] = patternValue
	}
	for i, patternValue := range matcher.methods {
		patternValue = strings.ToUpper(strings.TrimSpace(patternValue))
		if patternValue == "" {
			panic(vm.NewTypeError("match.methods must not contain an empty pattern"))
		}
		if _, err := path.Match(patternValue, "GET"); err != nil {
			panic(vm.NewTypeError("invalid method pattern %q: %v", patternValue, err))
		}
		matcher.methods[i] = patternValue
	}
	for i, patternValue := range matcher.paths {
		patternValue = strings.TrimSpace(patternValue)
		if patternValue == "" {
			panic(vm.NewTypeError("match.paths must not contain an empty pattern"))
		}
		matcher.paths[i] = patternValue
	}
}

func scanScripts(paths []string) ([]scriptFile, string, error) {
	var files []scriptFile
	for _, configuredPath := range paths {
		info, err := os.Stat(configuredPath)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, "", fmt.Errorf("stat provider path %s: %w", configuredPath, err)
		}
		if !info.IsDir() {
			if isExtensionScript(configuredPath) {
				source, err := os.ReadFile(configuredPath)
				if err != nil {
					return nil, "", fmt.Errorf("read provider script %s: %w", configuredPath, err)
				}
				files = append(files, scriptFile{path: configuredPath, source: source})
			}
			continue
		}
		entries, err := os.ReadDir(configuredPath)
		if err != nil {
			return nil, "", fmt.Errorf("read provider directory %s: %w", configuredPath, err)
		}
		for _, entry := range entries {
			if entry.IsDir() || !isExtensionScript(entry.Name()) {
				continue
			}
			scriptPath := filepath.Join(configuredPath, entry.Name())
			source, err := os.ReadFile(scriptPath)
			if err != nil {
				return nil, "", fmt.Errorf("read provider script %s: %w", scriptPath, err)
			}
			files = append(files, scriptFile{path: scriptPath, source: source})
		}
	}
	sort.Slice(files, func(i, j int) bool { return files[i].path < files[j].path })

	hasher := sha256.New()
	for _, file := range files {
		hasher.Write([]byte(file.path))
		hasher.Write([]byte{0})
		hasher.Write(file.source)
		hasher.Write([]byte{0})
	}
	return files, hex.EncodeToString(hasher.Sum(nil)), nil
}

func isExtensionScript(name string) bool {
	return strings.HasSuffix(name, ".provider.js") || strings.HasSuffix(name, ".policy.js")
}

func cleanPaths(paths []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, configuredPath := range paths {
		configuredPath = strings.TrimSpace(configuredPath)
		if configuredPath == "" {
			continue
		}
		absolute, err := filepath.Abs(configuredPath)
		if err == nil {
			configuredPath = absolute
		}
		if !seen[configuredPath] {
			seen[configuredPath] = true
			result = append(result, configuredPath)
		}
	}
	sort.Strings(result)
	return result
}

func cloneSpecs(specs []Spec) []Spec {
	result := make([]Spec, len(specs))
	for i, spec := range specs {
		result[i] = Spec{Name: spec.Name, Type: spec.Type, Config: cloneMap(spec.Config)}
	}
	return result
}

func sameConfiguredMacaroonNamespaces(left, right map[string]string, specs []Spec) bool {
	for _, spec := range specs {
		leftNamespace, leftOK := left[spec.Type]
		rightNamespace, rightOK := right[spec.Type]
		if leftOK != rightOK || leftNamespace != rightNamespace {
			return false
		}
	}
	return true
}

func clonePolicySpecs(specs []PolicySpec) []PolicySpec {
	result := make([]PolicySpec, len(specs))
	for i, spec := range specs {
		result[i] = PolicySpec{Name: spec.Name, Type: spec.Type, Config: cloneMap(spec.Config)}
	}
	return result
}

func cloneMap(src map[string]any) map[string]any {
	dst := make(map[string]any, len(src))
	for key, value := range src {
		dst[key] = value
	}
	return dst
}

func cloneStringMap(src map[string]string) map[string]string {
	dst := make(map[string]string, len(src))
	for key, value := range src {
		dst[key] = value
	}
	return dst
}

func cloneResult(src provider.Result) provider.Result {
	return provider.Result{
		Headers:   cloneStringMap(src.Headers),
		ExpiresAt: src.ExpiresAt,
		Stop:      src.Stop,
	}
}

func isNullish(value goja.Value) bool {
	return value == nil || goja.IsUndefined(value) || goja.IsNull(value)
}
