package jsvm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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
	fingerprint string
	generation  uint64
	pool        chan *scriptRuntime
	plans       []registrationPlan
}

type scriptRuntime struct {
	vm            *goja.Runtime
	httpClient    *http.Client
	registrations []registration
	policies      []policyRegistration
	names         map[string]string
	policyNames   map[string]string
	callContext   context.Context
	source        string
	nextOrder     int
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

func (m *Manager) buildSet(files []scriptFile, fingerprint string, generation uint64) (*runtimeSet, error) {
	pool := make(chan *scriptRuntime, m.poolSize)
	var plans []registrationPlan
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
		}
		pool <- scriptVM
	}
	return &runtimeSet{
		fingerprint: fingerprint,
		generation:  generation,
		pool:        pool,
		plans:       plans,
	}, nil
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
		vm: goja.New(),
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
	if err := r.vm.Set("registerCredentialProvider", r.register); err != nil {
		return err
	}
	if err := r.vm.Set("registerUpstreamPolicy", r.registerPolicy); err != nil {
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
	if err := r.vm.Set("$log", map[string]any{
		"debug": func(message string) { log.Printf("provider: %s", message) },
		"info":  func(message string) { log.Printf("provider: %s", message) },
		"warn":  func(message string) { log.Printf("provider warning: %s", message) },
	}); err != nil {
		return err
	}
	return nil
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

func (r *scriptRuntime) authorizeRequest(ctx context.Context, request policy.Request, config map[string]any) (policy.Decision, error) {
	policyContext, cancel := context.WithTimeout(ctx, providerExecutionTimeout)
	defer cancel()
	r.callContext = policyContext

	decision := policy.Decision{}
	err := r.runWithContext(policyContext, func() error {
		matched := false
		var subject any
		if request.Subject != nil {
			subject = *request.Subject
		}
		constraints := make([]map[string]any, 0, len(request.Constraints))
		for _, constraint := range request.Constraints {
			constraints = append(constraints, map[string]any{
				"namespace": constraint.Namespace,
				"body":      cloneMap(constraint.Body),
			})
		}
		requestValue := map[string]any{
			"policy":         request.Policy,
			"policyType":     request.PolicyType,
			"host":           request.Host,
			"method":         request.Method,
			"path":           request.Path,
			"credential":     request.Credential,
			"credentialType": request.CredentialType,
			"subject":        subject,
			"constraints":    constraints,
		}
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
	if !matchesCredentialType(credentialType, request.CredentialType) {
		return false
	}
	if !matchAny(matcher.hosts, strings.ToLower(request.Host), false) {
		return false
	}
	if !matchAny(matcher.methods, strings.ToUpper(request.Method), true) {
		return false
	}
	if len(matcher.paths) > 0 {
		requestPath := request.Path
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
	inheritEnv, environment := r.execOptions(call)

	ctx := r.callContext
	if ctx == nil {
		ctx = context.Background()
	}
	cmd := exec.CommandContext(ctx, command, args...)
	if !inheritEnv || len(environment) > 0 {
		cmd.Env = mergedEnvironment(inheritEnv, environment)
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

func (r *scriptRuntime) execOptions(call goja.FunctionCall) (bool, map[string]string) {
	inheritEnv := true
	environment := make(map[string]string)
	if len(call.Arguments) < 3 || isNullish(call.Arguments[2]) {
		return inheritEnv, environment
	}

	exported, ok := call.Arguments[2].Export().(map[string]any)
	if !ok {
		panic(r.vm.NewTypeError("$exec.run options must be an object"))
	}
	for key := range exported {
		if key != "inheritEnv" && key != "env" {
			panic(r.vm.NewTypeError("$exec.run unknown option %q", key))
		}
	}
	if value, exists := exported["inheritEnv"]; exists {
		configured, ok := value.(bool)
		if !ok {
			panic(r.vm.NewTypeError("$exec.run inheritEnv must be a boolean"))
		}
		inheritEnv = configured
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
	return inheritEnv, environment
}

func mergedEnvironment(inherit bool, overrides map[string]string) []string {
	values := make(map[string]string, len(overrides))
	if inherit {
		for _, entry := range os.Environ() {
			name, value, ok := strings.Cut(entry, "=")
			if ok {
				values[name] = value
			}
		}
	}
	for name, value := range overrides {
		values[name] = value
	}

	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	result := make([]string, 0, len(names))
	for _, name := range names {
		result = append(result, name+"="+values[name])
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
