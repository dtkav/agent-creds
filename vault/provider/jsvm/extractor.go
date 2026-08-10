package jsvm

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/dop251/goja"

	"vault/provider"
)

const (
	extractorExecutionTimeout = 100 * time.Millisecond
	maxExtractedTokenBytes    = 64 << 10
)

// extractorRuntime is deliberately separate from scriptRuntime. It has no
// provider configuration, resolved secrets, HTTP client, process execution,
// or JWT helper. A plugin can register both hooks, but they execute in
// different VMs with different globals.
type extractorRuntime struct {
	vm            *goja.Runtime
	registrations []extractorRegistration
	names         map[string]string
	callContext   context.Context
	source        string
	nextOrder     int
}

type extractorRegistration struct {
	name           string
	credentialType string
	priority       int
	match          matchSpec
	extract        goja.Callable
	source         string
	order          int
}

func newExtractorRuntime(files []scriptFile) (*extractorRuntime, error) {
	runtime := &extractorRuntime{
		vm:    goja.New(),
		names: make(map[string]string),
	}
	runtime.vm.SetFieldNameMapper(goja.TagFieldNameMapper("json", true))
	if err := runtime.installGlobals(); err != nil {
		return nil, err
	}
	for _, file := range files {
		runtime.source = file.path
		loadContext, cancel := context.WithTimeout(context.Background(), initializationTimeout)
		runtime.callContext = loadContext
		err := runtime.runWithContext(loadContext, func() error {
			_, runErr := runtime.vm.RunScript(file.path, string(file.source))
			return runErr
		})
		cancel()
		runtime.callContext = nil
		if err != nil {
			return nil, fmt.Errorf("loading extractor script %s: %w", file.path, err)
		}
	}
	sort.SliceStable(runtime.registrations, func(i, j int) bool {
		left := runtime.registrations[i]
		right := runtime.registrations[j]
		if left.priority != right.priority {
			return left.priority < right.priority
		}
		if left.source != right.source {
			return left.source < right.source
		}
		return left.order < right.order
	})
	return runtime, nil
}

func (r *extractorRuntime) installGlobals() error {
	// Provider and policy registrations are intentionally ignored here so a
	// single reviewed plugin file can declare both execution-zone hooks.
	if err := r.vm.Set("registerCredentialProvider", ignoredRegistration); err != nil {
		return err
	}
	if err := r.vm.Set("registerUpstreamPolicy", ignoredRegistration); err != nil {
		return err
	}
	if err := r.vm.Set("registerCredentialExtractor", r.register); err != nil {
		return err
	}
	if err := r.vm.Set("$base64", map[string]any{"decode": r.decodeBase64}); err != nil {
		return err
	}
	if err := r.vm.Set("$log", map[string]any{
		"debug": func(message string) { log.Printf("extractor: %s", message) },
		"info":  func(message string) { log.Printf("extractor: %s", message) },
		"warn":  func(message string) { log.Printf("extractor warning: %s", message) },
	}); err != nil {
		return err
	}
	return nil
}

func (r *extractorRuntime) register(call goja.FunctionCall) goja.Value {
	if len(call.Arguments) != 1 || isNullish(call.Arguments[0]) {
		panic(r.vm.NewTypeError("registerCredentialExtractor expects one extractor object"))
	}
	object := call.Arguments[0].ToObject(r.vm)
	name := requiredObjectString(r.vm, object, "name")
	credentialType := requiredObjectString(r.vm, object, "credentialType")
	if previousSource, exists := r.names[name]; exists {
		panic(r.vm.NewTypeError(
			"extractor name %q from %s is already registered by %s",
			name,
			r.source,
			previousSource,
		))
	}
	extract, ok := goja.AssertFunction(object.Get("extract"))
	if !ok {
		panic(r.vm.NewTypeError("extractor %q must define extract(request)", name))
	}
	priority := 0
	if value := object.Get("priority"); !isNullish(value) {
		priority = int(value.ToInteger())
	}
	matcher := matchSpec{}
	if value := object.Get("match"); !isNullish(value) {
		matchObject := value.ToObject(r.vm)
		matcher.hosts = objectStringList(r.vm, matchObject, "hosts")
		matcher.methods = objectStringList(r.vm, matchObject, "methods")
		matcher.paths = objectStringList(r.vm, matchObject, "paths")
	}
	normalizeMatchPatterns(r.vm, &matcher)

	r.registrations = append(r.registrations, extractorRegistration{
		name:           name,
		credentialType: credentialType,
		priority:       priority,
		match:          matcher,
		extract:        extract,
		source:         r.source,
		order:          r.nextOrder,
	})
	r.names[name] = r.source
	r.nextOrder++
	return goja.Undefined()
}

func (r *extractorRuntime) extractRequest(ctx context.Context, request provider.ExtractionRequest) (string, error) {
	extractorContext, cancel := context.WithTimeout(ctx, extractorExecutionTimeout)
	defer cancel()
	r.callContext = extractorContext

	var token string
	err := r.runWithContext(extractorContext, func() error {
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
			value, callErr := registration.extract(
				goja.Undefined(),
				r.vm.ToValue(requestValue),
			)
			if callErr != nil {
				return fmt.Errorf("extractor %q failed: %w", registration.name, callErr)
			}
			if isNullish(value) {
				continue
			}
			exported, ok := value.Export().(string)
			if !ok {
				return fmt.Errorf("extractor %q must return a token string or null", registration.name)
			}
			exported = strings.TrimSpace(exported)
			if exported == "" {
				continue
			}
			if len(exported) > maxExtractedTokenBytes {
				return fmt.Errorf("extractor %q returned a token larger than %d bytes", registration.name, maxExtractedTokenBytes)
			}
			token = exported
			return nil
		}
		return nil
	})
	return token, err
}

func (r *extractorRuntime) decodeBase64(value string) string {
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil {
		panic(r.vm.NewTypeError("$base64.decode received invalid base64"))
	}
	return string(decoded)
}

func (r *extractorRuntime) runWithContext(ctx context.Context, run func() error) error {
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

func (r extractorRegistration) matches(request provider.ExtractionRequest) bool {
	return matchesRequest(
		r.credentialType,
		r.match,
		request.CredentialType,
		request.Host,
		request.Method,
		request.Path,
	)
}
