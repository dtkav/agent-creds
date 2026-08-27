package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"

	vaultcfg "vault/vault"
)

const (
	controlReloadPath         = "/v1/config/reload"
	controlCredentialsPath    = "/v1/credentials"
	controlCredentialInfoPath = "/v1/credentials/info"
	maxReloadConfigBytes      = 4 << 20
)

type credentialEndpointInfo struct {
	Methods     []string `json:"methods"`
	Paths       []string `json:"paths"`
	Description string   `json:"description,omitempty"`
}

type credentialInfoResponse struct {
	Type        string                     `json:"type"`
	EnvVars     []string                   `json:"env_vars,omitempty"`
	Hosts       []string                   `json:"hosts,omitempty"`
	Endpoints   []credentialEndpointInfo   `json:"endpoints,omitempty"`
	Constraints []credentialConstraintInfo `json:"constraints,omitempty"`
	Caveat      *credentialCaveatInfo      `json:"caveat,omitempty"`
}

type credentialCaveatInfo struct {
	Namespace string         `json:"namespace"`
	Schema    map[string]any `json:"schema"`
}

type credentialConstraintInfo struct {
	Namespace  string         `json:"namespace"`
	Constraint map[string]any `json:"constraint"`
}

func newControlHandler(store *runtimeStore) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		snapshot := store.Load()
		if snapshot == nil {
			writeControlError(w, http.StatusServiceUnavailable, "vault runtime is not initialized")
			return
		}
		writeControlJSON(w, http.StatusOK, map[string]any{
			"status":     "ok",
			"generation": snapshot.generation,
		})
	})
	mux.HandleFunc("POST "+controlReloadPath, func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxReloadConfigBytes))
		if err != nil {
			writeControlError(w, http.StatusBadRequest, "reading vault config")
			return
		}
		config, err := vaultcfg.LoadBytes(body)
		if err != nil {
			writeControlError(w, http.StatusBadRequest, err.Error())
			return
		}
		warnings, err := store.Reload(config)
		if err != nil {
			writeControlError(w, http.StatusBadRequest, err.Error())
			return
		}
		snapshot := store.Load()
		writeControlJSON(w, http.StatusOK, map[string]any{
			"status":      "reloaded",
			"generation":  snapshot.generation,
			"credentials": len(snapshot.credentials),
			"warnings":    warnings,
		})
	})
	mux.HandleFunc("GET "+controlCredentialsPath, func(w http.ResponseWriter, _ *http.Request) {
		snapshot := store.Load()
		if snapshot == nil || snapshot.config == nil {
			writeControlError(w, http.StatusServiceUnavailable, "vault runtime is not initialized")
			return
		}
		paths := make([]string, 0, len(snapshot.config.Credentials))
		for path := range snapshot.config.Credentials {
			paths = append(paths, "/"+strings.TrimPrefix(path, "/"))
		}
		sort.Strings(paths)
		writeControlJSON(w, http.StatusOK, map[string]any{"paths": paths})
	})
	mux.HandleFunc("GET "+controlCredentialInfoPath, func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(strings.TrimSpace(r.URL.Query().Get("path")), "/")
		if path == "" {
			writeControlError(w, http.StatusBadRequest, "credential path is required")
			return
		}
		snapshot := store.Load()
		if snapshot == nil || snapshot.config == nil {
			writeControlError(w, http.StatusServiceUnavailable, "vault runtime is not initialized")
			return
		}
		credential, ok := snapshot.config.Credentials[path]
		if !ok {
			writeControlError(w, http.StatusNotFound, fmt.Sprintf("unknown credential path: /%s", path))
			return
		}
		info, err := credentialInfo(r.Context(), credential, snapshot.credentials[path])
		if err != nil {
			writeControlError(w, http.StatusInternalServerError, fmt.Sprintf("deriving credential capability: %v", err))
			return
		}
		writeControlJSON(w, http.StatusOK, info)
	})
	return mux
}

func credentialInfo(ctx context.Context, credential vaultcfg.CredentialConfig, configured configuredCredential) (credentialInfoResponse, error) {
	response := credentialInfoResponse{Type: credential.Type}
	for _, name := range []string{credential.Env, credential.EnvUser, credential.EnvPass} {
		if name != "" {
			response.EnvVars = append(response.EnvVars, name)
		}
	}
	if credential.Capabilities != nil {
		response.Hosts = append([]string(nil), credential.Capabilities.Hosts...)
		for _, endpoint := range credential.Capabilities.Endpoints {
			response.Endpoints = append(response.Endpoints, credentialEndpointInfo{
				Methods:     append([]string(nil), endpoint.Methods...),
				Paths:       append([]string(nil), endpoint.Paths...),
				Description: endpoint.Description,
			})
		}
	}
	if configured.macaroon != nil {
		constraint, err := configured.macaroon.Constraint(ctx)
		if err != nil {
			return credentialInfoResponse{}, err
		}
		if constraint != nil {
			response.Constraints = append(response.Constraints, credentialConstraintInfo{
				Namespace:  constraint.Namespace,
				Constraint: constraint.Body,
			})
		}
		if metadata, ok := configured.macaroon.(credentialCaveatMetadata); ok {
			schema, err := metadata.ConstraintSchema(ctx)
			if err != nil {
				return credentialInfoResponse{}, err
			}
			if schema != nil {
				response.Caveat = &credentialCaveatInfo{
					Namespace: configured.macaroon.Namespace(),
					Schema:    schema,
				}
			}
		}
	}
	return response, nil
}

func writeControlError(w http.ResponseWriter, status int, message string) {
	writeControlJSON(w, status, map[string]string{"error": message})
}

func writeControlJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
