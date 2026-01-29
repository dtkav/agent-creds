package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// ContainerInfo holds details about a container.
type ContainerInfo struct {
	ID     string
	Name   string
	Status string // "running", "exited", etc.
}

// Instance represents a running adev instance.
type Instance struct {
	Name       string
	Slug       string
	Status     string // "running", "partial", "stopped"
	Sandbox    *ContainerInfo
	Envoy      *ContainerInfo
	Net        *ContainerInfo
	HasNetwork bool
}

// InstanceManager handles instance detection and lifecycle.
type InstanceManager struct {
	scriptDir string
}

// NewInstanceManager creates a new instance manager.
func NewInstanceManager(scriptDir string) *InstanceManager {
	return &InstanceManager{scriptDir: scriptDir}
}

// ListInstances finds all adev instances by looking for adev-*-sandbox containers.
func (m *InstanceManager) ListInstances() []Instance {
	// Get all containers with adev- prefix
	out, err := exec.Command("docker", "ps", "-a",
		"--filter", "name=adev-",
		"--format", "{{.Names}}\t{{.Status}}").Output()
	if err != nil {
		return nil
	}

	// Group containers by slug
	instances := make(map[string]*Instance)

	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "\t", 2)
		if len(parts) != 2 {
			continue
		}
		name := parts[0]
		status := parts[1]

		// Parse container name: adev-{slug}-{type}
		if !strings.HasPrefix(name, "adev-") {
			continue
		}
		rest := strings.TrimPrefix(name, "adev-")

		var slug, containerType string
		if strings.HasSuffix(rest, "-sandbox") {
			slug = strings.TrimSuffix(rest, "-sandbox")
			containerType = "sandbox"
		} else if strings.HasSuffix(rest, "-envoy") {
			slug = strings.TrimSuffix(rest, "-envoy")
			containerType = "envoy"
		} else if strings.HasSuffix(rest, "-net") {
			slug = strings.TrimSuffix(rest, "-net")
			containerType = "net"
		} else {
			continue
		}

		if slug == "" {
			continue
		}

		inst, ok := instances[slug]
		if !ok {
			inst = &Instance{
				Name: slug, // Use slug as name initially
				Slug: slug,
			}
			instances[slug] = inst
		}

		isRunning := strings.HasPrefix(status, "Up")
		info := &ContainerInfo{
			Name:   name,
			Status: status,
		}
		if isRunning {
			info.Status = "running"
		} else {
			info.Status = "exited"
		}

		switch containerType {
		case "sandbox":
			inst.Sandbox = info
		case "envoy":
			inst.Envoy = info
		case "net":
			inst.Net = info
		}
	}

	// Check for networks and determine overall status
	for slug, inst := range instances {
		networkName := "adev-" + slug
		if err := exec.Command("docker", "network", "inspect", networkName).Run(); err == nil {
			inst.HasNetwork = true
		}

		// Determine status
		sandboxRunning := inst.Sandbox != nil && inst.Sandbox.Status == "running"
		envoyRunning := inst.Envoy != nil && inst.Envoy.Status == "running"
		netRunning := inst.Net != nil && inst.Net.Status == "running"

		if sandboxRunning && envoyRunning && netRunning {
			inst.Status = "running"
		} else if sandboxRunning || envoyRunning || netRunning {
			inst.Status = "partial"
		} else {
			inst.Status = "stopped"
		}
	}

	// Convert to slice
	var result []Instance
	for _, inst := range instances {
		result = append(result, *inst)
	}

	return result
}

// GetInstance returns a specific instance by slug.
func (m *InstanceManager) GetInstance(slug string) *Instance {
	for _, inst := range m.ListInstances() {
		if inst.Slug == slug {
			return &inst
		}
	}
	return nil
}

// CanAttach returns true if the instance has a running sandbox.
func (m *InstanceManager) CanAttach(inst *Instance) bool {
	return inst != nil && inst.Sandbox != nil && inst.Sandbox.Status == "running"
}

// AttachToInstance attaches to a running sandbox container.
func (m *InstanceManager) AttachToInstance(inst *Instance) error {
	if inst.Sandbox == nil {
		return fmt.Errorf("no sandbox container found")
	}

	cmd := exec.Command("docker", "exec", "-it", inst.Sandbox.Name, "/bin/bash")
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// CleanupInstance removes all containers and network for an instance.
func (m *InstanceManager) CleanupInstance(inst *Instance) error {
	sandboxName := "adev-" + inst.Slug + "-sandbox"
	netName := "adev-" + inst.Slug + "-net"
	envoyName := "adev-" + inst.Slug + "-envoy"
	networkName := "adev-" + inst.Slug

	// Remove containers
	exec.Command("docker", "rm", "-f", sandboxName).Run()
	exec.Command("docker", "rm", "-f", netName).Run()
	exec.Command("docker", "rm", "-f", envoyName).Run()

	// Remove network
	exec.Command("docker", "network", "rm", networkName).Run()

	return nil
}
