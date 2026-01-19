package macaroon

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/superfly/macaroon"
)

// Caveat type constants (using user-registerable range: 1<<32 to 1<<48-1)
const (
	CavAPIHost   macaroon.CaveatType = 1<<32 + 1
	CavAPIMethod macaroon.CaveatType = 1<<32 + 2
	CavAPIPath   macaroon.CaveatType = 1<<32 + 3
)

func init() {
	macaroon.RegisterCaveatType(&HostCaveat{})
	macaroon.RegisterCaveatType(&MethodCaveat{})
	macaroon.RegisterCaveatType(&PathCaveat{})
}

// HostCaveat restricts token to specific API hosts
type HostCaveat struct {
	Hosts []string `json:"hosts"`
}

func (c *HostCaveat) CaveatType() macaroon.CaveatType { return CavAPIHost }
func (c *HostCaveat) Name() string                    { return "APIHost" }

func (c *HostCaveat) Prohibits(f macaroon.Access) error {
	a, ok := f.(*Access)
	if !ok {
		return fmt.Errorf("invalid access type")
	}

	host := a.GetHost()
	for _, allowed := range c.Hosts {
		if host == allowed {
			return nil
		}
	}

	return fmt.Errorf("host %q not in allowed list %v", host, c.Hosts)
}

// MethodCaveat restricts token to specific HTTP methods
type MethodCaveat struct {
	Methods []string `json:"methods"`
}

func (c *MethodCaveat) CaveatType() macaroon.CaveatType { return CavAPIMethod }
func (c *MethodCaveat) Name() string                    { return "APIMethod" }

func (c *MethodCaveat) Prohibits(f macaroon.Access) error {
	a, ok := f.(*Access)
	if !ok {
		return fmt.Errorf("invalid access type")
	}

	method := strings.ToUpper(a.GetMethod())
	for _, allowed := range c.Methods {
		if method == strings.ToUpper(allowed) {
			return nil
		}
	}

	return fmt.Errorf("method %q not in allowed list %v", method, c.Methods)
}

// PathCaveat restricts token to specific endpoint path patterns
type PathCaveat struct {
	// Patterns are glob-style patterns:
	// - /v1/customers/* matches /v1/customers/cus_123
	// - /v1/** matches any path under /v1/
	Patterns []string `json:"patterns"`
}

func (c *PathCaveat) CaveatType() macaroon.CaveatType { return CavAPIPath }
func (c *PathCaveat) Name() string                    { return "APIPath" }

func (c *PathCaveat) Prohibits(f macaroon.Access) error {
	a, ok := f.(*Access)
	if !ok {
		return fmt.Errorf("invalid access type")
	}

	path := a.GetPath()
	for _, pattern := range c.Patterns {
		if matchPath(pattern, path) {
			return nil
		}
	}

	return fmt.Errorf("path %q does not match allowed patterns %v", path, c.Patterns)
}

// matchPath matches a path against a glob-style pattern
// * matches a single path segment (no slashes)
// ** matches zero or more path segments (including empty)
func matchPath(pattern, path string) bool {
	// Convert glob pattern to regex
	// Escape regex special chars except * which we handle specially
	regexPattern := regexp.QuoteMeta(pattern)

	// Replace /\*\* with optional slash + any characters (matches /foo/**, /foo, /foo/, /foo/bar)
	regexPattern = strings.ReplaceAll(regexPattern, `/\*\*`, `(?:/.*)?`)

	// Replace remaining \*\* (not preceded by /) with regex for "any characters"
	regexPattern = strings.ReplaceAll(regexPattern, `\*\*`, `.*`)

	// Replace remaining \* with regex for "single segment" (no slashes)
	regexPattern = strings.ReplaceAll(regexPattern, `\*`, `[^/]*`)

	// Anchor the pattern
	regexPattern = "^" + regexPattern + "$"

	matched, _ := regexp.MatchString(regexPattern, path)
	return matched
}
