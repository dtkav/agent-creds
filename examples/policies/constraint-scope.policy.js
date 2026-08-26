registerUpstreamPolicy({
  name: "example-constraint-scope",
  policyType: "constraint_scope",

  validate(config) {
    if (!config.namespace) throw new Error("namespace is required");
    if (!config.required_scope) throw new Error("required_scope is required");
  },

  authorize(request, config) {
    if (request.constraints.length === 0) {
      return { allow: false, reason: "scope constraint required" };
    }

    for (const constraint of request.constraints) {
      if (constraint.namespace !== config.namespace) {
        return { allow: false, reason: "unknown constraint namespace" };
      }
      if (!Array.isArray(constraint.body.scopes)) {
        return { allow: false, reason: "scopes must be an array" };
      }
      if (!constraint.body.scopes.includes(config.required_scope)) {
        return { allow: false, reason: "required scope excluded" };
      }
    }

    return true;
  },
});
