function githubRequiredString(config, name) {
  var value = config[name];
  if (typeof value !== "string" || value.trim() === "") {
    throw new TypeError(name + " is required");
  }
  return value;
}

registerCredentialExtractor({
  name: "github-client-auth",
  credentialType: "github",
  priority: 100,
  match: { hosts: ["github.com", "api.github.com"] },

  extract: function (request) {
    var authorization = request.headers.authorization;
    if (typeof authorization !== "string") return null;

    var tokenMatch = /^token\s+(.+)$/i.exec(authorization.trim());
    if (tokenMatch) return tokenMatch[1].trim();

    var basicMatch = /^Basic\s+(.+)$/i.exec(authorization.trim());
    if (!basicMatch) return null;
    var decoded = $base64.decode(basicMatch[1]);
    var separator = decoded.indexOf(":");
    if (separator < 0) return null;
    return decoded.slice(separator + 1).trim();
  },
});

registerCredentialProvider({
  name: "github-static-header",
  credentialType: "github",
  priority: 100,
  match: { hosts: ["github.com", "api.github.com"] },

  validate: function (config) {
    githubRequiredString(config, "header");
    githubRequiredString(config, "value");
  },

  resolve: function (_request, config) {
    var headers = {};
    headers[githubRequiredString(config, "header")] =
      githubRequiredString(config, "value");
    return { headers: headers, stop: true };
  },
});
