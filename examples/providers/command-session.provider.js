registerCredentialType({
  credentialType: "command_session",
  configSchema: {
    $schema: "https://json-schema.org/draft/2020-12/schema",
    type: "object",
    additionalProperties: false,
    required: [
      "command",
      "token_url",
      "client_id",
      "audience",
      "allowed_audiences",
      "client_secret",
    ],
    properties: {
      command: { type: "string", pattern: "^/" },
      token_url: { type: "string", pattern: "^https://" },
      client_id: { $ref: "#/$defs/nonEmptyString" },
      audience: { $ref: "#/$defs/nonEmptyString" },
      allowed_audiences: {
        type: "array",
        minItems: 1,
        uniqueItems: true,
        items: { $ref: "#/$defs/nonEmptyString" },
      },
      client_secret: { $ref: "#/$defs/nonEmptyString" },
      session_header: {
        type: "string",
        minLength: 1,
        default: "authorization",
      },
    },
    $defs: {
      nonEmptyString: { type: "string", minLength: 1 },
    },
  },

  validate(config) {
    if (!config.allowed_audiences.includes(config.audience)) {
      throw new Error("audience must appear in allowed_audiences");
    }
  },
});

registerCredentialExtractor({
  name: "example-command-session-client-auth",
  credentialType: "command_session",
  priority: 100,

  match: {
    hosts: ["api.service.example"],
    methods: ["GET", "POST"],
    paths: ["/v1/**"],
  },

  extract(request) {
    const framing = request.headers["x-service-authorization"] || "";
    const match = /^Session\s+(.+)$/i.exec(framing.trim());
    if (!match) return null;

    const capability = $base64.decode(match[1]).trim();
    $log.debug("extracted command_session client framing");
    return capability || null;
  },
});

registerCredentialProvider({
  name: "example-command-session",
  credentialType: "command_session",
  priority: 100,
  cache: "credential",

  match: {
    hosts: ["api.service.example"],
    methods: ["GET", "POST"],
    paths: ["/v1/**"],
  },

  validate(config) {
    const header = (config.session_header || "authorization").toLowerCase();
    if (header.startsWith("x-agent-creds-")) {
      throw new Error("session_header must not use the verifier namespace");
    }
  },

  resolve(request, config) {
    $log.debug(
      "issuing " + request.credential + " session for " + config.audience,
    );

    const assertion = $exec.run(
      config.command,
      ["assertion", "--audience", config.audience],
      {
        inheritEnv: false,
        env: {
          HOME: "/tmp",
          SERVICE_CLIENT_SECRET: config.client_secret,
        },
      },
    );
    if (!assertion) {
      throw new Error("credential helper returned no assertion");
    }

    const response = $http.request({
      method: "POST",
      url: config.token_url,
      headers: {
        authorization:
          "Basic " +
          $base64.encode(config.client_id + ":" + config.client_secret),
        "content-type": "application/json",
      },
      body: JSON.stringify({
        audience: config.audience,
        assertion,
      }),
    });
    if (response.status !== 200) {
      throw new Error("session exchange returned HTTP " + response.status);
    }

    const session = JSON.parse(response.body);
    if (!session.access_token) {
      throw new Error("session exchange returned no access_token");
    }
    const expiresAt =
      session.expires_at || $jwt.expiresAt(session.access_token);
    if (!expiresAt) {
      throw new Error("session exchange returned no expiry");
    }

    const header = config.session_header || "authorization";
    return {
      headers: {
        [header]: "Bearer " + session.access_token,
      },
      expiresAt,
      stop: true,
    };
  },
});
