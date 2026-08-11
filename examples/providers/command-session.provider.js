registerCredentialType({
  credentialType: "command_session",
  configSchema: {
    $schema: "https://json-schema.org/draft/2020-12/schema",
    type: "object",
    additionalProperties: false,
    required: ["command", "audience", "access_token"],
    properties: {
      command: { type: "string", pattern: "^/" },
      audience: { type: "string", minLength: 1 },
      access_token: { type: "string", minLength: 1 },
    },
  },
});

registerCredentialProvider({
  name: "example-command-session",
  credentialType: "command_session",
  cache: "credential",

  match: {
    hosts: ["api.service.example"],
    methods: ["GET", "POST"],
    paths: ["/v1/**"],
  },

  resolve(_request, config) {
    const output = $exec.run(
      config.command,
      ["session", "--audience", config.audience, "--format", "json"],
      {
        inheritEnv: false,
        env: {
          HOME: "/tmp",
          SERVICE_ACCESS_TOKEN: config.access_token,
        },
      },
    );

    const session = JSON.parse(output);
    if (!session.access_token) {
      throw new Error("credential helper returned no access_token");
    }
    const expiresAt =
      session.expires_at || $jwt.expiresAt(session.access_token);
    if (!expiresAt) {
      throw new Error("credential helper returned no expiry");
    }

    return {
      headers: {
        authorization: "Bearer " + session.access_token,
      },
      expiresAt,
      stop: true,
    };
  },
});
