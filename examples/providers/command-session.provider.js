registerCredentialProvider({
  name: "example-command-session",
  credentialType: "command_session",
  cache: "credential",

  match: {
    hosts: ["api.service.example"],
    methods: ["GET", "POST"],
    paths: ["/v1/**"],
  },

  validate(config) {
    if (!config.command || config.command[0] !== "/") {
      throw new Error("command must be an absolute path");
    }
    if (!config.audience) throw new Error("audience is required");
    if (!config.access_token) throw new Error("access_token is required");
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
