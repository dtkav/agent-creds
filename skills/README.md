# Skill registrations

Each `*.toml` file registers one named Agent Skill. The filename and `name`
must match. Registrations contain a literal Git `repo`, a branch, tag, or
revision `ref`, an optional monorepo `path`, and optional `nix` packages. Use a
full commit revision when an exact source pin is required.

Projects enable registered skills with `[sandbox] skills = ["name"]`. Global
and project registrations can override files in this directory by name.
