{
  description = "agent-creds sandbox image";

  inputs = {
    # Pin to 24.11 (glibc 2.40). nixos-unstable ships glibc 2.42+ which
    # broke isatty()/ttyname() under gVisor (TCGETS2 not implemented).
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        # Claude Code: native binary fetched directly from Anthropic's CDN.
        # No node.js dependency — standalone Bun-compiled binary.
        # To bump: update version, fetch new manifest, update hashes.
        #   curl -s https://storage.googleapis.com/claude-code-dist-86c565f3-f756-42ad-8dfa-d59b1c096819/claude-code-releases/latest
        #   curl -s https://storage.googleapis.com/claude-code-dist-86c565f3-f756-42ad-8dfa-d59b1c096819/claude-code-releases/VERSION/manifest.json
        # Ref: https://github.com/sadjow/claude-code-nix
        claudeCodeOverlay = final: prev: let
          version = "2.1.52";
          gcs = "https://storage.googleapis.com/claude-code-dist-86c565f3-f756-42ad-8dfa-d59b1c096819/claude-code-releases";
          platforms = {
            "x86_64-linux"  = { platform = "linux-x64";  hash = "sha256-cMH5iBt8CRxJ82lclMOB2cygrwlLy8mcufRj5E2Xzpw="; };
            "aarch64-linux" = { platform = "linux-arm64"; hash = "sha256-r+CBmQk2VQqY7caAhg5vFs2frTAPtTtKsnxwcccJaPI="; };
          };
          meta = platforms.${system} or (throw "claude-code: unsupported system ${system}");
        in {
          claude-code = prev.stdenv.mkDerivation {
            pname = "claude-code";
            inherit version;
            src = prev.fetchurl {
              url = "${gcs}/${version}/${meta.platform}/claude";
              hash = meta.hash;
            };
            dontUnpack = true;
            # The native binary is Bun-compiled; stripping corrupts its trailer.
            dontStrip = true;
            nativeBuildInputs = [ prev.makeBinaryWrapper prev.autoPatchelfHook ];
            buildInputs = [ prev.stdenv.cc.cc.lib ];
            installPhase = ''
              runHook preInstall
              mkdir -p $out/bin
              install -m755 $src $out/bin/.claude-unwrapped
              # Wrap with auto-update disabled and runtime deps on PATH.
              # No bubblewrap — gVisor is the sandbox.
              makeBinaryWrapper $out/bin/.claude-unwrapped $out/bin/claude \
                --set DISABLE_AUTOUPDATER 1 \
                --set DISABLE_INSTALLATION_CHECKS 1 \
                --set USE_BUILTIN_RIPGREP 0 \
                --prefix PATH : ${prev.lib.makeBinPath [ prev.procps prev.ripgrep prev.socat ]}
              runHook postInstall
            '';
          };
        };

        pkgs = import nixpkgs {
          inherit system;
          overlays = [ claudeCodeOverlay ];
        };

        # Base packages always included
        basePackages = with pkgs; [
          bashInteractive
          bash-completion  # tab completion framework
          coreutils
          findutils
          gnugrep
          gnused
          gawk
          gnutar
          gzip
          less             # pager (used by git log, man, etc.)
          which
          ncurses          # reset, tput, tset
          inetutils        # hostname, ping, traceroute
          procps           # ps, top, kill, pgrep, pkill, watch
          openssh          # ssh client (scp, ssh-keygen)
          dropbear         # lightweight SSH server — runs as devuser (no root needed)
          s6               # process supervisor (PID 1, replaces sleep infinity)
          execline         # s6 scripting language for service run scripts
          sudo             # devuser can sudo inside sessions (needs setuid set in entrypoint)
          linux-pam        # PAM modules for sudo (pam_permit)
          cacert           # CA certificates
          # Always-present dev utilities (ubuntu parity)
          curl
          wget
          git
          gnumake
          socat
          # Modern shell UX
          starship         # smart prompt: git status, language versions, exit codes
          zoxide           # smart cd: z <fuzzy-dir> jumps to frecent dirs
          direnv           # auto-loads .envrc per project directory
        ];

        # Plugin packages (from generated/packages.nix if exists, otherwise defaults)
        pluginPackages =
          if builtins.pathExists ./generated/packages.nix
          then import ./generated/packages.nix { inherit pkgs; }
          else with pkgs; [
            # Default fallback packages
            python311
            python311Packages.pip
            nodejs_20
            go
            rustup
            ripgrep
            fd
            bat
            eza
            fzf
            jq
            httpie
            tree
            unzip
            neovim
            gcc
            gnumake
            curl
            wget
            git
            cacert
            socat
            dnsutils
            file
          ];

        allPackages = basePackages ++ pluginPackages;

        # --- sandbox-base: thin Docker image, no Nix packages ---
        # Only busybox (for /bin/sh), user setup, scripts, config placeholders.
        # All real packages come from sandbox-env mounted at /nix at runtime.
        sandboxBase = pkgs.dockerTools.buildLayeredImage {
          name = "sandbox-base";
          tag = "latest";

          enableFakechroot = true;
          fakeRootCommands = ''
            # Install busybox as a REAL binary, not a Nix store symlink.
            # /nix gets mounted over at runtime with the host Nix store,
            # so anything that symlinks into /nix/store/ would break.
            # fakeRootCommands writes directly to the image filesystem.
            cp ${pkgs.busybox}/bin/busybox /bin/busybox
            chmod +x /bin/busybox
            for cmd in $(${pkgs.busybox}/bin/busybox --list); do
              ln -sf busybox "/bin/$cmd"
            done

            # Copy entrypoint (must survive /nix mount)
            cp ${./claude-dev/entrypoint.sh} /entrypoint.sh
            chmod +x /entrypoint.sh

            # Copy helper scripts
            mkdir -p /usr/local/bin
            cp ${./claude-dev/open-browser} /usr/local/bin/open-browser
            chmod +x /usr/local/bin/open-browser

            # readline config
            cp ${./claude-dev/inputrc} /etc/inputrc

            # Sudoers drop-in
            mkdir -p /etc/sudoers.d
            printf 'devuser ALL=(ALL) NOPASSWD: ALL\n' > /etc/sudoers.d/devuser
            chmod 440 /etc/sudoers.d/devuser

            # Initialize shadow database with root only
            # Use /bin/bash as shell — entrypoint creates symlink to $SANDBOX_ENV/bin/bash
            printf 'root:x:0:0:root:/root:/bin/bash\n' > /etc/passwd
            printf 'root:!:19000::::::\n' > /etc/shadow
            printf 'root:x:0:\n' > /etc/group
            printf 'root::::\n' > /etc/gshadow
            chmod 640 /etc/shadow /etc/gshadow

            # Create devuser via shadow suite (handles passwd/shadow/group correctly)
            ${pkgs.shadow}/bin/groupadd -g 1000 devuser
            ${pkgs.shadow}/bin/useradd \
              -u 1000 -g devuser \
              -d /home/devuser \
              -s /bin/bash \
              -M devuser

            # Home directory with devuser ownership
            mkdir -p /home/devuser
            cp ${./claude-dev/bashrc} /home/devuser/.bashrc
            chmod 644 /home/devuser/.bashrc
            # SSH login shells source .profile, not .bashrc — bridge the gap
            printf '[ -f ~/.bashrc ] && . ~/.bashrc\n' > /home/devuser/.profile
            chmod 644 /home/devuser/.profile
            chown -R 1000:1000 /home/devuser
          '';

          contents = [
            # Minimal filesystem skeleton. No Nix packages in contents because
            # buildLayeredImage puts them in /nix/store/ which gets mounted over.
            # Everything that needs to survive is placed by fakeRootCommands above.
            (pkgs.runCommand "base-system" {} ''
              mkdir -p $out/etc $out/tmp $out/workspace
              mkdir -p $out/bin $out/sbin $out/usr/local/bin
              chmod 1777 $out/tmp

              # Note: /etc/shells, /etc/pam.d/sudo, /etc/bash_completion are created
              # by entrypoint.sh at runtime from $SANDBOX_ENV paths.

              # Note: Go binaries (aenv, cdp-proxy, tcp-bridge) are added
              # as a Docker layer after the Nix build - see build-nix.sh
            '')
          ];

          config = {
            WorkingDir = "/workspace";
            Env = [
              "HOME=/home/devuser"
              "USER=devuser"
              "TERM=xterm-256color"
              # Trust the agent-creds proxy CA for Node.js (file is mounted at runtime)
              "NODE_EXTRA_CA_CERTS=/etc/ssl/agent-creds-ca.crt"
            ];
            # Root is needed because gVisor doesn't honor setuid bits —
            # dropbear needs root to allocate PTYs via grantpt/pt_chown.
            # SSH sessions still run as devuser (dropbear handles user switching).
            User = "root";
            Entrypoint = [ "/entrypoint.sh" ];
          };
        };

        # --- sandbox-env: all packages merged into one store path ---
        # Mounted from host at /nix, passed via SANDBOX_ENV env var.
        # Fast rebuild when only plugins change — Nix caches unchanged store paths.
        sandboxEnv = pkgs.buildEnv {
          name = "sandbox-env";
          paths = allPackages;
          ignoreCollisions = true;  # multiple packages may provide same file
        };

      in {
        packages = {
          default = sandboxBase;
          sandbox-base = sandboxBase;
          sandbox-env = sandboxEnv;
        };

        # Development shell for working on agent-creds itself
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            go
            docker
          ];
        };
      }
    );
}
