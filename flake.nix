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
          sudo             # devuser can sudo inside sessions (needs setuid set in build-nix.sh)
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

        # Base sandbox image
        sandboxImage = pkgs.dockerTools.buildLayeredImage {
          name = "sandbox";
          tag = "latest";

          # fakeRootCommands runs after contents are merged, with fakeroot + fakechroot.
          # Use the shadow suite to properly create users/groups (no manual passwd editing).
          # Note: groupadd/useradd print nscd-flush warnings (no nscd in build env) — harmless.
          enableFakechroot = true;
          fakeRootCommands = ''
            # Initialize shadow database with root only
            printf 'root:x:0:0:root:/root:${pkgs.bashInteractive}/bin/bash\n' > /etc/passwd
            printf 'root:!:19000::::::\n' > /etc/shadow
            printf 'root:x:0:\n' > /etc/group
            printf 'root::::\n' > /etc/gshadow
            chmod 640 /etc/shadow /etc/gshadow

            # Create devuser via shadow suite (handles passwd/shadow/group correctly)
            ${pkgs.shadow}/bin/groupadd -g 1000 devuser
            ${pkgs.shadow}/bin/useradd \
              -u 1000 -g devuser \
              -d /home/devuser \
              -s ${pkgs.bashInteractive}/bin/bash \
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

          contents = allPackages ++ [
            # Create filesystem structure and copy scripts
            (pkgs.runCommand "base-system" {} ''
              mkdir -p $out/etc $out/tmp $out/workspace
              mkdir -p $out/usr/local/bin
              chmod 1777 $out/tmp

              # Copy entrypoint
              cp ${./claude-dev/entrypoint.sh} $out/entrypoint.sh
              chmod +x $out/entrypoint.sh

              # Copy open-browser helper
              cp ${./claude-dev/open-browser} $out/usr/local/bin/open-browser
              chmod +x $out/usr/local/bin/open-browser

              # readline config (enables 8-bit input, UTF-8, word movement)
              cp ${./claude-dev/inputrc} $out/etc/inputrc

              # Symlink bash-completion main script to a stable path
              ln -s ${pkgs.bash-completion}/share/bash-completion/bash_completion $out/etc/bash_completion

              # Sudoers drop-in: devuser can run anything without password (dev sandbox).
              # Note: /etc/sudoers itself comes from pkgs.sudo (includes @includedir /etc/sudoers.d).
              # The sudo setuid bit is set in build-nix.sh's Dockerfile layer (Nix store is immutable).
              mkdir -p $out/etc/sudoers.d
              printf 'devuser ALL=(ALL) NOPASSWD: ALL\n' > $out/etc/sudoers.d/devuser
              chmod 440 $out/etc/sudoers.d/devuser

              # PAM config for sudo: pam_permit allows everything (dev sandbox, no real auth needed)
              # Use full Nix store paths since /lib/security/ doesn't exist in this image.
              mkdir -p $out/etc/pam.d
              pamlib="${pkgs.linux-pam}/lib/security"
              printf 'auth     sufficient %s/pam_permit.so\naccount  sufficient %s/pam_permit.so\nsession  sufficient %s/pam_permit.so\n' \
                "$pamlib" "$pamlib" "$pamlib" > $out/etc/pam.d/sudo

              # /etc/shells: dropbear validates user shells against this list.
              # Without it, dropbear rejects logins with "invalid shell".
              printf '%s\n' "${pkgs.bashInteractive}/bin/bash" "/bin/sh" > $out/etc/shells

              # Note: Go binaries (aenv, cdp-proxy, tcp-bridge) are added
              # as a Docker layer after the Nix build - see build-nix.sh
            '')
          ];

          config = {
            WorkingDir = "/workspace";
            Env = [
              "PATH=/usr/local/bin:/bin:/usr/bin:/home/devuser/.local/bin:/home/devuser/.cargo/bin:/home/devuser/go/bin"
              "HOME=/home/devuser"
              "USER=devuser"
              "SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
              "NIX_SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
              "TERM=xterm-256color"
              # Nix puts terminfo in the store path; set dirs so ncurses programs find it
              "TERMINFO_DIRS=${pkgs.ncurses}/share/terminfo:/usr/share/terminfo"
              # bash-completion finds completion scripts by searching XDG_DATA_DIRS for
              # share/bash-completion/completions/. Include all package share dirs.
              "XDG_DATA_DIRS=${pkgs.lib.makeSearchPath "share" allPackages}:/usr/share:/share"
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

      in {
        packages = {
          default = sandboxImage;
          sandbox = sandboxImage;
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
