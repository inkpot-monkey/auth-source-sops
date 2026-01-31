{
  description = "auth-source-sops - Integrate auth-source with sops";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
    nix-emacs-ci = {
      url = "github:purcell/nix-emacs-ci";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    inputs@{ self
    , nixpkgs
    , flake-parts
    , nix-emacs-ci
    , ...
    }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      perSystem =
        { config
        , self'
        , inputs'
        , pkgs
        , system
        , ...
        }:
        let
          # Emacs versions to test
          emacsVersions = {
            emacs-28-1 = nix-emacs-ci.packages.${system}.emacs-28-1;
            emacs-29-1 = nix-emacs-ci.packages.${system}.emacs-29-1;
            emacs-29-4 = nix-emacs-ci.packages.${system}.emacs-29-4;
            emacs-30-1 = nix-emacs-ci.packages.${system}.emacs-30-1;
            emacs-30-2 = nix-emacs-ci.packages.${system}.emacs-30-2;
            emacs-snapshot = nix-emacs-ci.packages.${system}.emacs-snapshot;
          };

          # Create a hermetic Emacs environment with dependencies for a specific version
          mkTestEnv =
            name: emacs:
            (pkgs.emacsPackagesFor emacs).withPackages (
              epkgs: [
                epkgs.yaml
                epkgs.package-lint
              ]
            );

          # Common dependencies (non-Emacs)
          testDeps = with pkgs; [
            sops
            ssh-to-age
            yq-go
            findutils
          ];

          # Unified test script for both local dev and CI
          testScript = ''
            set -euo pipefail
            export PATH="${pkgs.lib.makeBinPath testDeps}:$PATH"

            echo "--- Checking package headers (package-lint) ---"
            emacs -Q -batch -L . -l package-lint -f package-lint-batch-and-exit auth-source-sops.el

            echo "--- Checking documentation (checkdoc) ---"
            emacs -Q -batch -L . --eval "(checkdoc-file \"auth-source-sops.el\")"

            echo "--- Byte-compiling ---"
            emacs -Q -batch -L . -f batch-byte-compile auth-source-sops.el

            echo "--- Running unit tests ---"
            emacs -Q -batch -L . -L tests \
              -l tests/unit_tests.el \
              -l tests/ssh_to_age_test.el \
              -f ert-run-tests-batch-and-exit

            echo "--- Running integration tests ---"
            export SOPS_TEST_REAL_YAML=1
            emacs -Q -batch -L . -L tests \
              -l tests/integration_tests.el \
              -f ert-run-tests-batch-and-exit
          '';

          # Create check derivations
          makeCheck =
            name: emacs:
            let
              testEnv = mkTestEnv name emacs;
            in
            pkgs.runCommand "test-${name}"
              {
                nativeBuildInputs = [ testEnv ] ++ testDeps;
                src = ./.;
              }
              ''
                cp -r $src/* .
                chmod -R +w .
                ${testScript}
                touch $out
              '';
        in
        {
          # Default package (byte-compiled)
          packages.default =
            let
              emacs = emacsVersions.emacs-30-2;
            in
            pkgs.runCommand "auth-source-sops"
              {
                src = ./.;
                nativeBuildInputs = [ emacs ];
              }
              ''
                mkdir -p $out/share/emacs/site-lisp
                cp $src/auth-source-sops.el $out/share/emacs/site-lisp/
                ${emacs}/bin/emacs -Q -batch \
                  -L $out/share/emacs/site-lisp \
                  -f batch-byte-compile $out/share/emacs/site-lisp/auth-source-sops.el
              '';

          # Development shells
          devShells =
            pkgs.lib.mapAttrs
              (
                name: emacs:
                  let
                    testEnv = mkTestEnv name emacs;
                  in
                  pkgs.mkShell {
                    buildInputs = [ testEnv ] ++ testDeps;
                    shellHook = ''
                      echo "Development shell with ${name}"
                      alias run-tests='${testScript}'
                      echo "Run 'run-tests' to execute all tests and checks"
                    '';
                  }
              )
              emacsVersions
            // {
              default =
                let
                  name = "emacs-30-2";
                  emacs = emacsVersions.${name};
                  testEnv = mkTestEnv name emacs;
                in
                pkgs.mkShell {
                  buildInputs = [ testEnv ] ++ testDeps;
                  shellHook = ''
                    echo "Default development shell (${name})"
                    alias run-tests='${testScript}'
                    echo "Run 'run-tests' to execute all tests and checks"
                  '';
                };
            };

          # Checks
          checks = (pkgs.lib.mapAttrs makeCheck emacsVersions) // {
            nixpkgs-fmt = pkgs.runCommand "nixpkgs-fmt-check"
              {
                nativeBuildInputs = [ pkgs.nixpkgs-fmt ];
                src = ./.;
              }
              ''
                nixpkgs-fmt --check $src
                touch $out
              '';
          };
        };

    };
}
