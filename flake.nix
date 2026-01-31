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
    inputs@{
      self,
      nixpkgs,
      flake-parts,
      nix-emacs-ci,
      ...
    }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      perSystem =
        {
          config,
          self',
          inputs',
          pkgs,
          system,
          ...
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

          # Common dependencies for testing
          # We include the real yaml package from nixpkgs
          testDeps = with pkgs; [
            sops
            ssh-to-age
            emacsPackages.yaml
          ];

          # Build a test runner for a specific Emacs version
          makeTestRunner =
            name: emacs:
            pkgs.writeShellScriptBin "run-tests-${name}" ''
              export PATH="${pkgs.lib.makeBinPath testDeps}:$PATH"

              # Find the load path for yaml package dynamically if possible, or use the calculated one
              YAML_DIR=$(find ${pkgs.emacsPackages.yaml} -name "yaml.el" -exec dirname {} \;)

              echo "Running tests with ${name}..."
              ${emacs}/bin/emacs -Q -batch \
                -L "$YAML_DIR" \
                -L ${./.} -L ${./tests} \
                -l ${./tests/unit_tests.el} \
                -l ${./tests/ssh_to_age_test.el} \
                -f ert-run-tests-batch-and-exit

              echo "Running protocol tests with ${name}..."
              export SOPS_TEST_REAL_YAML=1
              ${emacs}/bin/emacs -Q -batch \
                -L "$YAML_DIR" \
                -L ${./.} -L ${./tests} \
                -l ${./tests/integration_tests.el} \
                -f ert-run-tests-batch-and-exit
            '';

          # Create check derivations for each Emacs version
          makeCheck =
            name: emacs:
            pkgs.runCommand "test-${name}"
              {
                nativeBuildInputs = [
                  emacs
                ]
                ++ testDeps
                ++ [
                  pkgs.yq-go
                  pkgs.findutils
                ];
                src = ./.;
              }
              ''
                cp -r $src/* .
                chmod -R +w .

                # Find the load path for yaml package
                YAML_DIR=$(find ${pkgs.emacsPackages.yaml} -name "yaml.el" -exec dirname {} \;)

                echo "Running unit tests with ${name}..."
                ${emacs}/bin/emacs -Q -batch \
                  -L "$YAML_DIR" \
                  -L . -L tests \
                  -l tests/unit_tests.el \
                  -l tests/ssh_to_age_test.el \
                  -f ert-run-tests-batch-and-exit

                echo "Running protocol tests with ${name}..."
                export SOPS_TEST_REAL_YAML=1
                ${emacs}/bin/emacs -Q -batch \
                  -L "$YAML_DIR" \
                  -L . -L tests \
                  -l tests/integration_tests.el \
                  -f ert-run-tests-batch-and-exit

                touch $out
              '';
        in
        {
          # Packages (mainly for byte-compilation)
          packages.default =
            pkgs.runCommand "auth-source-sops"
              {
                src = ./.;
                nativeBuildInputs = [ emacsVersions.emacs-30-2 ];
              }
              ''
                mkdir -p $out/share/emacs/site-lisp
                cp $src/auth-source-sops.el $out/share/emacs/site-lisp/
                ${emacsVersions.emacs-30-2}/bin/emacs -Q -batch \
                  -L $out/share/emacs/site-lisp \
                  -f batch-byte-compile $out/share/emacs/site-lisp/auth-source-sops.el
              '';

          # Development shells for each Emacs version
          devShells =
            pkgs.lib.mapAttrs (
              name: emacs:
              pkgs.mkShell {
                buildInputs = [
                  emacs
                ]
                ++ testDeps
                ++ [
                  (makeTestRunner name emacs)
                ];
                shellHook = ''
                  echo "Development shell with ${name}"
                  echo "Run 'run-tests-${name}' to execute tests"
                '';
              }
            ) emacsVersions
            // {
              default = pkgs.mkShell {
                buildInputs = [
                  emacsVersions.emacs-30-2
                ]
                ++ testDeps
                ++ [
                  (makeTestRunner "emacs-30-2" emacsVersions.emacs-30-2)
                ];
                shellHook = ''
                  echo "Default development shell (Emacs 30.2)"
                  echo "Run 'run-tests-emacs-30-2' to execute tests"
                '';
              };
            };

          # Checks for CI - runs tests for each Emacs version
          checks = pkgs.lib.mapAttrs makeCheck emacsVersions;
        };
    };
}
