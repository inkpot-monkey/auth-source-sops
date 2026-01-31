{
  description = "auth-source-sops - Integrate auth-source with sops";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    nix-emacs-ci = {
      url = "github:purcell/nix-emacs-ci";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, nix-emacs-ci }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        
        # Emacs versions to test
        emacsVersions = {
          emacs-28-1 = nix-emacs-ci.packages.${system}.emacs-28-1;
          emacs-29-1 = nix-emacs-ci.packages.${system}.emacs-29-1;
          emacs-29-4 = nix-emacs-ci.packages.${system}.emacs-29-4;
          emacs-snapshot = nix-emacs-ci.packages.${system}.emacs-snapshot;
        };

        # Common dependencies for testing
        testDeps = with pkgs; [
          sops
          ssh-to-age
        ];

        # Build a test runner for a specific Emacs version
        makeTestRunner = name: emacs: pkgs.writeShellScriptBin "run-tests-${name}" ''
          export PATH="${pkgs.lib.makeBinPath testDeps}:$PATH"
          
          echo "Running tests with ${name}..."
          ${emacs}/bin/emacs -Q -batch \
            -eval "(progn (require 'package) (package-initialize))" \
            -L ${./.} -L ${./tests} \
            -l ${./tests/tests.el} \
            -l ${./tests/incremental_test.el} \
            -l ${./tests/ssh_to_age_test.el} \
            -f ert-run-tests-batch-and-exit
          
          echo "Running protocol tests with ${name}..."
          export SOPS_TEST_REAL_YAML=1
          ${emacs}/bin/emacs -Q -batch \
            -eval "(progn (require 'package) (package-initialize))" \
            -L ${./.} -L ${./tests} \
            -l ${./tests/protocol_test.el} \
            -l ${./tests/protocol_yaml_test.el} \
            -l ${./tests/core_compliance_test.el} \
            -f ert-run-tests-batch-and-exit
        '';

        # Create check derivations for each Emacs version
        makeCheck = name: emacs: pkgs.runCommand "test-${name}" {
          nativeBuildInputs = [ emacs ] ++ testDeps ++ [ pkgs.yq-go ];
          src = ./.;
        } ''
          cp -r $src/* .
          chmod -R +w .
          
          # Install yaml.el for real YAML parsing
          ${emacs}/bin/emacs -Q -batch \
            -eval "(progn 
                    (require 'package) 
                    (add-to-list 'package-archives '(\"melpa\" . \"https://melpa.org/packages/\") t) 
                    (package-initialize) 
                    (package-refresh-contents) 
                    (package-install 'yaml))" 2>/dev/null || true
          
          echo "Running unit tests with ${name}..."
          ${emacs}/bin/emacs -Q -batch \
            -eval "(progn (require 'package) (package-initialize))" \
            -L . -L tests \
            -l tests/tests.el \
            -l tests/incremental_test.el \
            -l tests/ssh_to_age_test.el \
            -f ert-run-tests-batch-and-exit
          
          echo "Running protocol tests with ${name}..."
          export SOPS_TEST_REAL_YAML=1
          ${emacs}/bin/emacs -Q -batch \
            -eval "(progn (require 'package) (package-initialize))" \
            -L . -L tests \
            -l tests/protocol_test.el \
            -l tests/protocol_yaml_test.el \
            -l tests/core_compliance_test.el \
            -f ert-run-tests-batch-and-exit
          
          touch $out
        '';

      in {
        # Development shells for each Emacs version
        devShells = pkgs.lib.mapAttrs (name: emacs: 
          pkgs.mkShell {
            buildInputs = [ emacs ] ++ testDeps ++ [
              (makeTestRunner name emacs)
            ];
            shellHook = ''
              echo "Development shell with ${name}"
              echo "Run 'run-tests-${name}' to execute tests"
            '';
          }
        ) emacsVersions // {
          default = pkgs.mkShell {
            buildInputs = [ emacsVersions.emacs-29-4 ] ++ testDeps ++ [
              (makeTestRunner "emacs-29-4" emacsVersions.emacs-29-4)
            ];
            shellHook = ''
              echo "Default development shell (Emacs 29.4)"
              echo "Run 'run-tests-emacs-29-4' to execute tests"
            '';
          };
        };

        # Checks for CI - runs tests for each Emacs version
        checks = pkgs.lib.mapAttrs makeCheck emacsVersions;

        # Packages (mainly for byte-compilation)
        packages.default = pkgs.runCommand "auth-source-sops" {
          src = ./.;
          nativeBuildInputs = [ emacsVersions.emacs-29-4 ];
        } ''
          mkdir -p $out/share/emacs/site-lisp
          cp $src/auth-source-sops.el $out/share/emacs/site-lisp/
          ${emacsVersions.emacs-29-4}/bin/emacs -Q -batch \
            -L $out/share/emacs/site-lisp \
            -f batch-byte-compile $out/share/emacs/site-lisp/auth-source-sops.el
        '';
      }
    );
}
