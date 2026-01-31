EMACS ?= emacs
SRC = auth-source-sops.el

.PHONY: test clean compile

test: test-unit test-protocol

test-unit:
	@echo "Running unit tests..."
	$(EMACS) -Q -batch \
		-eval "(progn (require 'package) (package-initialize))" \
		-L . -L tests \
		-l tests/unit_tests.el \
		-l tests/ssh_to_age_test.el \
		-f ert-run-tests-batch-and-exit

test-protocol:
	@echo "Running protocol tests..."
	@export SOPS_TEST_REAL_YAML=1; \
	$(EMACS) -Q -batch \
		-eval "(progn (require 'package) (package-initialize))" \
		-L . -L tests \
		-l tests/integration_tests.el \
		-f ert-run-tests-batch-and-exit

clean:
	@echo "Cleaning up..."
	@rm -f *.elc tests/*.elc tests/auth-sops-*.json tests/sops-plain*.json

compile:
	@echo "Compiling..."
	$(EMACS) -Q -batch -L . -f batch-byte-compile $(SRC)
