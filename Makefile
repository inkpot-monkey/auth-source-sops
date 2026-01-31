EMACS ?= emacs
SRC = auth-source-sops.el
TESTS = tests/tests.el tests/incremental_test.el tests/protocol_yaml_test.el tests/core_compliance_test.el

.PHONY: test clean compile

test: test-unit test-protocol

test-unit:
	@echo "Running unit tests (Mock YAML)..."
	$(EMACS) -Q -batch \
		-eval "(progn (require 'package) (package-initialize))" \
		-L . -L tests \
		-l tests/tests.el \
		-l tests/incremental_test.el \
		-l tests/ssh_to_age_test.el \
		-f ert-run-tests-batch-and-exit

test-protocol:
	@echo "Running protocol tests (Real YAML/JSON)..."
	@export SOPS_TEST_REAL_YAML=1; \
	$(EMACS) -Q -batch \
		-eval "(progn (require 'package) (package-initialize))" \
		-L . -L tests \
		-l tests/protocol_test.el \
		-l tests/protocol_yaml_test.el \
		-l tests/core_compliance_test.el \
		-f ert-run-tests-batch-and-exit

clean:
	@echo "Cleaning up..."
	@rm -f *.elc tests/*.elc tests/auth-sops-*.json tests/sops-plain*.json

compile:
	@echo "Compiling..."
	$(EMACS) -Q -batch -L . -f batch-byte-compile $(SRC)
