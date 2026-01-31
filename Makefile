EMACS ?= emacs
SRC = auth-source-sops.el
ELC = $(SRC:.el=.elc)

.PHONY: all test lint lint-package lint-doc compile clean

all: compile lint test

test: test-unit test-protocol

test-unit:
	@echo "Running unit tests..."
	$(EMACS) -Q -batch \
		-L . -L tests \
		-l tests/unit_tests.el \
		-l tests/ssh_to_age_test.el \
		-f ert-run-tests-batch-and-exit

test-protocol:
	@echo "Running protocol tests..."
	@export SOPS_TEST_REAL_YAML=1; \
	$(EMACS) -Q -batch \
		-L . -L tests \
		-l tests/integration_tests.el \
		-f ert-run-tests-batch-and-exit

lint: lint-package lint-doc

lint-package:
	@echo "Linting package..."
	$(EMACS) -Q -batch -L . -l package-lint -f package-lint-batch-and-exit $(SRC)

lint-doc:
	@echo "Checking documentation..."
	$(EMACS) -Q -batch -L . --eval "(checkdoc-file \"$(SRC)\")"

compile: $(ELC)

%.elc: %.el
	@echo "Compiling $<..."
	$(EMACS) -Q -batch -L . -f batch-byte-compile $<

clean:
	@echo "Cleaning up..."
	@rm -f *.elc tests/*.elc tests/auth-sops-*.json tests/sops-plain*.json
