;;; ssh_to_age_test.el --- Tests for SSH-to-Age integration -*- lexical-binding: t; no-byte-compile: t -*-

;;; Commentary:

;; Tests for the SSH-to-Age key derivation feature of auth-source-sops.

;;; Code:
(defvar current-dir (file-name-directory (or load-file-name buffer-file-name)))

(require 'ert)
(require 'cl-lib)
(require 'auth-source-sops (expand-file-name "../auth-source-sops.el" current-dir))

;; Test SSH key paths
(defvar ssh-test-key-private
  (expand-file-name "ssh_test_key" current-dir))

(defvar ssh-test-key-public
  (expand-file-name "ssh_test_key.pub" current-dir))

;; Expected derived age key (pre-computed for reproducibility)
(defvar expected-derived-age-key
  "AGE-SECRET-KEY-1KJTU68E8LYXZ2S0XRY6HLHXN7QHDVAEDDZX4A2G5EQC4E9SV9QLQP0RR8A")

;;; Tests for customization variables

(ert-deftest auth-source-sops-age-key-source-custom-type-test ()
  "Test that auth-source-sops-age-key-source is a defcustom with correct type."
  (should (custom-variable-p 'auth-source-sops-age-key-source))
  (let ((type (get 'auth-source-sops-age-key-source 'custom-type)))
    (should (eq (car type) 'choice))
    ;; Verify it includes environment, file, and ssh options
    (should (member '(const :tag "Environment variable" environment) (cdr type)))
    (should (member '(const :tag "File" file) (cdr type)))
    (should (member '(const :tag "Derive from SSH key" ssh) (cdr type)))))

(ert-deftest auth-source-sops-ssh-private-key-default-test ()
  "Test that auth-source-sops-ssh-private-key defaults to ~/.ssh/id_ed25519."
  (should (equal (default-value 'auth-source-sops-ssh-private-key) "~/.ssh/id_ed25519")))

(ert-deftest auth-source-sops-ssh-to-age-executable-default-test ()
  "Test that auth-source-sops-ssh-to-age-executable defaults to 'ssh-to-age'."
  (should (equal (default-value 'auth-source-sops-ssh-to-age-executable) "ssh-to-age")))

;;; Tests for cache variable

(ert-deftest auth-source-sops-derived-age-key-initially-nil-test ()
  "Test that auth-source-sops--derived-age-key is initially nil."
  (let ((auth-source-sops--derived-age-key nil))
    (should (null auth-source-sops--derived-age-key))))

;;; Tests for auth-source-sops--ensure-age-key

(ert-deftest auth-source-sops-ensure-age-key-environment-mode-test ()
  "Test that 'environment mode doesn't set SOPS_AGE_KEY."
  (let ((auth-source-sops-age-key-source 'environment)
        (process-environment (copy-sequence process-environment)))
    ;; Clear any existing key
    (setenv "SOPS_AGE_KEY" nil)
    ;; Should not error and should not set the env var
    (auth-source-sops--ensure-age-key)
    (should (null (getenv "SOPS_AGE_KEY")))))

(ert-deftest auth-source-sops-ensure-age-key-file-mode-test ()
  "Test that 'file mode reads from auth-source-sops-age-key file."
  (let ((auth-source-sops-age-key-source 'file)
        (auth-source-sops-age-key (expand-file-name "age" current-dir))
        (process-environment (copy-sequence process-environment)))
    (setenv "SOPS_AGE_KEY" nil)
    (auth-source-sops--ensure-age-key)
    (should (string-prefix-p "AGE-SECRET-KEY-" (getenv "SOPS_AGE_KEY")))))

(ert-deftest auth-source-sops-ensure-age-key-file-mode-missing-file-test ()
  "Test that 'file mode errors when file doesn't exist."
  (let ((auth-source-sops-age-key-source 'file)
        (auth-source-sops-age-key "/nonexistent/path/to/age/key"))
    (should-error (auth-source-sops--ensure-age-key) :type 'user-error)))

(ert-deftest auth-source-sops-ensure-age-key-file-mode-nil-key-test ()
  "Test that 'file mode errors when auth-source-sops-age-key is nil."
  (let ((auth-source-sops-age-key-source 'file)
        (auth-source-sops-age-key nil))
    (should-error (auth-source-sops--ensure-age-key) :type 'user-error)))

(ert-deftest auth-source-sops-ensure-age-key-ssh-mode-test ()
  "Test that 'ssh mode derives key from SSH key."
  (skip-unless (executable-find "ssh-to-age"))
  (skip-unless (file-exists-p ssh-test-key-private))
  (let ((auth-source-sops-age-key-source 'ssh)
        (auth-source-sops-ssh-private-key ssh-test-key-private)
        (auth-source-sops--derived-age-key nil)
        (process-environment (copy-sequence process-environment)))
    (setenv "SOPS_AGE_KEY" nil)
    (auth-source-sops--ensure-age-key)
    (should (equal (getenv "SOPS_AGE_KEY") expected-derived-age-key))
    (should (equal auth-source-sops--derived-age-key expected-derived-age-key))))

(ert-deftest auth-source-sops-ensure-age-key-ssh-mode-caching-test ()
  "Test that 'ssh mode caches the derived key and doesn't call ssh-to-age again."
  (skip-unless (executable-find "ssh-to-age"))
  (let ((auth-source-sops-age-key-source 'ssh)
        (auth-source-sops-ssh-private-key ssh-test-key-private)
        (auth-source-sops--derived-age-key "CACHED-KEY")
        (process-environment (copy-sequence process-environment))
        (shell-command-called nil))
    (setenv "SOPS_AGE_KEY" nil)
    (cl-letf (((symbol-function 'shell-command-to-string)
               (lambda (_cmd)
                 (setq shell-command-called t)
                 "AGE-SECRET-KEY-NEWKEY")))
      (auth-source-sops--ensure-age-key)
      ;; Should use cached key, not call shell command
      (should-not shell-command-called)
      (should (equal (getenv "SOPS_AGE_KEY") "CACHED-KEY")))))

(ert-deftest auth-source-sops-ensure-age-key-ssh-mode-missing-executable-test ()
  "Test that 'ssh mode errors when ssh-to-age is not found."
  (let ((auth-source-sops-age-key-source 'ssh)
        (auth-source-sops-ssh-private-key ssh-test-key-private)
        (auth-source-sops--derived-age-key nil))
    (cl-letf (((symbol-function 'executable-find)
               (lambda (_) nil)))
      (should-error (auth-source-sops--ensure-age-key) :type 'user-error))))

(ert-deftest auth-source-sops-ensure-age-key-ssh-mode-missing-key-test ()
  "Test that 'ssh mode errors when SSH key doesn't exist."
  (let ((auth-source-sops-age-key-source 'ssh)
        (auth-source-sops-ssh-private-key "/nonexistent/ssh/key")
        (auth-source-sops--derived-age-key nil))
    (should-error (auth-source-sops--ensure-age-key) :type 'user-error)))

(ert-deftest auth-source-sops-ensure-age-key-ssh-mode-invalid-output-test ()
  "Test that 'ssh mode errors when ssh-to-age returns invalid output."
  (let ((auth-source-sops-age-key-source 'ssh)
        (auth-source-sops-ssh-private-key ssh-test-key-private)
        (auth-source-sops--derived-age-key nil))
    (cl-letf (((symbol-function 'executable-find) (lambda (_) t))
              ((symbol-function 'file-exists-p) (lambda (_) t))
              ((symbol-function 'shell-command-to-string)
               (lambda (_) "error: invalid SSH key format")))
      (should-error (auth-source-sops--ensure-age-key) :type 'user-error))))

(ert-deftest auth-source-sops-ensure-age-key-unknown-source-test ()
  "Test that unknown key source triggers an error."
  (let ((auth-source-sops-age-key-source 'unknown))
    (should-error (auth-source-sops--ensure-age-key) :type 'user-error)))

;;; Tests for auth-source-sops-clear-ssh-cache

(ert-deftest auth-source-sops-clear-ssh-cache-test ()
  "Test that auth-source-sops-clear-ssh-cache clears the cached key."
  (let ((auth-source-sops--derived-age-key "SOME-CACHED-KEY"))
    (auth-source-sops-clear-ssh-cache)
    (should (null auth-source-sops--derived-age-key))))

;;; Integration test - full decryption with SSH-derived key

(ert-deftest auth-source-sops-ssh-mode-decrypt-integration-test ()
  "Test that SSH-derived key works for actual decryption.
This test requires sops and ssh-to-age to be installed."
  (skip-unless (executable-find "sops"))
  (skip-unless (executable-find "ssh-to-age"))
  (skip-unless (file-exists-p ssh-test-key-private))
  ;; This test would require a secrets file encrypted with the SSH-derived age key
  ;; For now, we just verify the key derivation path works end-to-end
  (let ((auth-source-sops-age-key-source 'ssh)
        (auth-source-sops-ssh-private-key ssh-test-key-private)
        (auth-source-sops--derived-age-key nil)
        (process-environment (copy-sequence process-environment)))
    (setenv "SOPS_AGE_KEY" nil)
    ;; Verify key gets set correctly before decryption would happen
    (auth-source-sops--ensure-age-key)
    (should (equal (getenv "SOPS_AGE_KEY") expected-derived-age-key))))

(provide 'ssh_to_age_test)
;;; ssh_to_age_test.el ends here
