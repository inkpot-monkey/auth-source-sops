;;; auth-source-sops-test.el --- Tests for auth-source-sops -*- lexical-binding: t; no-byte-compile: t -*-

;;; Commentary:

;; Tests for the auth-source-sops package.

;;; Code:
(defvar current-dir (file-name-directory (or load-file-name buffer-file-name)))

(require 'ert)
(require 'cl-lib)
(require 'auth-source-sops (expand-file-name "../auth-source-sops.el" current-dir))

(defvar auth-source-unencrypted-sops-file
  (expand-file-name "./secrets.yaml" current-dir))

(setq auth-source-sops-file
      (expand-file-name "./encrypted.yaml" current-dir))

(setq auth-source-sops-age-key
      (expand-file-name "./age" current-dir))

(auth-source-sops-enable)

;; Helpers
(defun remove-escaped-quotes (str)
  "Remove all escaped double quotes (\") from STR."
  (replace-regexp-in-string "\\\"" "" str))

;; Decrypt test
(ert-deftest auth-source-sops-decrypt-yaml-test ()
  "Test decrypting a sops yaml file."
  (should (equal
           (auth-source-sops-decrypt)
           (remove-escaped-quotes
            (auth-source-sops-get-string-from-file auth-source-unencrypted-sops-file)))))

;; Search tests
(ert-deftest auth-source-sops-search-basic-test ()
  "Test basic search functionality."
  (let ((result (car (auth-source-search :host "github"))))
    (should (equal (plist-get result :host) "github"))
    (should (equal (plist-get result :user) nil))
    (should (equal (plist-get result :port) nil))
    (should (equal (funcall (plist-get result :secret)) "1"))))

;; There are multiples of this search but this works because
;; auth-source-search has a default of :max 1 and the first
;; match in the the example secrets.yaml file matches this
(ert-deftest auth-source-sops-search-user-test ()
  "Test search with user specified."
  (let ((result (car (auth-source-search :host "github.com" :user "example"))))
    (should (equal (plist-get result :host) "github.com"))
    (should (equal (plist-get result :user) "example"))
    (should (equal (plist-get result :port) nil))
    (should (equal (funcall (plist-get result :secret)) "3"))))

(ert-deftest auth-source-sops-search-port-test ()
  "Test search with user specified."
  (let ((result (car (auth-source-search :host "github.com" :port 22))))
    (should (equal (plist-get result :host) "github.com"))
    (should (equal (plist-get result :user) nil))
    (should (equal (plist-get result :port) 22))
    (should (equal (funcall (plist-get result :secret)) "4"))))

(ert-deftest auth-source-sops-search-port-and-user-test ()
  "Test search with user specified."
  (let ((result (car (auth-source-search :host "github.com" :user "example" :port 22))))
    (should (equal (plist-get result :host) "github.com"))
    (should (equal (plist-get result :user) "example"))
    (should (equal (plist-get result :port) 22))
    (should (equal (funcall (plist-get result :secret)) "5"))))

;; Preference tests
;; List members should take precedence over elements defined in the key
(ert-deftest auth-source-sops-list-precedence-test ()
  "Test search with user specified."
  (let ((result (car (auth-source-search :host "api.github.com" :user "override"))))
    (should (equal (plist-get result :host) "api.github.com"))
    (should (equal (plist-get result :user) "override"))
    (should (equal (funcall (plist-get result :secret)) "7"))))

;; Nested list tests
(ert-deftest auth-source-sops-nested-list-test ()
  "Test search with user specified."
  (let ((result (car (auth-source-search :host "nested"))))
    (should (equal (plist-get result :host) "nested"))
    (should (equal (plist-get result :user) "example"))
    (should (equal (funcall (plist-get result :secret)) "8"))))

;; Max tests
(ert-deftest auth-source-sops-search-max-results-test ()
  "Test search with max results specified."
  (let ((results (auth-source-search :host "github.com" :max 4)))
    (should (= (length results) 4))
    (should (equal (plist-get (nth 0 results) :host) "github.com"))
    (should (equal (funcall (plist-get (nth 0 results) :secret)) "2"))
    (should (equal (plist-get (nth 1 results) :host) "github.com"))
    (should (equal (plist-get (nth 1 results) :user) "example"))
    (should (equal (funcall (plist-get (nth 1 results) :secret)) "3"))
    (should (equal (plist-get (nth 2 results) :host) "github.com"))
    (should (equal (plist-get (nth 2 results) :port) 22))
    (should (equal (funcall (plist-get (nth 2 results) :secret)) "4"))
    (should (equal (plist-get (nth 3 results) :host) "github.com"))
    (should (equal (plist-get (nth 3 results) :user) "example"))
    (should (equal (plist-get (nth 3 results) :port) 22))
    (should (equal (funcall (plist-get (nth 3 results) :secret)) "5"))))

;; Require tests
(ert-deftest auth-source-sops-search-require-user-test ()
  "Test search with require fields specified."
  (let ((result (car (auth-source-search
                      :host "api.github.com"
                      :require '(:user)))))
    (should (equal (plist-get result :host) "api.github.com"))
    (should (equal (plist-get result :user) "apikey"))
    (should (equal (plist-get result :port) nil))
    (should (equal (funcall (plist-get result :secret)) "6"))))

(ert-deftest auth-source-sops-search-require-secret-test ()
  "Test search with require fields specified."
  (let ((result (car (auth-source-search
                      :host "api.github.com"
                      :user "apikey"
                      :require '(:secret)))))
    (should (equal (plist-get result :host) "api.github.com"))
    (should (equal (plist-get result :user) "apikey"))
    (should (equal (plist-get result :port) nil))
    (should (equal (funcall (plist-get result :secret)) "6"))))

(ert-deftest auth-source-sops-search-require-multiple-test ()
  "Test search with require fields specified."
  (let ((result (car (auth-source-search
                      :host "api.github.com"
                      :user "apikey"
                      :require '(:secret :user)))))
    (should (equal (plist-get result :host) "api.github.com"))
    (should (equal (plist-get result :user) "apikey"))
    (should (equal (plist-get result :port) nil))
    (should (equal (funcall (plist-get result :secret)) "6"))))


;; Reproduction tests
(ert-deftest auth-source-sops-repro-machine-alias-test ()
  "Test that 'machine' key in YAML is mapped to :host."
  (cl-letf (((symbol-function 'auth-source-sops-decrypt)
             (lambda () "
repro-machine:
  - machine: machine.example.com
    password: secure
")))
    (let ((result (car (auth-source-search :host "machine.example.com"))))
      (should result)
      (should (equal (plist-get result :host) "machine.example.com"))
      (should (equal (funcall (plist-get result :secret)) "secure")))))

(ert-deftest auth-source-sops-repro-sudo-string-port-test ()
  "Test matching a string port 'sudo' used by TRAMP."
  (cl-letf (((symbol-function 'auth-source-sops-decrypt)
             (lambda () "
repro-sudo:
  - host: sudo-host
    port: sudo
    user: root
    password: sudo-password
")))
    (let ((result (car (auth-source-search :host "sudo-host" :port "sudo"))))
      (should result)
      (should (equal (plist-get result :port) "sudo"))
      (should (equal (funcall (plist-get result :secret)) "sudo-password")))))

(ert-deftest auth-source-sops-search-json-test ()
  "Test search functionality with a JSON file."
  (let ((auth-source-sops-file "secrets.json"))
    (cl-letf (((symbol-function 'auth-source-sops-decrypt)
               (lambda () (auth-source-sops-get-string-from-file
                           (expand-file-name "secrets.json" current-dir)))))
      (let ((result (car (auth-source-search :host "github.json"))))
        (should result)
        (should (equal (plist-get result :host) "github.json"))
        (should (equal (funcall (plist-get result :secret)) "json-secret")))
      
      (let ((result (car (auth-source-search :host "host.json" :user "json-user"))))
        (should result)
        (should (equal (plist-get result :user) "json-user"))
        (should (equal (funcall (plist-get result :secret)) "json-user-secret"))))))

;;; auth-source-sops-test.el ends here

(ert-deftest auth-source-sops-exit-code-test ()
  "Test that decryption fails if sops exit code is non-zero."
  ;; Mock call-process to return 1 (error)
  ;; Mock make-process to simulate failure
  (cl-letf* (((symbol-function 'make-process)
              (lambda (&rest args)
                ;; Call the sentinel immediately to simulate exit
                (let ((sentinel (plist-get args :sentinel))
                      (proc 'mock-proc)) ; Use a symbol as mock process
                  (funcall sentinel proc 'exit)
                  proc)))
             ((symbol-function 'process-status) (lambda (_) 'exit))
             ((symbol-function 'process-exit-status) (lambda (_) 1))
             ((symbol-function 'process-live-p) (lambda (_) nil))
             ((symbol-function 'accept-process-output) (lambda (&rest _) t)))
    (should-error (auth-source-sops-decrypt))))

(ert-deftest auth-source-sops-timeout-test ()
  "Test that decryption times out if process hangs."
  ;; Mock make-process to return a "hung" process
  (cl-letf* (((symbol-function 'make-process)
              (lambda (&rest args) 'mock-hung-proc))
             ;; process-live-p always returns true, simulating hang
             ((symbol-function 'process-live-p) (lambda (_) t))
             ((symbol-function 'process-status) (lambda (_) 'run))
             ((symbol-function 'process-exit-status) (lambda (_) nil))
             ((symbol-function 'delete-process) (lambda (_) t))
             ((symbol-function 'set-process-query-on-exit-flag) (lambda (_ __) t))
             ;; Advance time by 6 seconds to trigger timeout immediately in loop
             ((symbol-function 'float-time)
              (let ((counter 0))
                (lambda (&optional _time)
                  (setq counter (+ counter 6.0))
                  counter)))
             ((symbol-function 'accept-process-output) (lambda (&rest _) t)))
    (let ((err (should-error (auth-source-sops-decrypt))))
      (should (string-match-p "timed out" (cadr err))))))

(ert-deftest auth-source-sops-cleanup-test ()
  "Test that temporary buffers are cleaned up."
  (let ((created-buffers nil))
    (cl-letf* (((symbol-function 'generate-new-buffer)
                (lambda (name &optional _)
                  (let ((buf (get-buffer-create (make-temp-name name))))
                    (push buf created-buffers)
                    buf)))
               ;; Mock successful process
               ((symbol-function 'make-process)
                 (lambda (&rest args)
                   (funcall (plist-get args :sentinel) "mock-proc" 'exit)
                   "mock-proc"))
                ((symbol-function 'process-status) (lambda (_) 'exit))
                ((symbol-function 'process-exit-status) (lambda (_) 0))
                ((symbol-function 'set-process-query-on-exit-flag) (lambda (_ __) t))
                ((symbol-function 'accept-process-output) (lambda (&rest _) t)))
      
      ;; Run decrypt
      (auth-source-sops-decrypt)
      
      ;; Verify buffers were created
      (should created-buffers)
      ;; Verify all created buffers are dead
      (dolist (buf created-buffers)
        (should-not (buffer-live-p buf))))))

(ert-deftest auth-source-sops-permissions-test ()
  "Test that insecure permissions trigger a warning."
  ;; Mock file-modes to return world-readable (0644 = 420 decimal)
  (cl-letf (((symbol-function 'auth-source-sops--file-modes) (lambda (_) #o644))
            ((symbol-function 'warn) (lambda (&rest args) (error (apply #'format args)))) ; Turn warning into error for testing
            ((symbol-function 'file-exists-p) (lambda (_) t))
            ;; Mock decryption path to just return without doing real work
            ((symbol-function 'call-process) (lambda (&rest _) 0))) ; success
    ;; Since we turned warn into error, this should signal an error
    (should-error (auth-source-sops-decrypt))))


(ert-deftest auth-source-sops-cached-secret-test ()
  "Test that secret is cached and doesn't trigger decryption again."
  (cl-letf (((symbol-function 'auth-source-sops-decrypt)
             (lambda () (auth-source-sops-get-string-from-file
                         (expand-file-name "secrets.yaml" current-dir)))))
    (let* ((result (car (auth-source-search :host "github")))
           (secret-fn (plist-get result :secret)))
      ;; Now mock decrypt to FAIL. If it calls it, it will error.
      (cl-letf (((symbol-function 'auth-source-sops-decrypt)
                 (lambda () (error "Should not be called"))))
        (should (equal (funcall secret-fn) "1"))))))

(ert-deftest auth-source-sops-list-argument-test ()
  "Test search with list arguments."
  ;; Matches "github.com" which is in the list
  (let ((result (car (auth-source-search :host '("other.com" "github.com")))))
    (should result)
    (should (equal (plist-get result :host) "github.com"))))

(ert-deftest auth-source-sops-complex-key-test ()
  "Test parsing of complex user@host keys."
  (let ((result (car (auth-source-search :host "complex-host" :user "me@email.com" :port 123))))
    (should result)
    (should (equal (plist-get result :host) "complex-host"))
    (should (equal (plist-get result :user) "me@email.com"))
    (should (equal (plist-get result :port) 123))
    (should (equal (funcall (plist-get result :secret)) "99"))))

(ert-deftest auth-source-sops-wildcard-host-test ()
  "Test that a wildcard host 't' triggers a warning and returns nil."
  ;; Mock warn to just log a message we can check, or ensure it doesn't error
  (cl-letf (((symbol-function 'warn) #'ignore))
    (should (null (auth-source-search :host t)))))

(ert-deftest auth-source-sops-malformed-yaml-test ()
  "Test that malformed YAML (parser error) propagates as an error."
  (auth-source-forget-all-cached)
  ;; Mock decryption to return string "malformed" which triggers error in our mock yaml
  (cl-letf (((symbol-function 'auth-source-sops-decrypt)
             (lambda () "malformed")))
    (should-error (auth-source-search :host "github"))))

(ert-deftest auth-source-sops-complex-email-user-test ()
  "Test parsing of complex user@email.com@host key."
  (let ((result (car (auth-source-search :host "complex-host" :user "me@email.com"))))
    ;; NOTE: This relies on manual mocking or string logic if not integrated with a full yaml file in tests
    ;; But auth-source-search relies on parsing the key from the data list.
    ;; We'll use a mock decrypt to feed a key of this shape.
    (cl-letf (((symbol-function 'auth-source-sops-decrypt)
               (lambda () "
me@email.com@complex-host:99:
  - password: 99
")))
      (let ((result (car (auth-source-search :host "complex-host" :user "me@email.com" :port 99))))
        (should result)
        (should (equal (plist-get result :host) "complex-host"))
        (should (equal (plist-get result :user) "me@email.com"))
        (should (equal (plist-get result :port) 99))
        (should (equal (funcall (plist-get result :secret)) "99"))))))

