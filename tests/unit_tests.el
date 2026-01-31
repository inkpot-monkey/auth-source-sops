(require 'cl-lib)
(require 'ert)
(require 'test-helper)

(require 'auth-source-sops (expand-file-name "../auth-source-sops.el" (file-name-directory (or load-file-name buffer-file-name))))

(ert-deftest auth-source-sops-decrypt-yaml-test ()
  "Test YAML parsing of decrypted content."
  (auth-source-sops-test-with-mock-environment
    (let* ((parsed (auth-source-sops-parse "file.yaml" "mocked-content")))
      (should (equal (cdr (assoc "github.com" parsed)) "2"))
      (should (equal (cdr (assoc "github" parsed)) "1")))))

(ert-deftest auth-source-sops-search-basic-test ()
  "Basic search functionality test."
  (auth-source-sops-test-with-mock-environment
    (let ((results (auth-source-sops-search :host "github.com" :backend auth-source-sops-backend)))
      (should (= (length results) 1))
      (should (equal (plist-get (car results) :host) "github.com"))
      (should (equal (funcall (plist-get (car results) :secret)) "2")))))

(ert-deftest auth-source-sops-search-user-test ()
  "Test searching by user."
  (auth-source-sops-test-with-mock-environment
    (let ((results (auth-source-search :host "api.github.com" :user "apikey")))
      (should (= (length results) 1))
      (should (equal (plist-get (car results) :user) "apikey")))))

(ert-deftest auth-source-sops-search-port-test ()
  "Test searching by port."
  (auth-source-sops-test-with-mock-environment
    (let ((results (auth-source-search :host "github.com" :port 22)))
      (should (= (length results) 1))
      (should (equal (plist-get (car results) :port) 22)))))

(ert-deftest auth-source-sops-search-port-and-user-test ()
  "Test searching by port and user."
  (auth-source-sops-test-with-mock-environment
    (let ((results (auth-source-search :host "github.com" :port 22 :user "example")))
      (should (= (length results) 1))
      (should (equal (plist-get (car results) :user) "example")))))

(ert-deftest auth-source-sops-list-precedence-test ()
  "Test that the first matching entry in a list is returned."
  (auth-source-sops-test-with-mock-environment
    (let ((results (auth-source-search :host "multiple@yaml-host" :port 443)))
      (should (= (length results) 1))
      (should (equal (funcall (plist-get (car results) :secret)) "p443-yaml")))))

(ert-deftest auth-source-sops-nested-list-test ()
  "Test searching inside nested structures."
  (auth-source-sops-test-with-mock-environment
    (let ((results (auth-source-search :host "nested" :user "example")))
      (should (= (length results) 1))
      (should (equal (funcall (plist-get (car results) :secret)) "8")))))

(ert-deftest auth-source-sops-search-max-results-test ()
  "Test the :max parameter."
  (auth-source-sops-test-with-mock-environment
    (let ((results (auth-source-search :host "multiple@yaml-host" :max 2)))
      (should (= (length results) 2)))))

(ert-deftest auth-source-sops-repro-machine-alias-test ()
  "Test machine alias handling."
  (auth-source-sops-test-with-mock-environment
    (let ((results (auth-source-search :host "repro-machine")))
      (should (= (length results) 1))
      (should (equal (plist-get (car results) :host) "machine.example.com")))))

(ert-deftest auth-source-sops-repro-sudo-string-port-test ()
  "Test sudo port handling."
  (auth-source-sops-test-with-mock-environment
    (let ((results (auth-source-search :host "repro-sudo")))
      (should (= (length results) 1))
      (should (equal (plist-get (car results) :port) "sudo")))))

;; Incremental Search Tests (Merged from incremental_test.el)

(ert-deftest auth-source-sops-incremental-extraction-test ()
  "Verify that incremental parsing uses sops --extract."
  (auth-source-sops-test-with-mock-environment
    (let ((extract-calls 0)
          (raw-content "\nkey1: ENC[...]\nkey2: ENC[...]\n"))
      (cl-letf* (((symbol-function 'auth-source-sops-get-string-from-file)
                  (lambda (_path) raw-content))
                 ((symbol-function 'auth-source-sops-decrypt)
                  (lambda () (error "This should NOT be called in incremental mode")))
                 ((symbol-function 'auth-source-sops-parse)
                  (lambda (_file output)
                    (cond
                     ((string-match-p "ENC" output)
                      '(("github" . "enc")
                        ("api.github.com" . "enc")
                        ("origin@api.github.com" . "enc")))
                     ((string-match-p "api" output)
                      '((user . "apikey") (secret . "6")))
                     (t
                      '((secret . "secret-value"))))))
                 ((symbol-function 'process-live-p) (lambda (_p) nil))
                 ((symbol-function 'process-exit-status) (lambda (_p) 0))
                 ((symbol-function 'accept-process-output) (lambda (&rest _args) t))
                 ((symbol-function 'set-process-query-on-exit-flag) (lambda (&rest _args) nil))
                 ((symbol-function 'make-process)
                  (lambda (&rest args)
                    (let ((command (plist-get args :command)))
                      (when (member "--extract" command)
                        (setq extract-calls (1+ extract-calls))
                        (let ((key (nth 3 command)))
                          (with-current-buffer (plist-get args :buffer)
                            (insert (if (string-match "api" key)
                                        "user: apikey\nsecret: 6"
                                      "example-secret"))))
                        (funcall (plist-get args :sentinel) 'fake-proc "finished\n"))
                      'fake-proc))))
        (setq auth-source-sops-search-method :incremental)
        
        (let ((results (auth-source-search :host "github" :max 1)))
          (should (= (length results) 1))
          (should (equal (plist-get (car results) :host) "github"))
          (should (= extract-calls 1)))
        
        (let ((results (auth-source-search :host "api.github.com" :max 2)))
          (should (= (length results) 2))
          (should (equal (plist-get (car results) :host) "api.github.com"))
          (should (= extract-calls 3)))))))

;; Creation Tests (Merged from create_test.el)

(ert-deftest auth-source-sops-create-new-test ()
  "Verify that creating a new entry works."
  (auth-source-sops-test-with-mock-environment
    (let ((set-calls 0)
          (last-payload nil))
      (cl-letf* (((symbol-function 'auth-source-sops--get-raw-structure) (lambda () nil))
                 ((symbol-function 'read-string) (lambda (_prompt &optional _init _hist default) (or default "testuser")))
                 ((symbol-function 'read-passwd) (lambda (_prompt) "testpass"))
                 ((symbol-function 'auth-source-sops-get-string-from-file) (lambda (_) "fake-key"))
                 ((symbol-function 'call-process)
                  (lambda (_exe _infile destination _display &rest args)
                    (if (member "set" args)
                        (progn
                          (setq set-calls (1+ set-calls))
                          (setq last-payload (nth 3 args))
                          0)
                      0))))
        
        (setq auth-source-sops-search-method :incremental)
        (let ((results (auth-source-search :host "newhost" :create t)))
          (should (= (length results) 1))
          (should (equal (plist-get (car results) :host) "newhost"))
          (should (equal (funcall (plist-get (car results) :secret)) "testpass"))
          (should (= set-calls 1))
          (should (string-match-p "testuser" last-payload))
          (should (string-match-p "testpass" last-payload)))))))

(ert-deftest auth-source-sops-cleanup-test ()
  "Verify cache cleanup."
  (auth-source-sops-test-with-mock-environment
    (setq auth-source-sops--raw-cache '((host1 . "val1")))
    (auth-source-forget+ :host t)
    (should (null auth-source-sops--raw-cache))))

(ert-deftest auth-source-sops-permissions-test ()
  "Verify permission check logic."
  (auth-source-sops-test-with-mock-environment
    (cl-letf (((symbol-function 'auth-source-sops--file-modes) (lambda (_) #o600)))
      (should-not (auth-source-sops--check-permissions "/tmp/fake")))))

(ert-deftest auth-source-sops-wildcard-host-test ()
  "Verify wildcard host search support."
  (auth-source-sops-test-with-mock-environment
    (let ((results (auth-source-search :host t :max 10)))
      (should (> (length results) 5)))))

(provide 'unit-tests)
