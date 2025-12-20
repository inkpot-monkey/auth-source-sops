(require 'ert)
(require 'auth-source-sops "./auth-source-sops.el")

(ert-deftest auth-source-sops-incremental-extraction-test ()
  "Verify that incremental parsing uses sops --extract."
  (let ((extract-calls 0)
        (raw-content "\nkey1: ENC[...]\nkey2: ENC[...]\n"))
    (cl-letf* (((symbol-function 'auth-source-sops-get-string-from-file)
                (lambda (_path) raw-content))
               ((symbol-function 'auth-source-sops-decrypt)
                (lambda () (error "This should NOT be called in incremental mode")))
               ((symbol-function 'auth-source-sops-parse)
                (lambda (file output)
                  (cond
                   ((string-match-p "ENC" output) ; Raw encrypted structure
                    '(("github" . "enc")
                      ("api.github.com" . "enc")
                      ("origin@api.github.com" . "enc")))
                   ((string-match-p "api" output) ; Extracted branch
                    '((user . "apikey") (secret . "6")))
                   (t ; Default extracted branch
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
                      (funcall (plist-get args :sentinel) 'fake-proc "finished\n")
                      'fake-proc)))))
      
      (auth-source-sops-enable)
      (setq auth-source-sops-file "/fake/path.yaml")
      ;; Clear cache
      (setq auth-source-sops--raw-cache nil)
      
      (let ((results (auth-source-search :host "github" :max 1)))
        (should (= (length results) 1))
        (should (equal (plist-get (car results) :host) "github"))
        (should (= extract-calls 1)))
      
      (let ((results (auth-source-search :host "api.github.com" :max 2)))
        (should (= (length results) 2))
        (should (equal (plist-get (car results) :host) "api.github.com"))
        (should (= extract-calls 3))))))

(ert-deftest auth-source-sops-incremental-wildcard-test ()
  "Verify that wildcard searches extract multiple matching branches."
  (let ((extract-calls 0)
        (raw-content "\nhost1: ENC[...]\nhost2: ENC[...]\n"))
    (cl-letf* (((symbol-function 'auth-source-sops-get-string-from-file)
                (lambda (_path) raw-content))
               ((symbol-function 'auth-source-sops-parse)
                (lambda (_file output)
                  (if (string-match-p "ENC" output)
                      '(("host1" . "enc") ("host2" . "enc") ("other" . "enc"))
                    (if (string-match-p "host2" output)
                        '(("host2" . "enc"))
                      '(("host1" . "enc"))))))
               ((symbol-function 'process-live-p) (lambda (_p) nil))
               ((symbol-function 'process-exit-status) (lambda (_p) 0))
               ((symbol-function 'accept-process-output) (lambda (&rest _args) t))
               ((symbol-function 'set-process-query-on-exit-flag) (lambda (&rest _args) nil))
               ((symbol-function 'make-process)
                (lambda (&rest args)
                  (setq extract-calls (1+ extract-calls))
                  (with-current-buffer (plist-get args :buffer)
                    (insert (if (member "host2" (plist-get args :command))
                                "secret: host2-val"
                              "secret: host1-val")))
                  (funcall (plist-get args :sentinel) 'fake-proc "finished\n")
                  'fake-proc)))
      
      (auth-source-sops-enable)
      (setq auth-source-sops-file "/fake/path.yaml")
      (setq auth-source-sops--raw-cache nil)
      
      ;; Search for host matching "host.*"
      (let ((results (auth-source-search :host "host." :max 2)))
        (should (= (length results) 2))
        (should (= extract-calls 2))))))

(ert-deftest auth-source-sops-incremental-cache-test ()
  "Verify that raw structure is cached."
  (let ((read-calls 0))
    (cl-letf* (((symbol-function 'auth-source-sops-get-string-from-file)
                (lambda (_path) (setq read-calls (1+ read-calls)) "key: enc"))
               ((symbol-function 'auth-source-sops-parse) (lambda (&rest _) '(("host" . "enc"))))
               ((symbol-function 'file-attributes) (lambda (_) '((0 0 0 0))))) ; Mock mod time
      
      (setq auth-source-sops--raw-cache nil)
      (setq auth-source-sops-file "/fake/path.yaml")
      
      ;; First call
      (auth-source-sops--get-raw-structure)
      (should (= read-calls 1))
      
      ;; Second call - should use cache
      (auth-source-sops--get-raw-structure)
      (should (= read-calls 1)))))

(ert-deftest auth-source-sops-incremental-json-test ()
  "Verify that incremental parsing works with JSON files."
  (let ((extract-calls 0)
        (raw-content "{\"host1\": \"ENC[...]\", \"host2\": \"ENC[...]\"}"))
    (cl-letf* (((symbol-function 'auth-source-sops-get-string-from-file)
                (lambda (_path) raw-content))
               ((symbol-function 'json-parse-string)
                (lambda (string &rest _args)
                  (cond
                   ((string-match-p "ENC" string)
                    '((host1 . "enc") (host2 . "enc")))
                   ((string-match-p "json-val1" string)
                    "json-val1")
                   (t
                    "json-val2"))))
               ((symbol-function 'auth-source-sops-decrypt)
                (lambda () (error "Should not call full decrypt")))
               ((symbol-function 'process-live-p) (lambda (_p) nil))
               ((symbol-function 'process-exit-status) (lambda (_p) 0))
               ((symbol-function 'accept-process-output) (lambda (&rest _args) t))
               ((symbol-function 'set-process-query-on-exit-flag) (lambda (&rest _args) nil))
               ((symbol-function 'make-process)
                (lambda (&rest args)
                  (setq extract-calls (1+ extract-calls))
                  (with-current-buffer (plist-get args :buffer)
                    (insert (if (string-match-p "host1" (format "%S" (plist-get args :command)))
                                "{\"secret\": \"json-val1\"}"
                              "{\"secret\": \"json-val2\"}")))
                  (funcall (plist-get args :sentinel) 'fake-proc "finished\n")
                  'fake-proc)))
      
      (auth-source-sops-enable)
      (setq auth-source-sops-file "/fake/path.json")
      (setq auth-source-sops--raw-cache nil)
      
      (let ((results (auth-source-search :host "host1")))
        (should (= (length results) 1))
        (should (equal (funcall (plist-get (car results) :secret)) "json-val1"))
        (should (= extract-calls 1))))))

(provide 'incremental-test)
