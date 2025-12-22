;;; protocol_yaml_test.el --- Protocol tests for auth-source-sops with YAML -*- lexical-binding: t -*-

(require 'ert)
(require 'auth-source-sops)

;; Only run these tests if we are in "Real YAML" mode.
(when (getenv "SOPS_TEST_REAL_YAML")
  (require 'yaml)
  
  (defvar auth-source-sops-protocol-yaml-test-dir
    (file-name-directory (or load-file-name buffer-file-name)))

  (defun auth-source-sops-protocol-yaml-setup ()
    "Setup a fresh sops file for testing."
    (let ((template-file (expand-file-name "empty-sops.yaml" auth-source-sops-protocol-yaml-test-dir))
          (target-file (make-temp-file "auth-source-sops-protocol-yaml-" nil ".yaml")))
      (copy-file template-file target-file t)
      (setq auth-source-sops-file target-file)
      (setq auth-source-sops-search-method :full)
      (auth-source-sops-enable)
      (auth-source-forget-all-cached)
      ;; Ensure age key is available
      (setenv "SOPS_AGE_KEY" (auth-source-sops-get-string-from-file 
                              (expand-file-name "age" auth-source-sops-protocol-yaml-test-dir)))))

  (defun auth-source-sops-protocol-yaml-teardown ()
    "Cleanup test file."
    (when (and auth-source-sops-file (file-exists-p auth-source-sops-file))
      (delete-file auth-source-sops-file)))

  (ert-deftest auth-source-sops-protocol-yaml-create-test ()
    "Test creating a NEW entry in a real encrypted sops YAML file using standard auth-source protocol."
    (auth-source-sops-protocol-yaml-setup)
    (unwind-protect
        (let* ((host "protocol-test-host")
               (user "protocol-test-user")
               (secret "protocol-test-secret")
               (port "8080")
               ;; 1. Search (should fail)
            ;; 1. Search (should fail)
               (initial-search (auth-source-search :host host :max 1)))
          (should (null initial-search))

            ;; 2. Create (simulated interactive)
          (cl-letf (((symbol-function 'read-string)
                     (lambda (prompt &rest _)
                       (cond
                        ((string-match-p "User" prompt) user)
                        ((string-match-p "Password" prompt) secret)
                        ((string-match-p "Port" prompt) port)
                        (t (error "Unexpected prompt: %s" prompt)))))
                     ((symbol-function 'read-passwd)
                      (lambda (prompt &rest _) secret)))
            (auth-source-search :host host :create t :max 1)
            
            ;; 3. Verify it was saved and can be found
            (sleep-for 1)
            (auth-source-forget-all-cached)
            (let ((created (car (auth-source-search :host host :max 1))))
              (should created)
              (should (equal (plist-get created :host) host))
              (should (equal (plist-get created :user) user))
              (should (equal (format "%s" (plist-get created :port)) port))
              (should (equal (funcall (plist-get created :secret)) secret)))))
      (auth-source-sops-protocol-yaml-teardown)))

  (ert-deftest auth-source-sops-protocol-yaml-delete-test ()
    "Test deleting an entry from a real encrypted sops YAML file."
    (auth-source-sops-protocol-yaml-setup)
    (unwind-protect
        (let ((host "delete-me")
              (user "user-to-delete")
              (secret "secret-to-delete")
              (kept-host "keep-me")
              (kept-user "user-to-keep"))

          ;; 1. Setup: Create two entries
          (cl-letf (((symbol-function 'read-string)
                     (lambda (prompt &rest _)
                       (cond
                        ((string-match-p "User" prompt) user)
                        ((string-match-p "Password" prompt) secret)
                        ((string-match-p "Port" prompt) "123")
                        (t ""))))
                     ((symbol-function 'read-passwd)
                      (lambda (prompt &rest _) secret)))
            (auth-source-search :host host :create t))
          
          (cl-letf (((symbol-function 'read-string)
                     (lambda (prompt &rest _)
                       (cond
                        ((string-match-p "User" prompt) kept-user)
                        ((string-match-p "Password" prompt) "keep-secret")
                        (t ""))))
                     ((symbol-function 'read-passwd)
                      (lambda (prompt &rest _) "keep-secret")))
            (auth-source-search :host kept-host :create t))

          ;; 2. Verify they exist
          (auth-source-forget-all-cached)
          (should (auth-source-search :host host :max 1))
          (should (auth-source-search :host kept-host :max 1))

          ;; 3. Delete one
          (let ((entry (car (auth-source-search :host host :max 1))))
            (message "DEBUG: Delete entry: %S" entry)
            ;; Use explicit backend delete function to bypass potential auth-source-delete dispatch issues in batch mode
            (auth-source-sops-delete entry)
            
            ;; Wait for deletion to propagate (polling)
            (let ((retries 20)
                  (deleted nil))
              (while (and (> retries 0) (not deleted))
                (auth-source-forget-all-cached)
                (if (null (auth-source-search :host host :max 1))
                    (setq deleted t)
                  (sleep-for 0.5)
                  (setq retries (1- retries))))
              (should deleted)))
          (should (auth-source-search :host kept-host :max 1)))
      (auth-source-sops-protocol-yaml-teardown)))
)

(provide 'protocol_yaml_test)
