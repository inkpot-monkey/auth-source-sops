(require 'cl-lib)
(require 'ert)
(require 'test-helper)

(require 'auth-source-sops (expand-file-name "../auth-source-sops.el" (file-name-directory (or load-file-name buffer-file-name))))

(defun auth-source-sops-test-integration-setup (format)
  "Setup a fresh sops file for testing. Returns the temp file path."
  (let* ((ext (if (eq format 'yaml) ".yaml" ".json"))
         (template-file (expand-file-name (format "empty-sops%s" ext) auth-source-sops-test-dir))
         (target-file (make-temp-file "auth-source-sops-integration-" nil ext)))
    (copy-file template-file target-file t)
    (setenv "SOPS_AGE_KEY" (auth-source-sops-test-get-age-key))
    target-file))

(ert-deftest auth-source-sops-protocol-compliance-test ()
  "Consolidated protocol compliance test for both JSON and YAML."
  (dolist (format '(json yaml))
    (let ((auth-source-sops-file (auth-source-sops-test-integration-setup format))
          (auth-source-sops-age-key-source 'environment)
          (auth-sources '(sops))
          (auth-source-do-cache nil)
          (user "proto-user")
          (pass "proto-pass")
          (host (format "proto-host-%s" format)))
      
      (auth-source-sops-enable)
      (unwind-protect
          (progn
            ;; 1. Search (should be empty)
            (should (null (auth-source-search :host host)))

            ;; 2. Create entry
            (cl-letf (((symbol-function 'read-string) (lambda (&rest _) user))
                      ((symbol-function 'read-passwd) (lambda (&rest _) pass)))
              (auth-source-search :host host :create t :max 1))

            ;; 3. Verify persistence
            (auth-source-forget-all-cached)
            (let ((created (car (auth-source-search :host host))))
              (should created)
              (should (equal (plist-get created :user) user))
              (should (equal (funcall (plist-get created :secret)) pass)))

            ;; 4. Delete entry
            (let ((entry (car (auth-source-search :host host))))
              (auth-source-sops-delete entry)
              (auth-source-forget-all-cached)
              (should (null (auth-source-search :host host)))))
        
        (when (file-exists-p auth-source-sops-file)
          (delete-file auth-source-sops-file))))))

(ert-deftest auth-source-sops-core-compliance-search-test ()
  "Verify compliance with high-level auth-source search patterns."
  (let* ((temp-sops-file (make-temp-file "auth-sops-core" nil ".json"))
         (plain-file (make-temp-file "sops-plain" nil ".json"))
         (age-recipient (auth-source-sops-test-get-age-recipient)))
    
    (with-temp-file plain-file 
      (insert "{\"a1\": {\"port\": \"a2\", \"user\": \"a3\", \"secret\": \"a4\"},
                \"b1\": {\"port\": \"b2\", \"user\": \"b3\", \"secret\": \"b4\"}}"))
    
    (setenv "SOPS_AGE_KEY" (auth-source-sops-test-get-age-key))
    (call-process "sops" nil `(:file ,temp-sops-file) nil
                  "--age" age-recipient "--encrypt" plain-file)
    
    (unwind-protect
        (let ((auth-source-sops-file temp-sops-file)
              (auth-source-sops-age-key-source 'environment)
              (auth-sources '(sops))
              (auth-source-do-cache nil))
          
          (auth-source-sops-enable)
          
          ;; Test multiple searches
          (should (= (length (auth-source-search :host t :max 10)) 2))
          (should (equal (plist-get (car (auth-source-search :host "a1")) :user) "a3"))
          (should (equal (funcall (plist-get (car (auth-source-search :host "b1")) :secret)) "b4")))
      
      (delete-file temp-sops-file)
      (delete-file plain-file))))

(provide 'integration-tests)
