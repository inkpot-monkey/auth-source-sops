;;; tests/protocol_test.el --- Protocol compliance tests -*- lexical-binding: t; no-byte-compile: t; -*-
(require 'auth-source-sops "./auth-source-sops.el")
(require 'ert)
(require 'cl-lib)

;; This test is adapted from the core Emacs auth-source-tests.el.
;; It verifies that the :create protocol is correctly followed.

(ert-deftest auth-source-sops-protocol-create-test ()
  "Verify that sops follows the standard :create protocol.
Adapted from `auth-source-test-netrc-create-secret'."
  (let* ((test-dir (file-name-as-directory (let ((file (or load-file-name buffer-file-name)))
                                              (if file
                                                  (file-name-directory file)
                                                (expand-file-name "tests" default-directory)))))
         (temp-sops-file (make-temp-file "auth-sops-test" nil ".json"))
         (age-key-file (expand-file-name "age" test-dir))
         (template-file (expand-file-name "empty-sops.json" test-dir)))
    (copy-file template-file temp-sops-file t)
    
    (unwind-protect
        (let ((auth-source-sops-file temp-sops-file)
              (auth-source-sops-age-key age-key-file)
              (auth-sources '(sops))
              (auth-source-sops--raw-cache nil)
              (passwd "standard-test-pass")
              (user "standard-test-user")
              (host "protocol-test-host"))
          
          (auth-source-sops-enable)
          
          ;; Redefine `read-*' to avoid interaction
          (cl-letf (((symbol-function 'read-passwd) (lambda (_) passwd))
                    ((symbol-function 'read-string)
                     (lambda (_prompt &optional _initial _history default _inherit)
                       (cond ((string-match-p "User" _prompt) user)
                             (t default)))))
            
            (let ((auth-info (car (auth-source-search
                                   :host host :require '(:user :secret) :create t))))
              (should auth-info)
              (should (string-equal (plist-get auth-info :user) user))
              (should (string-equal (plist-get auth-info :host) host))
              (should (equal (funcall (plist-get auth-info :secret)) passwd)))
            
            ;; Persistent check
            (auth-source-forget+ :host t)
            (setq auth-source-sops--raw-cache nil)
            
            (let ((auth-info (car (auth-source-search :host host))))
              (should auth-info)
              (should (string-equal (plist-get auth-info :user) user))
              (should (string-equal (plist-get auth-info :host) host))
              (should (string-equal (funcall (plist-get auth-info :secret)) passwd)))))
      
      (delete-file temp-sops-file))))

(ert-deftest auth-source-sops-protocol-search-test ()
  "Test various search criteria for protocol compliance."
  (let* ((test-dir (file-name-as-directory (let ((file (or load-file-name buffer-file-name)))
                                              (if file
                                                  (file-name-directory file)
                                                (expand-file-name "tests" default-directory)))))
         (temp-sops-file (make-temp-file "auth-sops-search" nil ".json"))
         (age-key-file (expand-file-name "age" test-dir))
         (template-file (expand-file-name "empty-sops.json" test-dir)))
    (copy-file template-file temp-sops-file t)
    
    (unwind-protect
        (let ((auth-source-sops-file temp-sops-file)
              (auth-source-sops-age-key age-key-file)
              (auth-sources '(sops))
              (auth-source-do-cache nil))
          (auth-source-sops-enable)
          
          ;; Redefine `read-*' to avoid interaction
          (cl-letf (((symbol-function 'read-passwd) (lambda (_) "pass"))
                    ((symbol-function 'read-string) (lambda (_p &optional _i _h d _inh) (or d ""))))
            
            ;; Setup some entries
            (auth-source-search :host "host-a" :user "user-a" :secret "pass-a" :create t)
            (auth-source-search :host "host-b" :user "user-b" :secret "pass-b" :create t)
            (auth-source-search :host "host-c" :user "user-c" :secret "pass-c" :create t)
            
            ;; Test host t (wildcard)
            (should (= (length (auth-source-search :host t :max 10)) 3))
            
            ;; Test max 1
            (should (= (length (auth-source-search :host t :max 1)) 1))
            
            ;; Test max 0 (boolean)
            (should (eq (auth-source-search :host "host-a" :max 0) t))
            (should (eq (auth-source-search :host "nonexistent" :max 0) nil))
            
            ;; Test specific criteria
            (let ((res (car (auth-source-search :host "host-b"))))
              (should (equal (plist-get res :user) "user-b")))))
      (when (file-exists-p temp-sops-file)
        (delete-file temp-sops-file)))))

(ert-deftest auth-source-sops-protocol-delete-test ()
  "Test secret deletion for protocol compliance."
  (let* ((test-dir (file-name-as-directory (let ((file (or load-file-name buffer-file-name)))
                                              (if file
                                                  (file-name-directory file)
                                                (expand-file-name "tests" default-directory)))))
         (temp-sops-file (make-temp-file "auth-sops-delete" nil ".json"))
         (age-key-file (expand-file-name "age" test-dir))
         (template-file (expand-file-name "empty-sops.json" test-dir)))
    (copy-file template-file temp-sops-file t)
    
    (unwind-protect
        (let ((auth-source-sops-file temp-sops-file)
              (auth-source-sops-age-key age-key-file)
              (auth-sources '(sops))
              (auth-source-do-cache nil))
          (auth-source-sops-enable)
          
          ;; Redefine `read-*' to avoid interaction
          (cl-letf (((symbol-function 'read-passwd) (lambda (_) "pass"))
                    ((symbol-function 'read-string) (lambda (_p &optional _i _h d _inh) (or d ""))))
            
            ;; Setup entries
            (auth-source-search :host "delete-me" :user "user1" :secret "pass1" :create t)
            (auth-source-search :host "delete-me" :user "user2" :secret "pass2" :create t)
            (auth-source-search :host "keep-me" :user "user3" :secret "pass3" :create t)
            
            ;; Verify they exist
            (should (= (length (auth-source-search :host "delete-me" :max 10)) 2))
            
            ;; Delete one entry specifically
            (let ((deleted (auth-source-delete :host "delete-me" :user "user1")))
              (should (= (length deleted) 1))
              (should (equal (plist-get (car deleted) :user) "user1")))
            
            ;; Verify one remains for that host
            (let ((remaining (auth-source-search :host "delete-me")))
              (should (= (length remaining) 1))
              (should (equal (plist-get (car remaining) :user) "user2")))
            
            ;; Delete by host wildcard
            (auth-source-delete :host "delete-me")
            (should (null (auth-source-search :host "delete-me")))
            
            ;; Verify keep-me still exists
            (should (auth-source-search :host "keep-me"))))
      (when (file-exists-p temp-sops-file)
        (delete-file temp-sops-file)))))

(provide 'protocol-test)
