;;; auth-source-sops-test.el --- Tests for auth-source-sops -*- lexical-binding: t; no-byte-compile: t -*-

;;; Commentary:

;; Tests for the auth-source-sops package.

;;; Code:
(defvar current-dir (file-name-directory (or load-file-name buffer-file-name)))

(require 'ert)
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

;;; auth-source-sops-test.el ends here
