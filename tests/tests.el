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
            (get-string-from-file auth-source-unencrypted-sops-file)))))

;; Search tests
(ert-deftest auth-source-sops-search-basic-test ()
  "Test basic search functionality."
  (let ((result (car (auth-source-search :host "github"))))
    (should (equal (plist-get result :host) "github"))
    (should (equal (plist-get result :user) nil))
    (should (equal (plist-get result :port) nil))
    (should (equal (funcall (plist-get result :secret)) "1"))))

(ert-deftest auth-source-sops-search-user-test ()
  "Test search with user specified."
  (let ((result (car (auth-source-search :host "api.github.com" :user "emacs"))))
    (should (equal (plist-get result :host) "api.github.com"))
    (should (equal (plist-get result :user) "emacs"))
    (should (equal (plist-get result :port) nil))
    (should (equal (funcall (plist-get result :secret)) "7"))))

(ert-deftest auth-source-sops-search-require-test ()
  "Test search with require fields specified."
  (let ((result (car (auth-source-search :host "api.github.com" :require '(user)))))
    (should (equal (plist-get result :host) "api.github.com"))
    (should (equal (plist-get result :user) "apiKey"))
    (should (equal (plist-get result :port) nil))
    (should (equal (funcall (plist-get result :secret)) "6"))))

(ert-deftest auth-source-sops-search-max-results-test ()
  "Test search with max results specified."
  (let ((results (auth-source-search :host "api.github.com" :max 2)))
    (should (<= (length results) 2))
    (should (equal (plist-get (nth 0 results) :host) "api.github.com"))
    (should (equal (plist-get (nth 0 results) :user) "apiKey"))
    (should (equal (plist-get (nth 1 results) :host) "api.github.com"))
    (should (equal (plist-get (nth 1 results) :user) "emacs"))))

(ert-deftest auth-source-sops-multiple-results-test ()
  "Test finding multiple matching entries."
  (let ((results (auth-source-sops--multiple-results "github.com" nil nil)))
    (should (equal (length results) 4))
    (should (equal (plist-get (nth 0 results) :host) "github.com"))
    (should (equal (plist-get (nth 0 results) :user) nil))
    (should (equal (plist-get (nth 0 results) :port) nil))
    (should (equal (plist-get (nth 1 results) :host) "github.com"))
    (should (equal (plist-get (nth 1 results) :user) "example"))
    (should (equal (plist-get (nth 1 results) :port) nil))
    (should (equal (plist-get (nth 2 results) :host) "github.com"))
    (should (equal (plist-get (nth 2 results) :user) nil))
    (should (equal (plist-get (nth 2 results) :port) 22))
    (should (equal (plist-get (nth 3 results) :host) "github.com")) 
    (should (equal (plist-get (nth 3 results) :user) "example"))
    (should (equal (plist-get (nth 3 results) :port) 22))))

;;; auth-source-sops-test.el ends here
