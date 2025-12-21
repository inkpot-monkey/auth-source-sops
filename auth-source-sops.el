;;; auth-source-sops.el --- Integrate auth-source with sops -*- lexical-binding: t -*-

;; Author: Inkpot Monkey <inkpot@palebluebytes.space>,
;; Version: 1.0.0
;; Created: 22 Jun 2025
;; URL: https://github.com/inkpot-monkey/auth-source-sops
;; Package-Requires: ((emacs "28.1") (yaml "0.5.1"))

;;; Commentary:

;; This package integrates `sops' (https://getsops.io/) with the Emacs
;; `auth-source' library.  It allows you to store your credentials in
;; encrypted YAML or JSON files, providing better structure and security
;; than traditional .netrc files.
;;
;; Key features:
;; - Support for YAML and JSON backends.
;; - `:incremental` (default): Only decrypt the specific branch matching the host.
;; - `:full`: Decrypts the entire file and search locally.  Faster for multiple
;;   lookups in small files.
;; - Automatic mapping of `machine' to `host' and `password' to `secret'.
;;
;; Quickstart:
;;
;; 1. Configure your secrets file and age key:
;;    (setq auth-source-sops-file "~/.authinfo.sops.yaml")
;;    (setq auth-source-sops-age-key "~/.config/sops/age/keys.txt")
;;
;; 2. Enable the backend:
;;    (auth-source-sops-enable)
;;
;; 3. Use standard `auth-source-search':
;;    (auth-source-search :host "my-host" :user "my-user")

;;; Code:
(require 'auth-source)
(require 'cl-lib)
(require 'yaml)
(require 'subr-x)
(require 'json)

(declare-function yaml-parse-string "yaml" (string &rest args))

(defgroup auth-source-sops nil
  "Sops integration within auth-source."
  :prefix "auth-source-sops-"
  :group 'auth-source)

(defcustom auth-source-sops-executable "sops"
  "Path to the sops executable.
If not absolute, it will be searched for in the variable `exec-path'."
  :type 'string)

(defcustom auth-source-sops-file "~/.authinfo.sops.yaml"
  "File in which sops-encrypted credentials are stored.
The file extension determines the parser used (.yaml or .json)."
  :type 'file)

(defcustom auth-source-sops-age-key nil
  "File containing the SOPS_AGE_KEY.
If set, the content of this file will be used to set the
SOPS_AGE_KEY environment variable when calling the sops process."
  :type '(choice (const :tag "None" nil)
                 file))

(defcustom auth-source-sops-search-method :incremental
  "Method used to search for credentials in the sops file.
- `:incremental`: Uses `sops --extract' to decrypt only the specific
  top-level key that matches the host.  This is faster for large files
  and avoids keeping the entire decrypted file in memory.
- `:full`: Decrypts the entire file once and searches the resulting
  structure locally.  This may be faster if you have many matches or
  a small file."
  :type '(choice (const :tag "Incremental Search" :incremental)
                 (const :tag "Full Decryption" :full)))

(cl-defun auth-source-sops-search
    (&rest spec &key backend require type max host user port &allow-other-keys)
  "Main search function for the sops auth-source backend.
Search for credentials matching SPEC in the configured `auth-source-sops-file'.
SPEC is a plist as passed to `auth-source-search'.
BACKEND is the backend object provided by auth-source.
REQUIRE, TYPE, MAX, HOST, USER, PORT are standard search criteria.
Returns a list of matching entries (plists)."
  (cl-assert (or (null type) (eq type (oref backend type)))
             t "Invalid sops search: %s %s")
  (cond ((eq host t)
         (warn "auth-source-sops does not handle host wildcards")
         nil)
        ((null host)
         ;; Do not build a result, as none will match when HOST is nil
         nil)
        (t
         (auth-source-sops--multiple-results host user port require max))))

(defun auth-source-sops--match-p (val criteria)
  "Return non-nil if VAL matches CRITERIA.
VAL is the value from the secret file.
CRITERIA can be a string (matched via regex), a list (matched via `member'),
or t."
  (cond
   ((eq criteria t) t)
   ((null criteria) t)
   ((listp criteria) (member val criteria))
   (t (and (stringp val)
           (stringp criteria)
           (not (not (string-match-p criteria val)))))))

(defun auth-source-sops--entry-matches-criteria-p (entry host user port require)
  "Check if a normalized ENTRY matches all search criteria.
ENTRY is an alist representing a single set of credentials.
HOST, USER, PORT are the search criteria.
REQUIRE is a list of keywords (e.g., :secret, :user) that must be present.
Returns non-nil if all criteria and requirements are met."
  (let ((entry-host (alist-get 'host entry))
        (entry-user (alist-get 'user entry))
        (entry-port (alist-get 'port entry))
        (entry-secret (or (alist-get 'secret entry)
                          (alist-get 'password entry))))
    (and
     ;; Basic criteria matching
     entry-host
     (auth-source-sops--match-p entry-host host)
     (or (null user) (auth-source-sops--match-p entry-user user))
     (or (null port)
         (auth-source-sops--match-p (and entry-port (format "%s" entry-port))
                                    (if (listp port)
                                        (mapcar (lambda (p) (format "%s" p)) port)
                                      (format "%s" port))))
     entry-secret
     ;; Required fields check
     (cl-every (lambda (field)
                 (let ((sym-field (if (keywordp field)
                                      (intern (substring (symbol-name field) 1))
                                    field)))
                   (if (eq sym-field 'secret)
                       entry-secret
                     (alist-get sym-field entry))))
               require))))

(defun auth-source-sops--build-result (entry user port)
  "Build a properly formatted auth-source result from normalized ENTRY.
USER and PORT are used as fallbacks if not present in ENTRY.
Returns a plist containing :host, :user, :port, and a :secret lambda."
  (let* ((entry-host (cdr (assoc 'host entry)))
         (entry-user (cdr (assoc 'user entry)))
         (entry-port (cdr (assoc 'port entry)))
         (entry-secret (or (cdr (assoc 'secret entry))
                           (cdr (assoc 'password entry)))))
    (list :host entry-host
          :user (or entry-user user)
          :port (or entry-port port)
          :secret (lambda () (when entry-secret (format "%s" entry-secret))))))

(defun auth-source-sops--find-matching-entries (sops-parsed host user port require)
  "Find and build results from SOPS-PARSED entries.
SOPS-PARSED is a list of normalized entries.
HOST, USER, PORT, REQUIRE are search criteria.
Returns a list of formatted result plists."
  (let (results)
    (dolist (entry sops-parsed)
      (when (auth-source-sops--entry-matches-criteria-p entry host user port require)
        (push (auth-source-sops--build-result entry user port) results)))
    (nreverse results)))

(defvar auth-source-sops--raw-cache nil
  "Internal cache for the raw (encrypted) file structure.
Prevents redundant parsing of large top-level structures in incremental mode.
Format: (MODIFICATION-TIME . PARSED-STRUCTURE)")

(defun auth-source-sops--get-raw-structure ()
  "Return the parsed structure of the sops file without full decryption.
Uses `auth-source-sops--raw-cache' to avoid re-parsing if the file
hasn't changed.
In this state, top-level keys are readable, but values are encrypted
strings."
  (if (and auth-source-sops--raw-cache
           (equal (car auth-source-sops--raw-cache)
                  (file-attribute-modification-time (file-attributes auth-source-sops-file))))
      (cdr auth-source-sops--raw-cache)
    (let* ((content (auth-source-sops-get-string-from-file auth-source-sops-file))
           (parsed (auth-source-sops-parse auth-source-sops-file content)))
      (setq auth-source-sops--raw-cache
            (cons (file-attribute-modification-time (file-attributes auth-source-sops-file))
                  parsed))
      parsed)))

(defun auth-source-sops--extract-branch (key)
  "Decrypt only the branch at KEY using `sops --extract'.
Returns the decrypted branch content as a string."
  (let ((output-buffer (generate-new-buffer " *sops-extract*"))
        (error-buffer (generate-new-buffer " *sops-extract-error*"))
        (process-environment (copy-sequence process-environment))
        (exit-code nil)
        (proc-done nil))
    (unwind-protect
        (progn
          (when auth-source-sops-age-key
            (setenv "SOPS_AGE_KEY" (auth-source-sops-get-string-from-file auth-source-sops-age-key)))
          (let ((proc (make-process
                       :name "sops-extract"
                       :buffer output-buffer
                       :stderr error-buffer
                       :command (list auth-source-sops-executable "decrypt"
                                      "--extract" (format "[\"%s\"]" key)
                                      auth-source-sops-file)
                       :sentinel (lambda (p _e)
                                   (when (not (process-live-p p))
                                     (setq exit-code (process-exit-status p))
                                     (setq proc-done t))))))
            (set-process-query-on-exit-flag proc nil)
            (while (not proc-done)
              (accept-process-output proc 0.1))
            (if (zerop exit-code)
                (with-current-buffer output-buffer (buffer-string))
              (error "Sops extract failed: %s"
                     (with-current-buffer error-buffer (buffer-string))))))
      (kill-buffer output-buffer)
      (kill-buffer error-buffer))))

(defun auth-source-sops--multiple-results (host user port &optional require max)
  "Execute the search using the configured search method.
HOST, USER, PORT, REQUIRE, MAX are standard search criteria.
Dispatches to either full decryption or incremental extraction."
  (if (eq auth-source-sops-search-method :full)
      ;; Full decryption path
      (let* ((decrypted (auth-source-sops-decrypt))
             (parsed (auth-source-sops-parse auth-source-sops-file decrypted))
             (exploded (mapcan #'auth-source-sops-parse-entry parsed))
             (results (mapcar (lambda (entry)
                                (auth-source-sops--build-result entry user port))
                              (cl-remove-if-not (lambda (entry)
                                                  (auth-source-sops--entry-matches-criteria-p
                                                   entry host user port require))
                                                exploded))))
        (if max (seq-take results max) results))
    
    ;; Incremental extraction path
    (let* ((raw-parsed (auth-source-sops--get-raw-structure))
           (results nil))
      ;; Iterate through top-level keys to find potential matches
      (cl-loop for (key . _value) in raw-parsed
               until (and max (>= (length results) max))
               do (let ((parsed-key (auth-source-sops-entry-parse-key key)))
                    (when (auth-source-sops--match-p (alist-get 'host parsed-key) host)
                      ;; Only decrypt this branch if it matches the host criteria
                      (let* ((decrypted-branch (auth-source-sops--extract-branch key))
                             (branch-parsed (auth-source-sops-parse auth-source-sops-file decrypted-branch))
                             ;; Wrap in a single entry for parse-entry
                             (exploded (auth-source-sops-parse-entry (cons key branch-parsed)))
                             (branch-results (mapcar (lambda (entry)
                                                       (auth-source-sops--build-result entry user port))
                                                     (cl-remove-if-not (lambda (entry)
                                                                         (auth-source-sops--entry-matches-criteria-p
                                                                          entry host user port require))
                                                                       exploded))))
                        (setq results (append results branch-results))))))
      (if max (seq-take results max) results))))

(defvar auth-source-sops-backend
  (auth-source-backend
   :source "."
   :type 'sops
   :search-function #'auth-source-sops-search)
  "Auth-source backend definition for sops.")

(defun auth-source-sops-backend-parse (entry)
  "Backend parser for `auth-source-sops'.
ENTRY is the backend identifier (must be the symbol `sops')."
  (when (eq entry 'sops)
    (auth-source-backend-parse-parameters entry auth-source-sops-backend)))

;; Register the parser with auth-source
(if (boundp 'auth-source-backend-parser-functions)
    (add-hook 'auth-source-backend-parser-functions #'auth-source-sops-backend-parse)
  (advice-add 'auth-source-backend-parse :before-until #'auth-source-sops-backend-parse))



(defun auth-source-sops-get-string-from-file (file-path)
  "Return content of FILE-PATH as a string."
  (with-temp-buffer
    (insert-file-contents file-path)
    (buffer-string)))

(defun auth-source-sops--file-modes (file)
  "Return file permission modes for FILE."
  (file-modes file))

(defun auth-source-sops--check-permissions (file)
  "Verify that FILE has secure permissions (0600).
Warns if the file is group or world readable/writable."
  (let ((modes (auth-source-sops--file-modes file)))
    (when (and modes (> (logand modes #o077) 0))
      (warn "File %s has insecure permissions %o. Should be 0600." file modes))))

(defun auth-source-sops-decrypt ()
  "Decrypt the entire auth file and return its contents.
Uses `auth-source-sops-executable'.  Sets SOPS_AGE_KEY if
`auth-source-sops-age-key' is configured.
Returns the decrypted contents as a string."
  (let ((process-environment (copy-sequence process-environment)))
    (when (file-exists-p auth-source-sops-file)
      (auth-source-sops--check-permissions auth-source-sops-file))
    (with-temp-buffer
      (when auth-source-sops-age-key
        (when (file-exists-p auth-source-sops-age-key)
          (auth-source-sops--check-permissions auth-source-sops-age-key))
        (setenv "SOPS_AGE_KEY" (auth-source-sops-get-string-from-file auth-source-sops-age-key)))
      
      (let ((output-buffer (generate-new-buffer " *sops-output*"))
            (error-buffer (generate-new-buffer " *sops-error*"))
            (exit-code nil)
            (proc-done nil))
        (unwind-protect
            (progn
              (let ((proc (make-process
                           :name "sops-decrypt"
                           :buffer output-buffer
                           :stderr error-buffer
                           :connection-type 'pipe
                           :command (list auth-source-sops-executable "decrypt" auth-source-sops-file)
                           :sentinel (lambda (p _e)
                                       (when (if (fboundp 'process-live-p)
                                                 (not (process-live-p p))
                                               (memq (process-status p) '(exit signal failed)))
                                         (setq exit-code (process-exit-status p))
                                         (setq proc-done t))))))
                (set-process-query-on-exit-flag proc nil)
                (let ((stderr-proc (get-buffer-process error-buffer)))
                  (when (processp stderr-proc)
                    (set-process-query-on-exit-flag stderr-proc nil)))
                
                (let ((start-time (float-time)))
                  (while (not proc-done)
                    (accept-process-output proc 0.1)
                    (when (> (- (float-time) start-time) 10.0) ;; 10 second timeout
                      (delete-process proc)
                      (error "Sops decryption timed out after 10 seconds")))))
              
              (unless (zerop exit-code)
                (error "Sops decryption failed with exit code %s: %s"
                       exit-code (with-current-buffer error-buffer (buffer-string))))
              (with-current-buffer output-buffer (buffer-string)))
          (kill-buffer output-buffer)
          (kill-buffer error-buffer))))))

(defun auth-source-sops-parse (file output)
  "Parse decrypted sops OUTPUT string based on FILE extension.
Currently supports .yaml and .json files."
  (cond ((string-suffix-p ".yaml" file)
         (yaml-parse-string output :object-type 'alist :object-key-type 'string))
        ((string-suffix-p ".json" file)
         (json-parse-string output :object-type 'alist :array-type 'array))
        (t (error "File parser not implemented for %s" file))))

(defun auth-source-sops-get (key entry)
  "Retrieve value for KEY from a raw sops ENTRY.
KEY is a symbol (e.g., `user', `host').
This is a convenience function for manual extraction."
  (let ((data (auth-source-sops-parse-entry entry)))
    (cdr (assoc key (car data)))))

(defun auth-source-sops-parse-entry (entry)
  "Normalize a raw sops ENTRY into a list of constituent credential alists.
ENTRY is a cons cell (KEY-STRING . VALUE).
Handles `exploding' the key and normalizing sequence values."
  (let* ((key (car entry))
         (parsed-key (auth-source-sops-entry-parse-key key))
         (values (auth-source-sops-entry-parse-value (cdr entry))))
    (mapcar (lambda (value)
              (append value parsed-key `((key . ,key))))
            values)))

(defun auth-source-sops-entry-parse-key (key)
  "Parse a sops KEY string into host, user, and port components.
Supports common formats like user@host, host:port, etc."
  (let* ((key-str (format "%s" key))
         (host nil)
         (user nil)
         (port nil))
    (if (string-match ":\\([0-9]+\\)$" key-str)
        (progn
          (setq port (string-to-number (match-string 1 key-str)))
          (setq key-str (substring key-str 0 (match-beginning 0)))))
    
    (if (string-match "^\\(.*\\)@\\([^@]+\\)$" key-str)
        (progn
          (setq user (match-string 1 key-str))
          (setq host (match-string 2 key-str)))
      (setq host key-str))
    
    `((host . ,host)
      (user . ,user)
      (port . ,port))))

(defun auth-source-sops-entry-parse-value (value)
  "Normalize the VALUE part of a sops entry.
If VALUE is a list/vector, it is treated as multiple credential sets.
Keys like `machine' and `password' are normalized."
  (if (and (vectorp value) (> (length value) 0))
      (cl-loop for item across value
               collect (cl-loop for pair in item
                                for key-unparsed = (car pair)
                                for val = (cdr pair)
                                when (or (stringp val) (numberp val))
                                collect (cons (let ((key-str (if (symbolp key-unparsed)
                                                                 (symbol-name key-unparsed)
                                                               (format "%s" key-unparsed))))
                                                (cond ((string-equal key-str "machine") 'host)
                                                      ((string-equal key-str "password") 'secret)
                                                      (t (intern key-str))))
                                              val)))
    (list (list (cons 'secret value)))))

;;;###autoload
(defun auth-source-sops-enable ()
  "Register the sops backend with `auth-source'.
Checks for the sops executable and adds `sops' to `auth-sources'."
  (if (executable-find auth-source-sops-executable)
      (progn
        (add-to-list 'auth-sources 'sops)
        (auth-source-forget-all-cached))
    (user-error "Could not find sops executable at %s" auth-source-sops-executable)))

(provide 'auth-source-sops)

;;; auth-source-sops.el ends here

;; Local Variables:
;; ispell-buffer-session-localwords: ("auth" "yaml" "json" "plist" "regex" "plists" "alists" "sops" "fallbacks" "normalized" "decrypt" "decrypted" "backend" "normalize" "normalizing" "fallback" "parser" "decrypts")
;; End:
